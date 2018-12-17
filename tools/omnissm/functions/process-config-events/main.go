// Copyright 2018 Capital One Services, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/configservice"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/s3"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/sns"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/ssm"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/omnissm"
)

var (
	resourceTypes = map[string]struct{}{
		"AWS::EC2::Instance": struct{}{},
	}

	resourceStatusTypes = map[string]struct{}{
		"ResourceDeleted":    struct{}{},
		"ResourceDiscovered": struct{}{},
		"OK":                 struct{}{},
	}
)

func removeTimestampMilliseconds(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// default to using the current time if we cannot parse the timestamp
		t = time.Now()
	}
	t = t.UTC()
	return t.Format("2006-01-02T15:04:05Z")
}

type configChangeHandler struct {
	*omnissm.OmniSSM
	*sns.SNS

	config *omnissm.Config
}

func (h *configChangeHandler) handleConfigurationItemChange(ctx context.Context, detail configservice.ConfigurationItemDetail) error {
	entry, err, ok := h.OmniSSM.Registrations.Get(ctx, detail.ConfigurationItem.Hash())
	if err != nil {
		return err
	}
	if !ok {
		log.Info().Str("name", detail.ConfigurationItem.Name()).Msgf("registration entry not found")
		return nil
	}
	log.Info().Interface("entry", entry).Msg("existing registration entry found")
	if !ssm.IsManagedInstance(entry.ManagedId) {
		return errors.Errorf("ManagedId %#v invalid for %s/%s", entry.ManagedId, entry.AccountId, entry.InstanceId)
	}
	switch detail.ConfigurationItem.ConfigurationItemStatus {
	case "ResourceDiscovered", "OK":
		tags := make(map[string]string)
		for k, v := range detail.ConfigurationItem.Tags {
			if !h.OmniSSM.HasResourceTag(k) {
				continue
			}
			tags[k] = v
		}
		ci := detail.ConfigurationItem
		tags["AccountId"] = ci.AWSAccountId
		tags["VPCId"] = ci.Configuration.VPCId
		tags["SubnetId"] = ci.Configuration.SubnetId
		resourceTags := &ssm.ResourceTags{
			ManagedId: entry.ManagedId,
			Tags:      tags,
		}
		if err := h.OmniSSM.TagInstance(ctx, resourceTags); err != nil {
			if c := errors.Cause(err); c == omnissm.ErrRegistrationNotFound || c == ssm.ErrInvalidInstance {
				log.Warn().Err(err).Msg("instance no longer exists")
				return nil
			}
			return err
		}
		log.Info().Msgf("AddTagsToResource successful for %#v", entry.ManagedId)
		// NOTE: CanfigurationItemCaptureTime is sometimes sent by AWS as
		// a timestamp with milliseconds, which are not accepted by SSM when
		// calling PutInventory. Here we must attempt to remove milliseconds
		// from the timestamp and return it in the proper format - otherwise the
		// current time is used.
		inv := &ssm.CustomInventory{
			TypeName:    "Custom:CloudInfo",
			ManagedId:   entry.ManagedId,
			CaptureTime: removeTimestampMilliseconds(detail.ConfigurationItem.ConfigurationItemCaptureTime),
			Content:     configservice.ConfigurationItemContentMap(detail.ConfigurationItem),
		}
		if err := h.OmniSSM.PutInstanceInventory(ctx, &inv); err != nil {
			if c := errors.Cause(err); c == omnissm.ErrRegistrationNotFound || c == ssm.ErrInvalidInstance {
				log.Warn().Err(err).Msg("instance no longer exists")
				return nil
			}
			return err
		}
		log.Info().Msgf("PutInventory successful for %#v", entry.ManagedId)
	case "ResourceDeleted":
		if err := h.OmniSSM.DeregisterInstance(ctx, entry); err != nil {
			return err
		}
		log.Info().Msgf("Successfully deregistered instance: %#v", entry.ManagedId)
		if h.config.ResourceDeletedSNSTopic != "" {
			data, err := json.Marshal(entry)
			if err != nil {
				return errors.Wrap(err, "cannot marshal notification")
			}
			if err := h.SNS.Publish(ctx, h.config.ResourceDeletedSNSTopic, data); err != nil {
				return err
			}
		}
	}
	return nil
}

type cloudWatchEvent struct {
	Version    string                              `json:"version"`
	ID         string                              `json:"id"`
	DetailType string                              `json:"detail-type"`
	Source     string                              `json:"source"`
	AccountId  string                              `json:"account"`
	Time       time.Time                           `json:"time"`
	Region     string                              `json:"region"`
	Resources  []string                            `json:"resources"`
	Detail     configservice.CloudWatchEventDetail `json:"detail"`
}

func main() {
	config, err := omnissm.ReadConfig("config.yaml")
	if err != nil {
		panic(err)
	}
	omni, err := omnissm.New(config)
	if err != nil {
		panic(err)
	}

	h := &configChangeHandler{
		OmniSSM: omni,
		SNS:     sns.New(config.AWSConfig().WithAssumeRole(config.SNSPublishRole)),
		config:  config,
	}
	svc := s3.New(config.AWSConfig().WithAssumeRole(config.S3DownloadRole))

	lambda.Start(func(ctx context.Context, event cloudWatchEvent) (err error) {
		if event.Source != "aws.config" {
			return
		}
		var eventDetail configservice.ConfigurationItemDetail
		switch event.Detail.MessageType {
		case "ConfigurationItemChangeNotification":
			if _, ok := resourceTypes[event.Detail.ConfigurationItem.ResourceType]; !ok {
				return
			}
			if _, ok := resourceStatusTypes[event.Detail.ConfigurationItem.ConfigurationItemStatus]; !ok {
				return
			}
			eventDetail = event.Detail.ConfigurationItemDetail
		case "OversizedConfigurationItemChangeNotification":
			if _, ok := resourceTypes[event.Detail.ConfigurationItemSummary.ResourceType]; !ok {
				return
			}
			if _, ok := resourceStatusTypes[event.Detail.ConfigurationItemSummary.ConfigurationItemStatus]; !ok {
				return
			}
			data, err := svc.GetObject(ctx, event.Detail.S3DeliverySummary.S3BucketLocation)
			if err != nil {
				return errors.Wrap(err, "cannot download oversized configuration item")
			}
			if err := json.Unmarshal(data, &eventDetail); err != nil {
				return errors.Wrap(err, "cannot unmarshal oversized configuration item")
			}
		default:
			return errors.Errorf("unknown message type: %#v", event.Detail.MessageType)
		}
		return handleConfigurationItemChange(ctx, eventDetail)
	})
}
