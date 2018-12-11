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

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/ssm"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/omnissm"
)

var omni *omnissm.OmniSSM

type message struct {
	Type  omnissm.DeferredActionType
	Value json.RawMessage
}

func processDeferredActionMessage(ctx context.Context, msg message) error {
	switch msg.Type {
	case omnissm.AddTagsToResource:
		var resourceTags ssm.ResourceTags
		if err := json.Unmarshal(msg.Value, &resourceTags); err != nil {
			return errors.Wrap(err, "cannot unmarshal DeferredActionMessage.Value")
		}
		if err := omni.TagInstance(ctx, &resourceTags); err != nil {
			if c := errors.Cause(err); c == omnissm.ErrRegistrationNotFound || c == ssm.ErrInvalidInstance {
				log.Warn().Err(err).Msg("instance no longer exists")
				return nil
			}
			return err
		}
		log.Info().Msg("tags added to resource successfully")
	case omnissm.RequestActivation:
		var req omnissm.RegistrationRequest
		if err := json.Unmarshal(msg.Value, &req); err != nil {
			return errors.Wrap(err, "cannot unmarshal DeferredActionMessage.Value")
		}
		resp, err := omni.RequestActivation(ctx, &req)
		if err != nil {
			return err
		}
		if resp.Existing() {
			log.Info().Interface("entry", resp).Msg("existing registration entry found")
		} else {
			log.Info().Interface("entry", resp).Msg("new registration entry created")
		}
	case omnissm.DeregisterInstance:
		var entry omnissm.RegistrationEntry
		if err := json.Unmarshal(msg.Value, &entry); err != nil {
			return errors.Wrap(err, "cannot unmarshal DeferredActionMessage.Value")
		}
		if !ssm.IsManagedInstance(entry.ManagedId) {
			return errors.Errorf("registration managed id is invalid: %#v", entry.ManagedId)
		}
		if err := omni.DeregisterInstance(ctx, &entry); err != nil {
			if errors.Cause(err) == ErrRegistrationNotFound {
				log.Warn().Err(err).Str("Id", id).Msg("instance no longer exists")
				return nil
			}
			return err
		}
	case omnissm.PutInventory:
		var inv ssm.CustomInventory
		if err := json.Unmarshal(msg.Value, &inv); err != nil {
			return errors.Wrap(err, "cannot unmarshal DeferredActionMessage.Value")
		}
		if err := omni.PutInstanceInventory(ctx, &inv); err != nil {
			if c := errors.Cause(err); c == omnissm.ErrRegistrationNotFound || c == ssm.ErrInvalidInstance {
				log.Warn().Err(err).Msg("instance no longer exists")
				return nil
			}
			return err
		}
		log.Info().Msg("custom inventory successful")
	default:
	}
	return nil
}

func main() {
	config, err := omnissm.ReadConfig("config.yaml")
	if err != nil {
		panic(err)
	}
	omni, err = omnissm.New(config)
	if err != nil {
		panic(err)
	}

	lambda.Start(func(ctx context.Context, m message) error {
		if err := handleConfigurationItemChange(ctx, msg); err != nil {
			log.Info().Err(err).Interface("message", m).Msg("processing DeferredActionMessage failed")
			return err
		}
		return nil
	})
}
