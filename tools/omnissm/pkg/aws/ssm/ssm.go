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

package ssm

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/awsutil"
	"github.com/golang/time/rate"
	"github.com/pkg/errors"
)

var ErrInvalidInstance = errors.New("invalid instance id")

type SSM struct {
	ssmiface.SSMAPI

	config  *awsutil.Config
	ssmRate *rate.Limiter
}

func New(config *awsutil.Config) *SSM {
	svc := ssm.New(awsutil.Session(config))
	if config.EnableTracing {
		xray.AWS(svc.Client)
	}
	s := &SSM{
		SSMAPI:  svc,
		config:  config,
		ssmRate: rate.NewLimiter(5, 5),
	}
	return s
}

type Activation struct {
	ActivationId   string `json:"ActivationId"`
	ActivationCode string `json:"ActivationCode"`
}

func (s *SSM) CreateActivation(ctx context.Context, name, instanceRole string) (*Activation, error) {
	s.ssmRate.Wait(ctx)
	resp, err := s.SSMAPI.CreateActivationWithContext(ctx, &ssm.CreateActivationInput{
		DefaultInstanceName: aws.String(name),
		IamRole:             aws.String(instanceRole),
		Description:         aws.String(name),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "ssm.CreateActivation failed: %#v", name)
	}
	return &Activation{*resp.ActivationId, *resp.ActivationCode}, nil
}

type ResourceTags struct {
	ManagedId string            `json:"ManagedId"`
	Tags      map[string]string `json:"Tags"`
}

func (s *SSM) AddTagsToResource(ctx context.Context, input *ResourceTags) error {
	awsTags := make([]*ssm.Tag, 0)
	for k, v := range input.Tags {
		v = SanitizeTag(v)
		if v == "" {
			continue
		}
		awsTags = append(awsTags, &ssm.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	if len(awsTags) == 0 {
		return nil
	}
	s.ssmRate.Wait(ctx)
	_, err := s.SSMAPI.AddTagsToResourceWithContext(ctx, &ssm.AddTagsToResourceInput{
		ResourceType: aws.String(ssm.ResourceTypeForTaggingManagedInstance),
		ResourceId:   aws.String(input.ManagedId),
		Tags:         awsTags,
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "InvalidResourceId" {
				err = ErrInvalidInstance
			}
		}
	}
	return errors.Wrapf(err, "ssm.AddTagsToResource failed: %#v", input.ManagedId)
}

// TODO: custom inventory can also contain an array of maps, which our current
// system does not handle.
type CustomInventory struct {
	TypeName    string
	ManagedId   string
	CaptureTime string
	Content     map[string]string
}

func (c *CustomInventory) ContentHash() string {
	data, _ := json.Marshal(c.Content)
	return fmt.Sprintf("%x", md5.Sum(data))
}

func (s *SSM) PutInventory(ctx context.Context, inv *CustomInventory) error {
	s.ssmRate.Wait(ctx)
	_, err := s.SSMAPI.PutInventoryWithContext(ctx, &ssm.PutInventoryInput{
		InstanceId: aws.String(inv.ManagedId),
		Items: []*ssm.InventoryItem{{
			CaptureTime:   aws.String(inv.CaptureTime), // "2006-01-02T15:04:05Z"
			Content:       []map[string]*string{aws.StringMap(inv.Content)},
			ContentHash:   aws.String(inv.ContentHash()),
			SchemaVersion: aws.String("1.0"),
			TypeName:      aws.String(inv.TypeName),
		}},
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "InvalidResourceId" {
				err = ErrInvalidInstance
			}
		}
	}
	return errors.Wrapf(err, "ssm.PutInventory failed: %#v", inv.ManagedId)
}

func (s *SSM) DeregisterManagedInstance(ctx context.Context, managedId string) error {
	s.ssmRate.Wait(ctx)
	_, err := s.SSMAPI.DeregisterManagedInstanceWithContext(ctx, &ssm.DeregisterManagedInstanceInput{
		InstanceId: aws.String(managedId),
	})
	if aErr, ok := err.(awserr.Error); ok && aErr.Code() == "InvalidInstanceId" {
		// SSM no longer knows about the instance, but dynamodb does - continue
		err = ErrInvalidInstance
	}
	return errors.Wrapf(err, "ssm.DeregisterManagedInstance failed: %#v", managedId)
}

type ManagedInstance struct {
	ActivationId     string
	ManagedId        string
	Name             string
	PingStatus       string
	RegistrationDate time.Time
	LastPingDate     time.Time
}

func (s *SSM) DescribeInstanceInformation(ctx context.Context, activationId string) (*ManagedInstance, error) {
	resp, err := s.SSMAPI.DescribeInstanceInformationWithContext(ctx, &ssm.DescribeInstanceInformationInput{
		InstanceInformationFilterList: []*ssm.InstanceInformationFilter{
			{
				Key:      aws.String(ssm.InstanceInformationFilterKeyActivationIds),
				ValueSet: aws.StringSlice([]string{activationId}),
			},
		},
		MaxResults: aws.Int64(5),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "ssm.DescribeInstanceInformation failed: %#v", activationId)
	}
	for _, instance := range resp.InstanceInformationList {
		m := &ManagedInstance{
			ActivationId:     aws.StringValue(instance.ActivationId),
			ManagedId:        aws.StringValue(instance.InstanceId),
			Name:             aws.StringValue(instance.Name),
			RegistrationDate: aws.TimeValue(instance.RegistrationDate),
			PingStatus:       aws.StringValue(instance.PingStatus),
			LastPingDate:     aws.TimeValue(instance.LastPingDateTime),
		}
		return m, nil
	}
	return nil, errors.Errorf("activation not found: %#v", activationId)
}

func (s *SSM) DescribeOfflineInstances(ctx context.Context, fn func([]*ManagedInstance, bool) bool) error {
	params := &ssm.DescribeInstanceInformationInput{
		InstanceInformationFilterList: []*ssm.InstanceInformationFilter{
			{
				Key:      aws.String("PingStatus"),
				ValueSet: aws.StringSlice([]string{"ConnectionLost"}),
			},
		},
	}
	return svc.DescribeInstanceInformationPagesWithContext(ctx, params, func(resp *ssm.DescribeInstanceInformationOutput, lastPage bool) bool {
		page := make([]*ManagedInstance, len(resp.InstanceInformationList))
		for i, instance := range resp.InstanceInformationList {
			page[i] = &ManagedInstance{
				ActivationId:     aws.StringValue(instance.ActivationId),
				ManagedId:        aws.StringValue(instance.InstanceId),
				Name:             aws.StringValue(instance.Name),
				RegistrationDate: aws.TimeValue(instance.RegistrationDate),
				PingStatus:       aws.StringValue(instance.PingStatus),
				LastPingDate:     aws.TimeValue(instance.LastPingDateTime),
			}
		}
		return fn(page, lastPage)
	})
}
