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

package omnissmapi

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/pkg/errors"

	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/sns"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/sqs"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/ssm"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/omnissm"
)

type ssmAPI interface {
	CreateActivation(context.Context, string) (*ssm.Activation, error)
	AddTagsToResource(context.Context, *ssm.ResourceTags) error
	PutInventory(context.Context, *ssm.CustomInventory) error
	DeregisterManagedInstance(context.Context, string) error
}

type notifier interface {
	Publish(context.Context, string, []byte) error
}

type deferQueue interface {
	Send(context.Context, json.Marshaler) error
}

type registry interface {
	Get(context.Context, string) (*omnissm.RegistrationEntry, error)
	GetByManagedId(context.Context, string) (*omnissm.RegistrationEntry, error)
	Put(context.Context, *omnissm.RegistrationEntry) error
	Delete(context.Context, string) error
	SetTagged(context.Context, string, bool) error
	SetInventoried(context.Context, string, bool) error
}

// TODO: merge ssmAPI into registry? store(s)+activation provider+control plane?
type OmniSSM struct {
	config *Config

	ssmAPI
	notifier
	deferQueue
	registry
}

func New(config *Config) (*OmniSSM, error) {
	o := &OmniSSM{
		config: config,
		registry: omnissm.NewRegistrations(&omnissm.RegistrationsConfig{
			Config:        config.Config,
			TableName:     config.RegistrationsTable,
			EnableTracing: config.XRayTracingEnabled != "",
		}),
		notifier: sns.New(&sns.Config{
			Config:        config.Config,
			AssumeRole:    config.SNSPublishRole,
			EnableTracing: config.XRayTracingEnabled != "",
		}),
		ssmAPI: ssm.New(&ssm.Config{
			Config:        config.Config,
			InstanceRole:  config.InstanceRole,
			EnableTracing: config.XRayTracingEnabled != "",
		}),
	}
	if config.QueueName != "" {
		var err error
		o.deferQueue, err = sqs.New(&sqs.Config{
			Config:         config.Config,
			MessageGroupId: "omnissm-event-stream",
			QueueName:      config.QueueName,
			EnableTracing:  config.XRayTracingEnabled != "",
		})
		if err != nil {
			return nil, errors.Wrap(err, "cannot initialize SQS")
		}
	}

	return o, nil
}

func (o *OmniSSM) RequestActivation(ctx context.Context, req *omnissm.RegistrationRequest) (*omnissm.RegistrationResponse, error) {
	//if !req.Verified() {
	//return nil, errors.New("unverified registration request")
	//}
	entry, err := o.registry.Get(ctx, req.Hash())
	if err == nil {
		if ssm.IsManagedInstance(entry.ManagedId) || time.Now().Sub(entry.CreatedAt) < 12*time.Hour {
			// duplicate request
			return &omnissm.RegistrationResponse{
				RegistrationEntry: *entry,
				Region:            req.Region,
				Existing:          true,
			}, nil
		}
	} else if errors.Cause(err) == omnissm.ErrRegistrationNotFound {
		// new registration request
	} else {
		// unrelated failure
		return nil, err
	}
	activation, err := o.ssmAPI.CreateActivation(ctx, req.Name())
	if err != nil {
		// if we fail here, defer starting over
		return nil, o.tryDefer(ctx, err, RequestActivation, req)
	}
	entry = &omnissm.RegistrationEntry{
		Id:            req.Hash(),
		CreatedAt:     time.Now().UTC(),
		AccountId:     req.AccountId,
		Region:        req.Region,
		InstanceId:    req.InstanceId,
		ClientVersion: req.ClientVersion,
		Activation:    *activation,
		ManagedId:     "-",
	}
	if err := o.registry.Put(ctx, entry); err != nil {
		return nil, err
	}
	return &omnissm.RegistrationResponse{
		RegistrationEntry: *entry,
		Region:            req.Region,
	}, nil
}

func (o *OmniSSM) DeregisterInstance(ctx context.Context, entry *omnissm.RegistrationEntry) error {
	// Check dynamodb first to ease API pressure on SSM for repeat/invalid calls
	if _, err := o.registry.Get(ctx, entry.Id); err != nil {
		return o.tryDefer(ctx, err, DeregisterInstance, entry)
	}
	if err := o.ssmAPI.DeregisterManagedInstance(ctx, entry.ManagedId); err != nil {
		if errors.Cause(err) == ssm.ErrInvalidInstance {
			// SSM no longer knows about the instance, but dynamodb does - continue
		} else {
			return o.tryDefer(ctx, err, DeregisterInstance, entry)
		}
	}
	if err := o.registry.Delete(ctx, entry.Id); err != nil {
		return err
	}
	if o.config.ResourceDeletedSNSTopic != "" {
		data, err := json.Marshal(map[string]interface{}{
			"ManagedId":    entry.ManagedId,
			"ResourceId":   entry.InstanceId,
			"AWSAccountId": entry.AccountId,
			"AWSRegion":    entry.Region,
		})
		if err != nil {
			return errors.Wrap(err, "cannot marshal notification")
		}
		if err := o.notifier.Publish(ctx, o.config.ResourceDeletedSNSTopic, data); err != nil {
			return err
		}
	}
	return nil
}

func (o *OmniSSM) TagInstance(ctx context.Context, tags *ssm.ResourceTags) error {
	entry, err := o.registry.GetByManagedId(ctx, tags.ManagedId)
	if err != nil {
		if errors.Cause(err) == omnissm.ErrRegistrationNotFound {
			return errors.Wrapf(err, "failed to tag instance %#v", tags.ManagedId)
		}
		return err
	}
	if err := o.ssmAPI.AddTagsToResource(ctx, tags); err != nil {
		return o.tryDefer(ctx, err, AddTagsToResource, tags)
	}
	return o.registry.SetTagged(ctx, entry.Id, true)
}

func (o *OmniSSM) PutInstanceInventory(ctx context.Context, inv *ssm.CustomInventory) error {
	entry, err := o.registry.GetByManagedId(ctx, inv.ManagedId)
	if err != nil {
		if errors.Cause(err) == omnissm.ErrRegistrationNotFound {
			return errors.Wrapf(err, "cannot PutInventory for instance %#v", inv.ManagedId)
		}
		return err
	}
	if err := o.ssmAPI.PutInventory(ctx, inv); err != nil {
		return o.tryDefer(ctx, err, PutInventory, inv)
	}
	return o.registry.SetInventoried(ctx, entry.Id, true)
}

func (o *OmniSSM) tryDefer(ctx context.Context, err error, t DeferredActionType, value interface{}) error {
	if c := errors.Cause(err); o.deferQueue != nil && (request.IsErrorThrottle(c) || request.IsErrorRetryable(c)) {
		sqsErr := o.deferQueue.Send(ctx, &DeferredActionMessage{
			Type:  t,
			Value: value,
		})
		if sqsErr != nil {
			return errors.Wrapf(sqsErr, "could not defer message (original error: %v)", err)
		}
		return errors.Wrapf(err, "deferred action to queue (%s)", o.config.QueueName)
	}
	return err
}
