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

package omnissm

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/pkg/errors"

	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/sqs"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/ssm"
)

type ssmAPI interface {
	CreateActivation(context.Context, string, string) (*ssm.Activation, error)
	AddTagsToResource(context.Context, *ssm.ResourceTags) error
	PutInventory(context.Context, *ssm.CustomInventory) error
	DeregisterManagedInstance(context.Context, string) error
}

type deferQueue interface {
	Send(context.Context, json.Marshaler) error
}

type registry interface {
	Get(context.Context, string) (*RegistrationEntry, error)
	GetByManagedId(context.Context, string) (*RegistrationEntry, error)
	Put(context.Context, *RegistrationEntry) error
	Delete(context.Context, string) error
	SetManagedId(context.Context, string, string) error
	SetTagged(context.Context, string, bool) error
	SetInventoried(context.Context, string, bool) error
}

// TODO: merge ssmAPI into registry? store(s)+activation provider+control plane?
type OmniSSM struct {
	config *Config

	ssmAPI
	deferQueue
	registry
}

func New(config *Config) (*OmniSSM, error) {
	o := &OmniSSM{
		config: config,
		registry: NewRegistrations(&RegistrationsConfig{
			AWSConfig: config.AWSConfig,
			TableName: config.RegistrationsTable,
		}),
		ssmAPI: ssm.New(config.AWSConfig),
	}
	if config.QueueName != "" {
		var err error
		o.deferQueue, err = sqs.NewQueue(&sqs.Config{
			AWSConfig: config.AWSConfig,
			QueueName: config.QueueName,
			//MessageGroupId: "omnissm-event-stream",
		})
		if err != nil {
			return nil, errors.Wrap(err, "cannot initialize SQS")
		}
	}

	return o, nil
}

func (o *OmniSSM) RequestActivation(ctx context.Context, req *RegistrationRequest) (*RegistrationResponse, error) {
	//if !req.Verified() {
	//return nil, errors.New("unverified registration request")
	//}
	entry, err := o.registry.Get(ctx, req.Hash())
	if err == nil {
		if ssm.IsManagedInstance(entry.ManagedId) || time.Now().Sub(entry.CreatedAt) < 12*time.Hour {
			// duplicate request
			return &RegistrationResponse{
				RegistrationEntry: *entry,
				Region:            req.Region,
				Existing:          true,
			}, nil
		}
	} else if errors.Cause(err) == ErrRegistrationNotFound {
		// new registration request
	} else {
		// unrelated failure
		return nil, err
	}
	activation, err := o.ssmAPI.CreateActivation(ctx, req.Name(), o.config.InstanceRole)
	if err != nil {
		// if we fail here, defer starting over
		return nil, o.tryDefer(ctx, err, RequestActivation, req)
	}
	entry = &RegistrationEntry{
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
	return &RegistrationResponse{
		RegistrationEntry: *entry,
		Region:            req.Region,
	}, nil
}

// ConfirmRegistration verifies the SSM registration for a given instance ID by
// sending the assigned managed instance id returned from the SSM service. The
// managed id is recorded in the registry.
func (o *OmniSSM) ConfirmRegistration(ctx context.Context, id, mid string) (*RegistrationEntry, error) {
	if !ssm.IsManagedInstance(mid) {
		return nil, errors.Wrapf(ssm.ErrInvalidInstance, "unable to confirm %#v - %#v", id, mid)
	}
	entry, err := o.registry.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	entry.ManagedId = mid
	if err := o.registry.SetManagedId(ctx, id, mid); err != nil {
		return nil, err
	}
	return entry, nil
}

func (o *OmniSSM) DeregisterInstance(ctx context.Context, entry *RegistrationEntry) error {
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
	return nil
}

func (o *OmniSSM) TagInstance(ctx context.Context, tags *ssm.ResourceTags) error {
	entry, err := o.registry.GetByManagedId(ctx, tags.ManagedId)
	if err != nil {
		if errors.Cause(err) == ErrRegistrationNotFound {
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
		if errors.Cause(err) == ErrRegistrationNotFound {
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
