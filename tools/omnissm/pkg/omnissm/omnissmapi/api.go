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

	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/s3"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/sns"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/sqs"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/ssm"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/xray"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/omnissm"
)

type Queue interface {
	Send(context.Context, json.Marshaler) error
}

type API struct {
	*Config
	*omnissm.Registrations
	*s3.S3
	*sns.SNS
	*ssm.SSM

	DeferQueue Queue
}

func New(config *Config) (*API, error) {
	o := &API{
		Config: config,
		Registrations: omnissm.NewRegistrations(&omnissm.RegistrationsConfig{
			Config:    config.Config,
			TableName: config.RegistrationsTable,
		}),
		SNS: sns.New(&sns.Config{
			Config:     config.Config,
			AssumeRole: config.S3DownloadRole,
		}),
		SSM: ssm.New(&ssm.Config{
			Config:       config.Config,
			InstanceRole: config.InstanceRole,
		}),
		S3: s3.New(&s3.Config{
			Config:     config.Config,
			AssumeRole: config.S3DownloadRole,
		}),
	}
	if config.QueueName != "" {
		q, err := sqs.New(&sqs.Config{
			Config:         config.Config,
			MessageGroupId: "omnissm-event-stream",
			QueueName:      config.QueueName,
		})

		if err != nil {
			return nil, errors.Wrap(err, "cannot initialize SQS")
		}
		if config.XRayTracingEnabled != "" {
			xray.EnableTracing(q)
		}
		o.DeferQueue = q
	}

	if config.XRayTracingEnabled != "" {
		xray.EnableTracing(o.S3)
		xray.EnableTracing(o.SNS)
		xray.EnableTracing(o.SSM)
		xray.EnableTracing(o.Registrations)
	}

	return o, nil
}

func (o *API) RequestActivation(ctx context.Context, req *omnissm.RegistrationRequest) (*omnissm.RegistrationResponse, error) {
	entry, err := o.Registrations.Get(ctx, req.Identity().Hash())
	if err == nil {
		if ssm.IsManagedInstance(entry.ManagedId) || time.Now().Sub(entry.CreatedAt) < 12*time.Hour {
			// duplicate request
			return &omnissm.RegistrationResponse{
				RegistrationEntry: *entry,
				Region:            req.Identity().Region,
				Existing:          true,
			}, nil
		}
	} else if errors.Cause(err) == omnissm.ErrRegistrationNotFound {
		// new registration request
	} else {
		// unrelated failure
		return nil, err
	}
	activation, err := o.SSM.CreateActivation(ctx, req.Identity().Name())
	if err != nil {
		// if we fail here, defer starting over
		return nil, o.tryDefer(ctx, err, RequestActivation, req)
	}
	entry = &omnissm.RegistrationEntry{
		Id:            req.Identity().Hash(),
		CreatedAt:     time.Now().UTC(),
		AccountId:     req.Identity().AccountId,
		Region:        req.Identity().Region,
		InstanceId:    req.Identity().InstanceId,
		ClientVersion: req.ClientVersion,
		Activation:    *activation,
		ManagedId:     "-",
	}
	if err := o.Registrations.Put(ctx, entry); err != nil {
		// if we fail here, defer saving the created activation to alleviate
		// pressure on SSM to create it again
		return nil, o.tryDefer(ctx, err, PutRegistrationEntry, entry)
	}
	return &omnissm.RegistrationResponse{
		RegistrationEntry: *entry,
		Region:            req.Identity().Region,
	}, nil
}

func (o *API) DeregisterInstance(ctx context.Context, entry *omnissm.RegistrationEntry) error {
	// Check dynamodb first to ease API pressure on SSM for repeat/invalid calls
	if _, err := o.Registrations.Get(ctx, entry.Id); err != nil {
		return o.tryDefer(ctx, err, DeregisterInstance, entry)
	}
	if err := o.SSM.DeregisterManagedInstance(ctx, entry.ManagedId); err != nil {
		// if we fail here, defer starting over
		return o.tryDefer(ctx, err, DeregisterInstance, entry)
	}
	return o.DeleteRegistration(ctx, entry)
}

func (o *API) DeleteRegistration(ctx context.Context, entry *omnissm.RegistrationEntry) error {
	if err := o.Registrations.Delete(ctx, entry.Id); err != nil {
		// if we fail here, defer starting over
		return o.tryDefer(ctx, err, DeleteRegistrationEntry, entry)
	}
	if o.Config.ResourceDeletedSNSTopic != "" {
		data, err := json.Marshal(map[string]interface{}{
			"ManagedId":    entry.ManagedId,
			"ResourceId":   entry.InstanceId,
			"AWSAccountId": entry.AccountId,
			"AWSRegion":    entry.Region,
		})
		if err != nil {
			return errors.Wrap(err, "cannot marshal SNS message")
		}
		if err := o.SNS.Publish(ctx, o.Config.ResourceDeletedSNSTopic, data); err != nil {
			return err
		}
	}
	return nil
}

func (o *API) TagInstance(ctx context.Context, tags *ssm.ResourceTags) error {
	entry, err := o.Registrations.GetByManagedId(ctx, tags.ManagedId)
	if err != nil {
		if errors.Cause(err) == omnissm.ErrRegistrationNotFound {
			return errors.Wrapf(err, "failed to tag instance %#v", tags.ManagedId)
		}
		return err
	}
	if err := o.SSM.AddTagsToResource(ctx, tags); err != nil {
		return o.tryDefer(ctx, err, AddTagsToResource, tags)
	}
	entry.IsTagged = 1
	if err := o.Registrations.Update(ctx, entry); err != nil {
		return errors.Wrap(err, "failed to update registration table with tagged flag")
	}
	return nil
}

func (o *API) PutInstanceInventory(ctx context.Context, inv *ssm.CustomInventory) error {
	entry, err := o.Registrations.GetByManagedId(ctx, inv.ManagedId)
	if err != nil {
		if errors.Cause(err) == omnissm.ErrRegistrationNotFound {
			return errors.Wrapf(err, "cannot PutInventory for instance %#v", inv.ManagedId)
		}
		return err
	}
	if err := o.SSM.PutInventory(ctx, inv); err != nil {
		return o.tryDefer(ctx, err, PutInventory, inv)
	}
	entry.IsInventoried = 1
	if err := o.Registrations.Update(ctx, entry); err != nil {
		return err
	}
	return nil
}

func (o *API) tryDefer(ctx context.Context, err error, t DeferredActionType, value interface{}) error {
	if c := errors.Cause(err); o.DeferQueue != nil && (request.IsErrorThrottle(c) || request.IsErrorRetryable(c)) {
		sqsErr := o.DeferQueue.Send(ctx, &DeferredActionMessage{
			Type:  t,
			Value: value,
		})
		if sqsErr != nil {
			return errors.Wrapf(sqsErr, "could not defer message (original error: %v)", err)
		}
		return errors.Wrapf(err, "deferred action to SQS queue (%s)", o.Config.QueueName)
	}
	return err
}
