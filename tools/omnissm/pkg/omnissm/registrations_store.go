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
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	awsclient "github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/pkg/errors"

	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/ssm"
)

var ErrRegistrationNotFound = errors.New("instance registration not found")

type RegistrationEntry struct {
	Id         string    `json:"id,omitempty"`
	CreatedAt  time.Time `json:"CreatedAt"`
	ManagedId  string    `json:"ManagedId"`
	AccountId  string    `json:"AccountId"`
	Region     string    `json:"Region"`
	InstanceId string    `json:"InstanceId"`

	// IsTagged and IsInventoried are logically bool types, but must be
	// represented as integers to allow for a LSI to be created in DynamoDB, as
	// DynamoDB disallows creating a LSI on a Bool type. The value is false
	// when equal to 0 and true when greater than 0.
	IsTagged      int `json:"IsTagged,omitempty"`
	IsInventoried int `json:"IsInventoried,omitempty"`

	ClientVersion string `json:"ClientVersion,omitempty"`

	// ActivationId/ActivationCode for registering with SSM
	ssm.Activation
}

type RegistrationsConfig struct {
	*aws.Config

	TableName string
	TestDB    dynamodbiface.DynamoDBAPI
}

type Registrations struct {
	dynamodbiface.DynamoDBAPI

	config *RegistrationsConfig
}

func NewRegistrations(config *RegistrationsConfig) *Registrations {
	r := &Registrations{
		DynamoDBAPI: config.TestDB,
		config:      config,
	}
	if r.DynamoDBAPI == nil {
		r.DynamoDBAPI = dynamodb.New(session.New(config.Config))
	}
	return r
}

func (r *Registrations) Client() *awsclient.Client {
	if d, ok := r.DynamoDBAPI.(*dynamodb.DynamoDB); ok {
		return d.Client
	}
	return nil
}

func (r *Registrations) queryIndex(ctx context.Context, indexName, attrName, value string) ([]*RegistrationEntry, error) {
	input := &dynamodb.QueryInput{
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{":v1": {N: aws.String(value)}},
		IndexName:                 aws.String(indexName),
		KeyConditionExpression:    aws.String(fmt.Sprintf("%s = :v1", attrName)),
		TableName:                 aws.String(r.config.TableName),
	}
	items := make([]map[string]*dynamodb.AttributeValue, 0)
	err := r.DynamoDBAPI.QueryPagesWithContext(ctx, input, func(page *dynamodb.QueryOutput, lastPage bool) bool {
		items = append(items, page.Items...)
		return !lastPage
	})
	if err != nil {
		return nil, errors.Wrap(err, "dynamodb.Scan failed")
	}
	entries := make([]*RegistrationEntry, 0)
	for _, item := range items {
		var entry RegistrationEntry
		if err := dynamodbattribute.UnmarshalMap(item, &entry); err != nil {
			return nil, err
		}
		entries = append(entries, &entry)
	}
	return entries, nil
}

type QueryIndexInput struct {
	IndexName, AttrName, Value string
}

func (r *Registrations) QueryIndexes(ctx context.Context, inputs ...QueryIndexInput) ([]*RegistrationEntry, error) {
	m := make(map[string]bool)
	entries := make([]*RegistrationEntry, 0)
	for _, input := range inputs {
		resp, err := r.queryIndex(ctx, input.IndexName, input.AttrName, input.Value)
		if err != nil {
			return nil, err
		}
		// avoid duplicates
		for _, entry := range resp {
			if !m[entry.Id] {
				entries = append(entries, entry)
				m[entry.Id] = true
			}
		}
	}
	return entries, nil
}

func (r *Registrations) Get(ctx context.Context, id string) (*RegistrationEntry, error) {
	resp, err := r.DynamoDBAPI.GetItemWithContext(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.config.TableName),
		//AttributesToGet: aws.StringSlice([]string{"id", "ActivationId", "ActivationCode", "ManagedId"}),
		Key: map[string]*dynamodb.AttributeValue{"id": {S: aws.String(id)}},
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == dynamodb.ErrCodeResourceNotFoundException {
				return nil, ErrRegistrationNotFound
			}
		}
		return nil, errors.Wrap(err, "dynamodb.Get failed")
	}
	if resp.Item == nil {
		return nil, ErrRegistrationNotFound
	}
	var entry RegistrationEntry
	if err := dynamodbattribute.UnmarshalMap(resp.Item, &entry); err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal dynamodbattribute map")
	}
	return &entry, nil
}

func (r *Registrations) GetByManagedId(ctx context.Context, managedId string) (*RegistrationEntry, error) {
	resp, err := r.DynamoDBAPI.QueryWithContext(ctx, &dynamodb.QueryInput{
		TableName: aws.String(r.config.TableName),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":v1": {S: aws.String(managedId)},
		},
		IndexName:              aws.String("ManagedId-index"),
		KeyConditionExpression: aws.String("ManagedId = :v1"),
	})
	if err != nil {
		return nil, errors.Wrap(err, "GetByManagedId (dynamodb.Query) failed")
	}
	if len(resp.Items) == 0 {
		return nil, ErrRegistrationNotFound
	}
	var entry RegistrationEntry
	if err := dynamodbattribute.UnmarshalMap(resp.Items[0], &entry); err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal dynamodbattribute map")
	}
	return &entry, nil
}

func (r *Registrations) Put(ctx context.Context, entry *RegistrationEntry) error {
	item, err := dynamodbattribute.MarshalMap(entry)
	if err != nil {
		return err
	}
	_, err = r.DynamoDBAPI.PutItemWithContext(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(r.config.TableName),
		Item:      item,
	})
	return err
}

func bton(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func (r *Registrations) setField(ctx context.Context, id, field string, v *dynamodb.AttributeValue) error {
	_, err := r.DynamoDBAPI.UpdateItemWithContext(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(r.config.TableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {S: aws.String(id)},
		},
		UpdateExpression:          aws.String(fmt.Sprintf("SET %s=:v1", field)),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{":v1": v},
	})
	return errors.Wrapf(err, "unable to update entry %#v field %#v", id, field)
}

func (r *Registrations) SetManagedId(ctx context.Context, id, mid string) error {
	return r.setField(ctx, id, "ManagedId", &dynamodb.AttributeValue{S: aws.String(mid)})
}

func (r *Registrations) SetTagged(ctx context.Context, id string, b bool) error {
	return r.setField(ctx, id, "IsTagged", &dynamodb.AttributeValue{N: aws.String(bton(b))})
}

func (r *Registrations) SetInventoried(ctx context.Context, id string, b bool) error {
	return r.setField(ctx, id, "IsInventoried", &dynamodb.AttributeValue{N: aws.String(bton(b))})
}

func (r *Registrations) Delete(ctx context.Context, id string) error {
	_, err := r.DynamoDBAPI.DeleteItemWithContext(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(r.config.TableName),
		Key:       map[string]*dynamodb.AttributeValue{"id": {S: aws.String(id)}},
	})
	if err != nil {
		// NOTE: we do not check for ResourceNotFound here because DeleteItem
		// does not return it in the case that an item with the given key is not
		// found in the table. However it does return ResourceNotFound if the
		// table itself does not exist, so we should propagate it in that case.
		return errors.Wrapf(err, "unable to delete entry: %#v", id)
	}
	return nil
}
