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

package omnissm_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/ssm"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/omnissm"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
)

type dbItem map[string]*dynamodb.AttributeValue

type mockDynamoDB struct {
	dynamodbiface.DynamoDBAPI

	t                 *testing.T
	items             map[string]dbItem
	expectedTableName string
}

func (db *mockDynamoDB) checkTable(name *string) {
	db.t.Helper() // do not include this method in test stack trace
	if aws.StringValue(name) != db.expectedTableName {
		db.t.Errorf("unexpected table name in input:\n\tgot:  %#v\n\twant: %#v", *name, db.expectedTableName)
	}
}

// NOTE: all mockDynamoDB methods are specifically tailored to emulated only the
// inputs/outputs we expect to use in omnissm.Registrations

func (db *mockDynamoDB) QueryWithContext(ctx aws.Context, input *dynamodb.QueryInput, o ...request.Option) (*dynamodb.QueryOutput, error) {
	db.checkTable(input.TableName)

	if aws.StringValue(input.IndexName) != "ManagedId-index" {
		db.t.Errorf("unexpected query index in input:\n\tgot:  %#v\n\twant: %#v", *input.IndexName, "ManagedId-index")
	}

	target := aws.StringValue(input.ExpressionAttributeValues[":v1"].S)

	results := make([]map[string]*dynamodb.AttributeValue, 0)
	for _, item := range db.items {
		if target == aws.StringValue(item["ManagedId"].S) {
			results = append(results, item)
		}
	}
	return &dynamodb.QueryOutput{Items: results}, nil
}

func (db *mockDynamoDB) QueryPagesWithContext(ctx aws.Context, input *dynamodb.QueryInput, pageFunc func(*dynamodb.QueryOutput, bool) bool, o ...request.Option) error {
	db.checkTable(input.TableName)

	cKey := strings.TrimSpace(strings.SplitN(*input.KeyConditionExpression, "=", 2)[0])
	cValue := aws.StringValue(input.ExpressionAttributeValues[":v1"].N)

	results := make([]map[string]*dynamodb.AttributeValue, 0)
	for _, item := range db.items {
		if item[cKey] == nil {
			if cValue == "0" {
				results = append(results, item)
			}
		} else if aws.StringValue(item[cKey].N) == cValue {
			results = append(results, item)
		}
	}
	pageFunc(&dynamodb.QueryOutput{Items: results}, true)
	return nil
}

func (db *mockDynamoDB) ScanPagesWithContext(ctx aws.Context, input *dynamodb.ScanInput, pageFunc func(*dynamodb.ScanOutput, bool) bool, o ...request.Option) error {
	db.checkTable(input.TableName)
	return nil
}

func (db *mockDynamoDB) GetItemWithContext(ctx aws.Context, input *dynamodb.GetItemInput, o ...request.Option) (*dynamodb.GetItemOutput, error) {
	db.checkTable(input.TableName)
	item, ok := db.items[*input.Key["id"].S]
	if !ok {
		return nil, awserr.New(dynamodb.ErrCodeResourceNotFoundException, "", errors.New("dummy"))
	}
	return &dynamodb.GetItemOutput{Item: item}, nil
}

func (db *mockDynamoDB) PutItemWithContext(ctx aws.Context, input *dynamodb.PutItemInput, o ...request.Option) (*dynamodb.PutItemOutput, error) {
	db.checkTable(input.TableName)
	db.items[aws.StringValue(input.Item["id"].S)] = input.Item
	return nil, nil
}

func (db *mockDynamoDB) UpdateItemWithContext(ctx aws.Context, input *dynamodb.UpdateItemInput, o ...request.Option) (*dynamodb.UpdateItemOutput, error) {
	db.checkTable(input.TableName)
	key := aws.StringValue(input.Key["id"].S)
	item := db.items[key]
	if item == nil {
		item = make(dbItem)
		db.items[key] = item
		item["id"] = &dynamodb.AttributeValue{S: aws.String(key)}
	}
	// this is hacky of course, but it is fine for the purpose of a very limited test case
	exprs := strings.Split(strings.TrimPrefix(aws.StringValue(input.UpdateExpression), "SET"), ",")
	for _, e := range exprs {
		parts := strings.SplitN(strings.TrimSpace(e), "=", 2)
		if len(parts) != 2 {
			panic(fmt.Sprintf("invalid UpdateExpression %#v", aws.StringValue(input.UpdateExpression)))
		}
		v, ok := input.ExpressionAttributeValues[parts[1]]
		if !ok {
			panic(fmt.Sprintf("invalid UpdateExpression %#v (missing AttributeValue %#v)", aws.StringValue(input.UpdateExpression), parts[1]))
		}
		item[parts[0]] = v
	}
	return nil, nil
}

func (db *mockDynamoDB) DeleteItemWithContext(ctx aws.Context, input *dynamodb.DeleteItemInput, o ...request.Option) (*dynamodb.DeleteItemOutput, error) {
	if aws.StringValue(input.TableName) == "test-not-found" {
		return nil, awserr.New(dynamodb.ErrCodeResourceNotFoundException, "", errors.New("dummy"))
	}
	db.checkTable(input.TableName)

	delete(db.items, aws.StringValue(input.Key["id"].S))
	return nil, nil
}

func newWithMock(t *testing.T, table string) (*omnissm.Registrations, *mockDynamoDB) {
	m := &mockDynamoDB{
		items:             make(map[string]dbItem),
		expectedTableName: table,
		t:                 t,
	}
	r := omnissm.NewRegistrations(&omnissm.RegistrationsConfig{
		TableName: table,
		TestDB:    m,
	})
	if r == nil {
		t.Fatal("NewRegistrations returned nil")
	}
	return r, m
}

func checkEntry(orig *omnissm.RegistrationEntry, item dbItem) error {
	checkString := func(o string, item dbItem, k string) error {
		if _, ok := item[k]; !ok {
			return errors.Errorf("entry did not contain key %#v", k)
		}
		if i := aws.StringValue(item[k].S); o != i {
			return errors.Errorf("entry %#v did not match:\ngot:  %#v\nwant: %#v", k, i, o)
		}
		return nil
	}
	checkInt := func(o int, item dbItem, k string) error {
		if _, ok := item[k]; !ok {
			return fmt.Errorf("entry did not contain key %#v", k)
		}
		if i := aws.StringValue(item[k].N); fmt.Sprintf("%d", o) != i {
			return fmt.Errorf("entry %#v did not match:\ngot:  %#v\nwant: %#v", k, i, fmt.Sprintf("%d", o))
		}
		return nil
	}

	fields := []struct {
		v    interface{}
		k    string
		omit bool
	}{
		{v: orig.Id, k: "id"},
		{v: orig.CreatedAt.Format(time.RFC3339Nano), k: "CreatedAt"},
		{v: orig.ManagedId, k: "ManagedId"},
		{v: orig.AccountId, k: "AccountId"},
		{v: orig.Region, k: "Region"},
		{v: orig.InstanceId, k: "InstanceId"},
		{v: orig.IsTagged, k: "IsTagged", omit: true},
		{v: orig.IsInventoried, k: "IsInventoried", omit: true},
		{v: orig.ClientVersion, k: "ClientVersion", omit: true},
		{v: orig.ActivationId, k: "ActivationId"},
		{v: orig.ActivationCode, k: "ActivationCode"},
	}

	for _, f := range fields {
		switch v := f.v.(type) {
		case string:
			_, ok := item[f.k]
			if f.v == "" && f.omit {
				if ok {
					return errors.Errorf("entry %#v with zero value should have been ommitted, but was not", f.k)
				}
			} else if err := checkString(v, item, f.k); err != nil {
				return err
			}
		case int:
			_, ok := item[f.k]
			if f.v == 0 && f.omit {
				if ok {
					return errors.Errorf("entry %#v with zero value should have been ommitted, but was not", f.k)
				}
			} else if err := checkInt(v, item, f.k); err != nil {
				return err
			}
		default:
			panic(fmt.Sprintf("unexpected field value type %T", v))
		}
	}
	return nil
}

func TestNewRegistrations(t *testing.T) {
	newWithMock(t, "test-table")
}

func TestRegistrationsGet(t *testing.T) {
	r, m := newWithMock(t, "test-table")

	cases := []struct {
		name  string
		id    string
		mid   string
		entry *omnissm.RegistrationEntry
	}{
		{"nonexistant entry", "doesnotexist", "doesnotexist", nil},
		{"empty", "", "", &omnissm.RegistrationEntry{
			Id: "empty",
		}},
		{"no flags", "1", "mi-1", &omnissm.RegistrationEntry{
			Id:            "testing",
			ManagedId:     "mi-1",
			AccountId:     "123456",
			Region:        "us-east-1",
			ClientVersion: "1.0.2",
		}},
		{"flags, no version", "2", "mi-2", &omnissm.RegistrationEntry{
			Id:            "testing2",
			ManagedId:     "mi-2",
			AccountId:     "123456",
			Region:        "us-east-1",
			IsTagged:      1,
			IsInventoried: 1,
			Activation:    ssm.Activation{ActivationId: "activation_id"},
		}},
		{"full", "3", "mi-3", &omnissm.RegistrationEntry{
			Id:            "testing3",
			ManagedId:     "mi-3",
			CreatedAt:     time.Now(),
			AccountId:     "123456",
			Region:        "us-east-1",
			IsTagged:      1,
			IsInventoried: 1,
			ClientVersion: "1.0.2",
			Activation:    ssm.Activation{ActivationId: "activation_id", ActivationCode: "codecode"},
		}},
	}

	for _, c := range cases {
		if c.entry == nil {
			continue
		}
		item, err := dynamodbattribute.MarshalMap(c.entry)
		if err != nil {
			t.Errorf("%s - %v", c.name, err)
			continue
		}
		m.items[c.id] = item
	}

	for _, c := range cases {
		{
			resp, err := r.Get(context.Background(), c.id)
			if c.entry == nil {
				if resp != nil {
					t.Errorf("%s - expected resp to be nil, got %v", c.name, resp)
				} else if errors.Cause(err) != omnissm.ErrRegistrationNotFound {
					t.Errorf("%s - expected ErrRegistrationNotFound, got %v", c.name, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s - %v", c.name, err)
				continue
			}
			if d := cmp.Diff(resp, c.entry); d != "" {
				t.Errorf("%s - response entry does not match: %v", c.name, d)
			}
		}
	}

	for _, c := range cases {
		{
			resp, err := r.GetByManagedId(context.Background(), c.mid)
			if c.entry == nil {
				if resp != nil {
					t.Errorf("%s - expected resp to be nil, got %v", c.name, resp)
				} else if errors.Cause(err) != omnissm.ErrRegistrationNotFound {
					t.Errorf("%s - expected ErrRegistrationNotFound, got %v", c.name, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s - %v", c.name, err)
				continue
			}
			if d := cmp.Diff(resp, c.entry); d != "" {
				t.Errorf("%s - response entry does not match: %v", c.name, d)
			}
		}
	}
}

func TestRegistrationsPut(t *testing.T) {
	r, m := newWithMock(t, "test-table")

	cases := []struct {
		name  string
		entry omnissm.RegistrationEntry
	}{
		{"empty", omnissm.RegistrationEntry{
			Id: "empty",
		}},
		{"no flags", omnissm.RegistrationEntry{
			Id:            "testing",
			AccountId:     "123456",
			Region:        "us-east-1",
			ClientVersion: "1.0.2",
		}},
		{"flags, no version", omnissm.RegistrationEntry{
			Id:            "testing2",
			AccountId:     "123456",
			Region:        "us-east-1",
			IsTagged:      1,
			IsInventoried: 1,
			Activation:    ssm.Activation{ActivationId: "activation_id"},
		}},
		{"full", omnissm.RegistrationEntry{
			Id:            "testing3",
			CreatedAt:     time.Now(),
			AccountId:     "123456",
			Region:        "us-east-1",
			IsTagged:      1,
			IsInventoried: 1,
			ClientVersion: "1.0.2",
			Activation:    ssm.Activation{ActivationId: "activation_id", ActivationCode: "codecode"},
		}},
	}

	for _, c := range cases {
		if err := r.Put(context.Background(), &c.entry); err != nil {
			t.Error(err)
		}
		saved, ok := m.items[c.entry.Id]
		if !ok {
			t.Errorf("%s - item not added to mock dynamodb", c.name)
		}
		if err := checkEntry(&c.entry, saved); err != nil {
			t.Errorf("%s - %v", c.name, err)
		}
	}
}

func TestRegistrationsQueryIndexes(t *testing.T) {
	r, m := newWithMock(t, "test-table")

	input := []struct {
		name  string
		entry omnissm.RegistrationEntry
	}{
		{"no flags", omnissm.RegistrationEntry{
			Id:            "testing",
			AccountId:     "123456",
			Region:        "us-east-1",
			ClientVersion: "1.0.2",
		}},
		{"tagged", omnissm.RegistrationEntry{
			Id:         "testing2",
			AccountId:  "123456",
			Region:     "us-east-1",
			IsTagged:   1,
			Activation: ssm.Activation{ActivationId: "activation_id"},
		}},
		{"inventoried", omnissm.RegistrationEntry{
			Id:            "testing3",
			AccountId:     "123456",
			Region:        "us-east-1",
			IsInventoried: 1,
			Activation:    ssm.Activation{ActivationId: "activation_id"},
		}},
		{"full", omnissm.RegistrationEntry{
			Id:            "testing4",
			CreatedAt:     time.Now(),
			AccountId:     "123456",
			Region:        "us-east-1",
			IsTagged:      1,
			IsInventoried: 1,
			ClientVersion: "1.0.2",
			Activation:    ssm.Activation{ActivationId: "activation_id", ActivationCode: "codecode"},
		}},
	}

	for _, c := range input {
		item, err := dynamodbattribute.MarshalMap(c.entry)
		if err != nil {
			t.Errorf("%s - %v", c.name, err)
			continue
		}
		m.items[c.entry.Id] = item
	}

	entries := func(ii ...int) []*omnissm.RegistrationEntry {
		e := make([]*omnissm.RegistrationEntry, 0)
		for _, i := range ii {
			e = append(e, &input[i].entry)
		}
		return e
	}

	cases := []struct {
		name     string
		options  []omnissm.QueryIndexInput
		expected []*omnissm.RegistrationEntry
	}{
		{
			"IsTagged = 2",
			[]omnissm.QueryIndexInput{{"IsTagged-index", "IsTagged", "2"}},
			entries(),
		},
		{
			"IsTagged = 0",
			[]omnissm.QueryIndexInput{{"IsTagged-index", "IsTagged", "0"}},
			entries(0, 2),
		},
		{
			"IsTagged = 1",
			[]omnissm.QueryIndexInput{{"IsTagged-index", "IsTagged", "1"}},
			entries(1, 3),
		},
		{
			"IsInventoried = 0",
			[]omnissm.QueryIndexInput{{"IsInventoried-index", "IsInventoried", "0"}},
			entries(0, 1),
		},
		{
			"IsTagged = 0 || IsInventoried = 0",
			[]omnissm.QueryIndexInput{
				{"IsTagged-index", "IsTagged", "0"},
				{"IsInventoried-index", "IsInventoried", "0"},
			},
			entries(0, 1, 2),
		},
		{
			"IsTagged = 1 || IsInventoried = 1",
			[]omnissm.QueryIndexInput{
				{"IsTagged-index", "IsTagged", "1"},
				{"IsInventoried-index", "IsInventoried", "1"},
			},
			entries(1, 2, 3),
		},
	}

	for _, c := range cases {
		entries, err := r.QueryIndexes(context.Background(), c.options...)
		if err != nil {
			t.Errorf("%s - QueryIndexes failed: %v", c.name, err)
			continue
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Id < entries[j].Id
		})
		if d := cmp.Diff(entries, c.expected); d != "" {
			t.Errorf("%s - response entries do not match: %v", c.name, d)
		}
	}

}

func TestRegistrationsUpdate(t *testing.T) {
	r, m := newWithMock(t, "test-table")

	cases := []struct {
		name     string
		existing *omnissm.RegistrationEntry
		updated  *omnissm.RegistrationEntry
		expected *omnissm.RegistrationEntry
	}{
		{
			name: "not existing",
			updated: &omnissm.RegistrationEntry{
				Id:        "1",
				ManagedId: "mi-1",
			},
		},
		{
			name: "set partial flags",
			existing: &omnissm.RegistrationEntry{
				Id: "2",
			},
			updated: &omnissm.RegistrationEntry{
				Id:        "2",
				ManagedId: "mi-1",
				IsTagged:  1,
			},
		},
		{
			name: "set all flags",
			existing: &omnissm.RegistrationEntry{
				Id: "3",
			},
			updated: &omnissm.RegistrationEntry{
				Id:            "3",
				IsTagged:      1,
				IsInventoried: 1,
			},
		},
		{
			name: "merge fields",
			existing: &omnissm.RegistrationEntry{
				Id:            "4",
				ClientVersion: "1",
				IsTagged:      1,
			},
			updated: &omnissm.RegistrationEntry{
				Id:            "4",
				IsInventoried: 1,
			},
			expected: &omnissm.RegistrationEntry{
				Id:            "4",
				ClientVersion: "1",
				// NOTE: field is overriden by zero value in request
				IsTagged:      0,
				IsInventoried: 1,
			},
		},
		{
			name: "don't update extraneous fields",
			existing: &omnissm.RegistrationEntry{
				Id:            "5",
				ClientVersion: "1",
			},
			updated: &omnissm.RegistrationEntry{
				Id:            "5",
				ManagedId:     "mi-2",
				IsTagged:      1,
				IsInventoried: 1,
				ClientVersion: "2",
				Region:        "us-west-1",
			},
			expected: &omnissm.RegistrationEntry{
				Id:            "5",
				ManagedId:     "mi-2",
				ClientVersion: "1",
				IsTagged:      1,
				IsInventoried: 1,
			},
		},
	}

	for _, c := range cases {
		if c.existing == nil {
			continue
		}
		if c.existing.Id != c.updated.Id {
			panic(fmt.Sprintf("misconfigured test case %#v: Id fields do not match", c.name))
		}
		item, err := dynamodbattribute.MarshalMap(c.existing)
		if err != nil {
			t.Errorf("unexpected error while marshaling input - %v", err)
			continue
		}
		m.items[c.existing.Id] = item
	}

	for _, c := range cases {
		if err := r.Update(context.Background(), c.updated); err != nil {
			t.Errorf("%s - unexpected error during Update: %v", c.name, err)
		}
		entry, err := r.Get(context.Background(), c.updated.Id)
		if err != nil {
			t.Errorf("%s - unexpected error during Get: %v", c.name, err)
		}

		expected := c.expected
		if expected == nil {
			expected = c.updated
		}

		if d := cmp.Diff(expected, entry); d != "" {
			t.Errorf("%s - response entries do not match: %v", c.name, d)
		}
	}
}

func TestRegistrationsDelete(t *testing.T) {
	r, m := newWithMock(t, "test-table")

	input := []omnissm.RegistrationEntry{
		omnissm.RegistrationEntry{
			Id: "empty",
		},
		omnissm.RegistrationEntry{
			Id:            "testing",
			AccountId:     "123456",
			Region:        "us-east-1",
			ClientVersion: "1.0.2",
		},
		omnissm.RegistrationEntry{
			Id:            "testing2",
			AccountId:     "123456",
			Region:        "us-east-1",
			IsTagged:      1,
			IsInventoried: 1,
			Activation:    ssm.Activation{ActivationId: "activation_id"},
		},
		omnissm.RegistrationEntry{
			Id:            "testing3",
			CreatedAt:     time.Now(),
			AccountId:     "123456",
			Region:        "us-east-1",
			IsTagged:      1,
			IsInventoried: 1,
			ClientVersion: "1.0.2",
			Activation:    ssm.Activation{ActivationId: "activation_id", ActivationCode: "codecode"},
		},
	}

	for _, c := range input {
		item, err := dynamodbattribute.MarshalMap(c)
		if err != nil {
			t.Errorf("unexpected error while marshaling input - %v", err)
			continue
		}
		m.items[c.Id] = item
	}

	if _, err := r.Get(context.Background(), input[1].Id); err != nil {
		t.Errorf("could not retrieve entry: %v", err)
	}
	if err := r.Delete(context.Background(), input[1].Id); err != nil {
		t.Errorf("unexpected error while deleting entry: %v", err)
	}
	_, err := r.Get(context.Background(), input[1].Id)
	if errors.Cause(err) != omnissm.ErrRegistrationNotFound {
		t.Errorf("expected ErrRegistrationNotFound after deleting item, got: %v", err)
	}
	// deleting twice should not cause an error
	if err := r.Delete(context.Background(), input[1].Id); err != nil {
		t.Errorf("double-delete caused unexpected error: %v", err)
	}

	// get a new item, which should be valid
	entry, err := r.Get(context.Background(), input[2].Id)
	if err != nil {
		t.Errorf("unrelated Get caused error: %v", err)
	}
	if d := cmp.Diff(&input[2], entry); d != "" {
		t.Errorf("response entry does not match: %v", d)
	}

	// deleting an item that does not exist should not raise an error
	if err := r.Delete(context.Background(), "fake-entry"); err != nil {
		t.Errorf("unexpected error while deleting entry that does not exist: %v", err)
	}
}

func TestRegistrationsDeleteResourceNotFound(t *testing.T) {
	r, m := newWithMock(t, "test-not-found")
	_, err := m.DeleteItemWithContext(context.Background(), &dynamodb.DeleteItemInput{
		TableName: aws.String(m.expectedTableName),
		Key:       nil,
	})
	// sanity check to ensure that the test case/mock is still correct
	if err == nil {
		panic("DeleteWithContext for nonexistent table test did not return an error")
	} else if aErr, ok := errors.Cause(err).(awserr.Error); !ok || aErr.Code() != dynamodb.ErrCodeResourceNotFoundException {
		panic("DeleteWithContext for nonexistent table returned unexpected error: " + err.Error())
	}

	// actual test
	if err := r.Delete(context.Background(), "any-id"); err == nil {
		t.Errorf("Delete did not return an error for nonexistent table")
	} else if aErr, ok := errors.Cause(err).(awserr.Error); !ok || aErr.Code() != dynamodb.ErrCodeResourceNotFoundException {
		t.Errorf("Delete for nonexistent table did not return expected ResourceNotFoundException, instead returned: %v", err)
	}
}
