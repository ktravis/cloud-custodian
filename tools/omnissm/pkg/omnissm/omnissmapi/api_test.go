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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/ssm"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/omnissm"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	throttleError error = awserr.New("Throttling", "test message", nil)
	fatalError    error = awserr.New("simulated fatal error", "test message", nil)

	stdCmpOpts = []cmp.Option{
		cmp.FilterPath(func(p cmp.Path) bool {
			return p.Last().String() == ".CreatedAt"
		}, cmp.Ignore()),

		cmpopts.IgnoreUnexported(
			omnissm.SecureIdentity{},
			omnissm.RegistrationRequest{},
			omnissm.RegistrationResponse{},
		),
	}
)

// Actual tests

func TestOmniSSMRequestActivation(t *testing.T) {
	req := &omnissm.RegistrationRequest{
		SecureIdentity: omnissm.SecureIdentity{
			InstanceIdentity: &omnissm.InstanceIdentity{
				AccountId:  "my_account",
				InstanceId: "i-0123456789012345",
			},
		},
	}
	managedEntry := &omnissm.RegistrationEntry{
		Id:         req.Hash(),
		ManagedId:  "mi-0123456789012345",
		AccountId:  req.AccountId,
		InstanceId: req.InstanceId,
	}
	activationEntry := &omnissm.RegistrationEntry{
		Id:         req.Hash(),
		ManagedId:  "-",
		CreatedAt:  time.Now(), // TODO: RequestActivation checks against time.Now, consider refactor
		AccountId:  req.AccountId,
		InstanceId: req.InstanceId,
		Activation: ssm.Activation{ActivationCode: "code", ActivationId: "id"},
	}
	oldActivationEntry := &omnissm.RegistrationEntry{
		Id:         req.Hash(),
		ManagedId:  "-",
		CreatedAt:  time.Now().Add(-48 * time.Hour), // TODO: See above
		AccountId:  req.AccountId,
		InstanceId: req.InstanceId,
		Activation: ssm.Activation{ActivationCode: "expired code", ActivationId: "expired id"},
	}

	cases := []struct {
		name          string
		request       *omnissm.RegistrationRequest
		entries       map[string]*omnissm.RegistrationEntry
		newActivation func(string) (*ssm.Activation, error)
		wantDeferred  *DeferredActionMessage
		wantResponse  *omnissm.RegistrationResponse
		checkError    func(error) bool
	}{
		{
			name:    "instance already managed",
			request: req,
			entries: map[string]*omnissm.RegistrationEntry{managedEntry.Id: managedEntry},
			wantResponse: &omnissm.RegistrationResponse{
				RegistrationEntry: *managedEntry,
				Existing:          true,
			},
		},

		{
			name:    "activiation previously created",
			request: req,
			entries: map[string]*omnissm.RegistrationEntry{activationEntry.Id: activationEntry},
			wantResponse: &omnissm.RegistrationResponse{
				RegistrationEntry: *activationEntry,
				Existing:          true,
			},
		},

		{
			name:          "activiation expired",
			request:       req,
			entries:       map[string]*omnissm.RegistrationEntry{oldActivationEntry.Id: oldActivationEntry},
			newActivation: func(name string) (*ssm.Activation, error) { return &activationEntry.Activation, nil },
			wantResponse: &omnissm.RegistrationResponse{
				RegistrationEntry: *activationEntry,
			},
		},

		{
			name:          "CreateActivation throttled",
			request:       req,
			newActivation: func(name string) (*ssm.Activation, error) { return nil, throttleError },
			wantDeferred:  &DeferredActionMessage{RequestActivation, req},
			checkError:    func(e error) bool { return e != nil && strings.HasPrefix(e.Error(), "deferred action") },
		},

		{
			name:          "CreateActivation fault",
			request:       req,
			newActivation: func(name string) (*ssm.Activation, error) { return nil, fatalError },
			checkError:    func(e error) bool { return e == fatalError },
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var deferred *DeferredActionMessage
			o := &OmniSSM{
				config:   &Config{QueueName: "defer"},
				registry: &mockRegistry{entries: c.entries},
				ssmAPI:   &mockSSMAPI{newActivation: c.newActivation},
				deferQueue: mockQueue(func(msg json.Marshaler) error {
					deferred = msg.(*DeferredActionMessage)
					return nil
				}),
			}

			resp, err := o.RequestActivation(context.Background(), c.request)
			if err != nil {
				if c.checkError == nil || !c.checkError(err) {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if d := cmp.Diff(c.wantDeferred, deferred, stdCmpOpts...); d != "" {
				t.Errorf("unexpected deferred message: %v", d)
			}

			if d := cmp.Diff(c.wantResponse, resp, stdCmpOpts...); d != "" {
				t.Errorf("unexpected response: %v", d)
			}
			if c.wantResponse != nil {
				want := &c.wantResponse.RegistrationEntry
				got := c.entries[want.Id]
				if d := cmp.Diff(want, got, stdCmpOpts...); d != "" {
					t.Errorf("unexpected response in registry table: %v", d)
				}

			}
		})
	}
}

func TestOmniSSMDeregisterInstance(t *testing.T) {
	//t.Fatal("TODO")
}

func TestOmniSSMTagInstance(t *testing.T) {
	//t.Fatal("TODO")
}

func TestOmniSSMTryDefer(t *testing.T) {
	//t.Fatal("TODO")
}

// Mocks definitions

var _ ssmAPI = (*mockSSMAPI)(nil)
var _ notifier = (mockNotifier)(nil)
var _ deferQueue = (mockQueue)(nil)
var _ registry = (*mockRegistry)(nil)

type mockSSMAPI struct {
	newActivation             func(string) (*ssm.Activation, error)
	addTagsToResource         func(*ssm.ResourceTags) error
	putInventory              func(*ssm.CustomInventory) error
	deregisterManagedInstance func(string) error
}

func (s *mockSSMAPI) CreateActivation(ctx context.Context, n string) (*ssm.Activation, error) {
	return s.newActivation(n)
}
func (s *mockSSMAPI) AddTagsToResource(ctx context.Context, tags *ssm.ResourceTags) error {
	return s.addTagsToResource(tags)
}
func (s *mockSSMAPI) PutInventory(ctx context.Context, inv *ssm.CustomInventory) error {
	return s.putInventory(inv)
}
func (s *mockSSMAPI) DeregisterManagedInstance(ctx context.Context, mid string) error {
	return s.deregisterManagedInstance(mid)
}

type mockNotifier func(string, []byte) error

func (n mockNotifier) Publish(ctx context.Context, topic string, b []byte) error {
	return n(topic, b)
}

type mockQueue func(json.Marshaler) error

func (q mockQueue) Send(ctx context.Context, m json.Marshaler) error {
	return q(m)
}

type mockRegistry struct {
	mu      sync.RWMutex
	entries map[string]*omnissm.RegistrationEntry
}

func (r *mockRegistry) Get(ctx context.Context, id string) (*omnissm.RegistrationEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[id]
	if !ok {
		return nil, omnissm.ErrRegistrationNotFound
	}
	return e, nil
}

func (r *mockRegistry) GetByManagedId(ctx context.Context, mid string) (*omnissm.RegistrationEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.entries {
		if e.ManagedId == mid {
			return e, nil
		}
	}
	return nil, omnissm.ErrRegistrationNotFound
}

func (r *mockRegistry) Put(ctx context.Context, e *omnissm.RegistrationEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[string]*omnissm.RegistrationEntry)
	}
	r.entries[e.Id] = e
	return nil
}

func (r *mockRegistry) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, id)
	return nil
}

func (r *mockRegistry) SetTagged(ctx context.Context, id string, b bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[id]
	if !ok {
		return omnissm.ErrRegistrationNotFound
	}
	if b {
		e.IsTagged = 1
	} else {
		e.IsTagged = 0
	}
	return nil
}

func (r *mockRegistry) SetInventoried(ctx context.Context, id string, b bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[id]
	if !ok {
		return omnissm.ErrRegistrationNotFound
	}
	if b {
		e.IsInventoried = 1
	} else {
		e.IsInventoried = 0
	}
	return nil
}
