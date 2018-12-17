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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/ssm"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pkg/errors"
)

var (
	throttleError error = awserr.New("Throttling", "test message", nil)
	fatalError    error = awserr.New("simulated fatal error", "test message", nil)

	stdCmpOpts = []cmp.Option{
		cmp.FilterPath(func(p cmp.Path) bool {
			return p.Last().String() == ".CreatedAt"
		}, cmp.Ignore()),

		cmpopts.IgnoreUnexported(
			SecureIdentity{},
			RegistrationRequest{},
			RegistrationResponse{},
		),
	}
)

func isError(err error) func(error) bool {
	return func(other error) bool { return err == other }
}

func isCausedBy(err error) func(error) bool {
	return func(other error) bool { return err == errors.Cause(other) }
}

func isDeferredError(e error) bool {
	return errors.Cause(e) == throttleError && strings.HasPrefix(e.Error(), "deferred action")
}

// Actual tests

func TestOmniSSMRequestActivation(t *testing.T) {
	req := &RegistrationRequest{
		SecureIdentity: SecureIdentity{
			InstanceIdentity: &InstanceIdentity{
				AccountId:  "my_account",
				InstanceId: "i-0123456789012345",
			},
		},
	}
	managedEntry := &RegistrationEntry{
		Id:         req.Hash(),
		ManagedId:  "mi-0123456789012345",
		AccountId:  req.AccountId,
		InstanceId: req.InstanceId,
	}
	activationEntry := &RegistrationEntry{
		Id:         req.Hash(),
		ManagedId:  "-",
		CreatedAt:  time.Now(), // TODO: RequestActivation checks against time.Now, consider refactor
		AccountId:  req.AccountId,
		InstanceId: req.InstanceId,
		Activation: ssm.Activation{ActivationCode: "code", ActivationId: "id"},
	}
	oldActivationEntry := &RegistrationEntry{
		Id:         req.Hash(),
		ManagedId:  "-",
		CreatedAt:  time.Now().Add(-48 * time.Hour), // TODO: See above
		AccountId:  req.AccountId,
		InstanceId: req.InstanceId,
		Activation: ssm.Activation{ActivationCode: "expired code", ActivationId: "expired id"},
	}

	cases := []struct {
		name          string
		request       *RegistrationRequest
		registry      registry
		newActivation func(string, string) (*ssm.Activation, error)
		wantDeferred  *DeferredActionMessage
		wantResponse  *RegistrationResponse
		checkError    func(error) bool
	}{
		{
			name:     "instance already managed",
			request:  req,
			registry: newMockRegistry(managedEntry),
			wantResponse: &RegistrationResponse{
				RegistrationEntry: *managedEntry,
				Existing:          true,
			},
		},

		{
			name:     "activiation previously created",
			request:  req,
			registry: newMockRegistry(activationEntry),
			wantResponse: &RegistrationResponse{
				RegistrationEntry: *activationEntry,
				Existing:          true,
			},
		},

		{
			name:          "activiation expired",
			request:       req,
			registry:      newMockRegistry(oldActivationEntry),
			newActivation: func(name, r string) (*ssm.Activation, error) { return &activationEntry.Activation, nil },
			wantResponse: &RegistrationResponse{
				RegistrationEntry: *activationEntry,
			},
		},

		{
			name:          "CreateActivation throttled",
			request:       req,
			registry:      &errRegistry{get: ErrRegistrationNotFound},
			newActivation: func(name, r string) (*ssm.Activation, error) { return nil, throttleError },
			wantDeferred:  &DeferredActionMessage{RequestActivation, req},
			checkError:    isDeferredError,
		},

		{
			name:          "CreateActivation fault",
			request:       req,
			registry:      &errRegistry{get: ErrRegistrationNotFound},
			newActivation: func(name, r string) (*ssm.Activation, error) { return nil, fatalError },
			checkError:    isError(fatalError),
		},

		{
			name:       "registry get error",
			request:    req,
			registry:   &errRegistry{get: fatalError},
			checkError: isError(fatalError),
		},

		{
			name:          "registry put error",
			request:       req,
			registry:      &errRegistry{get: ErrRegistrationNotFound, put: fatalError},
			newActivation: func(name, r string) (*ssm.Activation, error) { return &activationEntry.Activation, nil },
			checkError:    isError(fatalError),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var deferred *DeferredActionMessage
			o := &OmniSSM{
				config:     &Config{QueueName: "defer"},
				registry:   c.registry,
				ssmAPI:     &mockSSMAPI{newActivation: c.newActivation},
				deferQueue: mockQueue(&deferred),
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
				got := c.registry.(*mockRegistry).entries[want.Id]
				if d := cmp.Diff(want, got, stdCmpOpts...); d != "" {
					t.Errorf("unexpected response in registry table: %v", d)
				}

			}
		})
	}
}

func TestOmniSSMConfirmRegistration(t *testing.T) {
	req := &RegistrationRequest{
		SecureIdentity: SecureIdentity{
			InstanceIdentity: &InstanceIdentity{
				AccountId:  "my_account",
				InstanceId: "i-0123456789012345",
			},
		},
	}
	entry := &RegistrationEntry{
		Id:         req.Hash(),
		ManagedId:  "",
		AccountId:  req.AccountId,
		InstanceId: req.InstanceId,
	}
	managedEntry := &RegistrationEntry{
		Id:         req.Hash(),
		ManagedId:  "mi-12345",
		AccountId:  req.AccountId,
		InstanceId: req.InstanceId,
	}

	cases := []struct {
		name string
		registry
		id, mid    string
		wantEntry  *RegistrationEntry
		checkError func(error) bool
	}{
		{
			name:      "normal case",
			registry:  newMockRegistry(entry),
			id:        entry.Id,
			mid:       "mi-12345",
			wantEntry: managedEntry,
		},
		{
			name:       "unknown instance",
			registry:   newMockRegistry(),
			id:         entry.Id,
			mid:        "mi-12345",
			checkError: isError(ErrRegistrationNotFound),
		},
		{
			name:       "empty mid",
			registry:   newMockRegistry(entry),
			id:         entry.Id,
			checkError: isCausedBy(ssm.ErrInvalidInstance),
		},
		{
			name:       "invalid mid",
			registry:   newMockRegistry(entry),
			id:         entry.Id,
			mid:        "i-12345",
			checkError: isCausedBy(ssm.ErrInvalidInstance),
		},
		{
			name:       "SetManagedId fault",
			registry:   &errRegistry{entry: entry, setManagedId: fatalError},
			id:         entry.Id,
			mid:        "mi-12345",
			checkError: isError(fatalError),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := &OmniSSM{
				registry: c.registry,
			}

			entry, err := o.ConfirmRegistration(context.Background(), c.id, c.mid)
			if err != nil {
				if c.checkError == nil || !c.checkError(err) {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if d := cmp.Diff(c.wantEntry, entry, stdCmpOpts...); d != "" {
				t.Errorf("unexpected response entry: %v", d)
			}
		})
	}
}

func TestOmniSSMDeregisterInstance(t *testing.T) {
	existingEntry := &RegistrationEntry{
		Id:        "1",
		ManagedId: "mi-123",
		AccountId: "account",
		Region:    "reg",
	}

	cases := []struct {
		name                      string
		entry                     *RegistrationEntry
		registry                  registry
		deregisterManagedInstance func(string) error
		wantDeferred              *DeferredActionMessage
		checkError                func(error) bool
	}{
		{
			name:     "instance exists",
			entry:    existingEntry,
			registry: newMockRegistry(existingEntry),
			deregisterManagedInstance: func(id string) error {
				if id != existingEntry.ManagedId {
					return ssm.ErrInvalidInstance
				}
				return nil
			},
		},
		{
			name:     "instance exists sns",
			entry:    existingEntry,
			registry: newMockRegistry(existingEntry),
			deregisterManagedInstance: func(id string) error {
				if id != existingEntry.ManagedId {
					return ssm.ErrInvalidInstance
				}
				return nil
			},
		},
		{
			name:       "instance does not exist",
			entry:      existingEntry,
			registry:   newMockRegistry(),
			checkError: isCausedBy(ErrRegistrationNotFound),
		},
		{
			name:       "instance in registry only",
			entry:      existingEntry,
			checkError: isCausedBy(ErrRegistrationNotFound),
			registry:   newMockRegistry(existingEntry),

			deregisterManagedInstance: func(id string) error { return ssm.ErrInvalidInstance },
		},
		{
			name:         "ssm throttled",
			entry:        existingEntry,
			registry:     newMockRegistry(existingEntry),
			checkError:   isDeferredError,
			wantDeferred: &DeferredActionMessage{DeregisterInstance, existingEntry},

			deregisterManagedInstance: func(id string) error { return throttleError },
		},
		{
			name:       "ssm fatal",
			entry:      existingEntry,
			registry:   newMockRegistry(existingEntry),
			checkError: isError(fatalError),

			deregisterManagedInstance: func(id string) error { return fatalError },
		},
		{
			name:         "registry Get throttled",
			entry:        existingEntry,
			registry:     &errRegistry{get: throttleError},
			checkError:   isDeferredError,
			wantDeferred: &DeferredActionMessage{DeregisterInstance, existingEntry},
		},
		{
			name:       "registry Get fatal",
			entry:      existingEntry,
			registry:   &errRegistry{get: fatalError},
			checkError: isError(fatalError),
		},
		{
			name:       "registry Delete error",
			entry:      existingEntry,
			registry:   &errRegistry{delete: throttleError},
			checkError: isError(throttleError),

			deregisterManagedInstance: func(id string) error { return nil },
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var (
				deferred         *DeferredActionMessage
				calledDeregister bool
			)
			dereg := c.deregisterManagedInstance
			if dereg != nil {
				dereg = func(mid string) error {
					calledDeregister = true
					return c.deregisterManagedInstance(mid)
				}
			}
			o := &OmniSSM{
				config:     &Config{QueueName: "defer"},
				registry:   c.registry,
				ssmAPI:     &mockSSMAPI{deregisterManagedInstance: dereg},
				deferQueue: mockQueue(&deferred),
			}
			err := o.DeregisterInstance(context.Background(), c.entry)
			if err == nil {
				if _, ok := c.registry.(*mockRegistry).entries[c.entry.Id]; ok {
					t.Errorf("entry still present in registry: %+v", c.entry)
				}
			} else {
				if c.checkError == nil || !c.checkError(err) {
					t.Fatalf("unexpected error: %v", err)
				}
			}
			if c.deregisterManagedInstance != nil && !calledDeregister {
				t.Errorf("DeregisterManagedInstance was not called")
			}

			if d := cmp.Diff(c.wantDeferred, deferred, stdCmpOpts...); d != "" {
				t.Errorf("unexpected deferred message: %v", d)
			}
		})
	}
}

func TestOmniSSMTagInstance(t *testing.T) {
	entry := &RegistrationEntry{
		Id:        "1",
		ManagedId: "mi-123",
		AccountId: "account",
		Region:    "reg",
	}

	normalTags := &ssm.ResourceTags{
		ManagedId: entry.ManagedId,
		Tags: map[string]string{
			"Name": "App",
		},
	}

	cases := []struct {
		name              string
		tags              *ssm.ResourceTags
		registry          registry
		addTagsToResource func(*ssm.ResourceTags) error
		wantDeferred      *DeferredActionMessage
		checkError        func(error) bool
	}{
		{
			name:     "tag existing",
			tags:     normalTags,
			registry: newMockRegistry(entry),

			addTagsToResource: func(tags *ssm.ResourceTags) error { return nil },
		},
		{
			name:       "tag unkown",
			tags:       &ssm.ResourceTags{ManagedId: "unknown"},
			registry:   newMockRegistry(entry),
			checkError: isCausedBy(ErrRegistrationNotFound),
		},
		{
			name:       "registry error",
			tags:       normalTags,
			registry:   &errRegistry{getByManagedId: throttleError},
			checkError: isError(throttleError),
		},
		{
			name:         "ssm throttled",
			tags:         normalTags,
			registry:     newMockRegistry(entry),
			wantDeferred: &DeferredActionMessage{AddTagsToResource, normalTags},
			checkError:   isDeferredError,

			addTagsToResource: func(tags *ssm.ResourceTags) error { return throttleError },
		},
		{
			name:       "registry tag error",
			tags:       normalTags,
			registry:   &errRegistry{entry: entry, setTagged: fatalError},
			checkError: isError(fatalError),

			addTagsToResource: func(tags *ssm.ResourceTags) error { return nil },
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var (
				deferred *DeferredActionMessage
				gotTags  *ssm.ResourceTags
			)
			tagResource := c.addTagsToResource
			if tagResource != nil {
				tagResource = func(tags *ssm.ResourceTags) error {
					gotTags = tags
					return c.addTagsToResource(tags)
				}
			}
			o := &OmniSSM{
				config:     &Config{QueueName: "defer"},
				registry:   c.registry,
				ssmAPI:     &mockSSMAPI{addTagsToResource: tagResource},
				deferQueue: mockQueue(&deferred),
			}
			err := o.TagInstance(context.Background(), c.tags)
			if err == nil {
				mr := c.registry.(*mockRegistry)
				if e, err := mr.GetByManagedId(context.Background(), c.tags.ManagedId); err != nil {
					t.Errorf("entry for tags not found in registry: %+v", err)
				} else if e.IsTagged != 1 {
					t.Errorf("entry is not tagged in registry: %+v", e)
				}

				if d := cmp.Diff(c.tags, gotTags, stdCmpOpts...); d != "" {
					t.Errorf("unexpected resource tags: %v", d)
				}
			} else if c.checkError == nil || !c.checkError(err) {
				t.Fatalf("unexpected error: %v", err)
			}

			if d := cmp.Diff(c.wantDeferred, deferred, stdCmpOpts...); d != "" {
				t.Errorf("unexpected deferred message: %v", d)
			}
		})
	}
}

func TestOmniSSMPutInstanceInventory(t *testing.T) {
	entry := &RegistrationEntry{
		Id:        "1",
		ManagedId: "mi-123",
		AccountId: "account",
		Region:    "reg",
	}

	inv := &ssm.CustomInventory{
		TypeName:    "Inventory",
		ManagedId:   entry.ManagedId,
		CaptureTime: "2006-01-02T15:04:05Z",
		Content: map[string]string{
			"a": "b",
		},
	}

	cases := []struct {
		name         string
		inv          *ssm.CustomInventory
		registry     registry
		putInventory func(*ssm.CustomInventory) error
		wantDeferred *DeferredActionMessage
		checkError   func(error) bool
	}{
		{
			name:         "inventory existing",
			inv:          inv,
			registry:     newMockRegistry(entry),
			putInventory: func(tags *ssm.CustomInventory) error { return nil },
		},
		{
			name:       "inventory unknown",
			inv:        &ssm.CustomInventory{ManagedId: "unknown"},
			registry:   newMockRegistry(entry),
			checkError: isCausedBy(ErrRegistrationNotFound),
		},
		{
			name:       "registry error",
			inv:        inv,
			registry:   &errRegistry{getByManagedId: throttleError},
			checkError: isError(throttleError),
		},
		{
			name:         "ssm throttled",
			inv:          inv,
			registry:     newMockRegistry(entry),
			putInventory: func(tags *ssm.CustomInventory) error { return throttleError },
			wantDeferred: &DeferredActionMessage{PutInventory, inv},
			checkError:   isDeferredError,
		},
		{
			name:         "registry inventory error",
			inv:          inv,
			registry:     &errRegistry{entry: entry, setInventoried: fatalError},
			putInventory: func(tags *ssm.CustomInventory) error { return nil },
			checkError:   isError(fatalError),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var (
				deferred *DeferredActionMessage
				gotInv   *ssm.CustomInventory
			)
			putInventory := c.putInventory
			if putInventory != nil {
				putInventory = func(inv *ssm.CustomInventory) error {
					gotInv = inv
					return c.putInventory(inv)
				}
			}
			o := &OmniSSM{
				config:     &Config{QueueName: "defer"},
				registry:   c.registry,
				ssmAPI:     &mockSSMAPI{putInventory: putInventory},
				deferQueue: mockQueue(&deferred),
			}
			err := o.PutInstanceInventory(context.Background(), c.inv)
			if err == nil {
				mr := c.registry.(*mockRegistry)
				if e, err := mr.GetByManagedId(context.Background(), c.inv.ManagedId); err != nil {
					t.Errorf("entry for inventory not found in registry: %+v", err)
				} else if e.IsInventoried != 1 {
					t.Errorf("entry is not inventoried in registry: %+v", e)
				}

				if d := cmp.Diff(c.inv, gotInv, stdCmpOpts...); d != "" {
					t.Errorf("unexpected instance inventory: %v", d)
				}
			} else if c.checkError == nil || !c.checkError(err) {
				t.Fatalf("unexpected error: %v", err)
			}

			if d := cmp.Diff(c.wantDeferred, deferred, stdCmpOpts...); d != "" {
				t.Errorf("unexpected deferred message: %v", d)
			}
		})
	}
}

func TestOmniSSMTryDefer(t *testing.T) {
	msg := &DeferredActionMessage{
		Type:  RequestActivation,
		Value: "test",
	}
	cases := []struct {
		name         string
		queueFunc    func() error
		in           error
		checkError   func(error) bool
		wantDeferred *DeferredActionMessage
	}{
		{
			name: "nil error no queue",
		},
		{
			name:      "nil error with queue",
			queueFunc: func() error { return nil },
		},
		{
			name:       "fatal error",
			queueFunc:  func() error { return nil },
			in:         fatalError,
			checkError: isError(fatalError),
		},
		{
			name:         "throttle error",
			queueFunc:    func() error { return nil },
			in:           throttleError,
			checkError:   isDeferredError,
			wantDeferred: msg,
		},
		{
			name:         "queue error",
			queueFunc:    func() error { return fatalError },
			in:           throttleError,
			checkError:   isCausedBy(fatalError),
			wantDeferred: msg,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var deferred *DeferredActionMessage
			o := &OmniSSM{config: &Config{QueueName: "defer"}}
			if c.queueFunc != nil {
				o.deferQueue = mockQueueFunc(func(x json.Marshaler) error {
					deferred = x.(*DeferredActionMessage)
					return c.queueFunc()
				})
			}
			err := o.tryDefer(context.Background(), c.in, msg.Type, msg.Value)
			if c.checkError != nil {
				if !c.checkError(err) {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if d := cmp.Diff(c.wantDeferred, deferred, stdCmpOpts...); d != "" {
				t.Errorf("unexpected deferred message: %v", d)
			}
		})
	}
}

// Mocks definitions

var _ ssmAPI = (*mockSSMAPI)(nil)
var _ deferQueue = (mockQueueFunc)(nil)
var _ registry = (*mockRegistry)(nil)

type mockSSMAPI struct {
	newActivation             func(string, string) (*ssm.Activation, error)
	addTagsToResource         func(*ssm.ResourceTags) error
	putInventory              func(*ssm.CustomInventory) error
	deregisterManagedInstance func(string) error
}

func (s *mockSSMAPI) CreateActivation(ctx context.Context, n, r string) (*ssm.Activation, error) {
	return s.newActivation(n, r)
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

type mockQueueFunc func(json.Marshaler) error

func (q mockQueueFunc) Send(ctx context.Context, m json.Marshaler) error {
	return q(m)
}

func mockQueue(d **DeferredActionMessage) mockQueueFunc {
	return func(x json.Marshaler) error {
		*d = x.(*DeferredActionMessage)
		return nil
	}
}

type mockRegistry struct {
	mu      sync.RWMutex
	entries map[string]*RegistrationEntry
}

func newMockRegistry(ee ...*RegistrationEntry) *mockRegistry {
	m := make(map[string]*RegistrationEntry)
	for _, e := range ee {
		m[e.Id] = e
	}
	return &mockRegistry{entries: m}
}

func (r *mockRegistry) Get(ctx context.Context, id string) (*RegistrationEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[id]
	if !ok {
		return nil, ErrRegistrationNotFound
	}
	return e, nil
}

func (r *mockRegistry) GetByManagedId(ctx context.Context, mid string) (*RegistrationEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.entries {
		if e.ManagedId == mid {
			return e, nil
		}
	}
	return nil, ErrRegistrationNotFound
}

func (r *mockRegistry) Put(ctx context.Context, e *RegistrationEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[string]*RegistrationEntry)
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

func (r *mockRegistry) SetManagedId(ctx context.Context, id, mid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[id]
	if !ok {
		return ErrRegistrationNotFound
	}
	e.ManagedId = mid
	return nil
}

func (r *mockRegistry) SetTagged(ctx context.Context, id string, b bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[id]
	if !ok {
		return ErrRegistrationNotFound
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
		return ErrRegistrationNotFound
	}
	if b {
		e.IsInventoried = 1
	} else {
		e.IsInventoried = 0
	}
	return nil
}

// mock for returning errors from registry methods
type errRegistry struct {
	entry *RegistrationEntry

	get, getByManagedId, put, delete        error
	setManagedId, setTagged, setInventoried error
}

func (r *errRegistry) Get(ctx context.Context, id string) (*RegistrationEntry, error) {
	return r.entry, r.get
}

func (r *errRegistry) GetByManagedId(ctx context.Context, mid string) (*RegistrationEntry, error) {
	return r.entry, r.getByManagedId
}

func (r *errRegistry) Put(ctx context.Context, e *RegistrationEntry) error {
	return r.put
}

func (r *errRegistry) Delete(ctx context.Context, id string) error {
	return r.delete
}

func (r *errRegistry) SetManagedId(ctx context.Context, id, mid string) error {
	return r.setManagedId
}

func (r *errRegistry) SetTagged(ctx context.Context, id string, b bool) error {
	return r.setTagged
}

func (r *errRegistry) SetInventoried(ctx context.Context, id string, b bool) error {
	return r.setInventoried
}
