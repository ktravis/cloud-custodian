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

package omnissmapi_test

import (
	"context"
	"encoding/json"
)

type mockQueue struct {
	sent []json.Marshaler
	err  error
}

func (q *mockQueue) Send(ctx context.Context, m json.Marshaler) error {
	if q.err != nil {
		return q.err
	}
	q.sent = append(q.sent, m)
	return nil
}

func (q *mockQueue) Pop() json.Marshaler {
	n := len(q.sent)
	if n == 0 {
		return nil
	}
	m := q.sent[n-1]
	q.sent = q.sent[:n-1]
	return m
}
