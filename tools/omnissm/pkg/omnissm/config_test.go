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
	"testing"

	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/omnissm"
)

func TestRequestVersionValid(t *testing.T) {
	testCases := []struct {
		clientVersion string
		constraint    string
		expected      bool
	}{
		// positive
		{"", "", true},
		{"12345abcde", "", true},
		{"1.0.0", "", true},
		{"1.0.0", "1.0.0", true},
		{"1.0.0", ">= 1.0.0", true},
		{"1.0.1", ">= 1.0.0", true},
		{"1.1.0", ">= 1.0.0", true},
		{"2.0.0", ">= 1.0.0", true},

		// negative
		{"", "1.0.0", false},
		{"12345abcde", "1.0.0", false},
		{"12345abcde", ">= 1.0.0", false},
		{"1.0.1", ">= 1.1.0", false},
	}

	for i, tc := range testCases {
		c := &omnissm.Config{
			ClientVersionConstraints: tc.constraint,
		}
		omnissm.MergeConfig(c, &omnissm.Config{})
		if got := c.RequestVersionValid(tc.clientVersion); got != tc.expected {
			t.Errorf("TestCase %d: version %#v constraint %#v (got %t, want %t)", i, tc.clientVersion, tc.constraint, got, tc.expected)
		}
	}
}
