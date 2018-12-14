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
	"crypto/rsa"
	"testing"

	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/omnissm"
	"github.com/pkg/errors"
)

func TestVerifySecureIdentity(t *testing.T) {
	cases := []struct {
		name string
		id   *omnissm.SecureIdentity
		err  error
	}{
		{
			name: "invalid signature",
			id: &omnissm.SecureIdentity{
				Provider:         "aws",
				VerificationType: omnissm.DocumentSignatureVerification,
			},
			err: rsa.ErrVerification,
		},
		{
			name: "invalid provider",
			id: &omnissm.SecureIdentity{
				Provider:         "invalid",
				VerificationType: omnissm.DocumentSignatureVerification,
			},
			err: omnissm.ErrInvalidProvider,
		},
		{
			name: "invalid verification type",
			id: &omnissm.SecureIdentity{
				Provider:         "aws",
				VerificationType: omnissm.VerificationType(-1),
			},
			err: omnissm.ErrInvalidVerificationType,
		},
	}

	var vt omnissm.VerificationType
	if vt != omnissm.DocumentSignatureVerification {
		t.Fatalf("zero value of %T was not omnissm.DocumentSignatureVerification", vt)
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			if err := c.id.Verify(); c.err != errors.Cause(err) {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
