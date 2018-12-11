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
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/ec2metadata"
	"github.com/pkg/errors"
)

var (
	ErrInvalidProvider         = errors.New("invalid provider type")
	ErrInvalidVerificationType = errors.New("invalid verification type")
)

type InstanceIdentity struct {
	// TODO: make these more generic
	AvailabilityZone string `json:"availabilityZone"`
	Region           string `json:"region"`
	InstanceId       string `json:"instanceId"`
	AccountId        string `json:"accountId"`
	InstanceType     string `json:"instanceType"`
}

// Name returns the logical name for the instance described in the identity
// document and is the value used when deriving the unique identifier hash.
func (i *InstanceIdentity) Name() string {
	return fmt.Sprintf("%s-%s", i.AccountId, i.InstanceId)
}

func (i *InstanceIdentity) Hash() string {
	return strings.ToUpper(fmt.Sprintf("%x", sha1.Sum([]byte(i.Name()))))
}

type VerificationType int

const (
	DocumentSignatureVerification VerificationType = iota
	JWTDocumentVerification
	// ...
)

type SecureIdentity struct {
	*InstanceIdentity

	Provider         string           `json:"provider"`
	VerificationType VerificationType `json:"verificationType"`
	Document         string           `json:"document"`
	Signature        string           `json:"signature"`

	verified bool
}

func (i *SecureIdentity) Verified() bool {
	return i.verified
}

func verifySignedDocument(signer *x509.Certificate, algo x509.SignatureAlgorithm, document, signature string) (*InstanceIdentity, error) {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, errors.Wrap(err, "malformed RSA signature")
	}
	if err := signer.CheckSignature(algo, []byte(document), sig); err != nil {
		return nil, errors.Wrap(err, "invalid signature")
	}
	var id InstanceIdentity
	if err := json.Unmarshal([]byte(document), &id); err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal identity document")
	}
	return &id, nil
}

func (i *SecureIdentity) Verify() error {
	var (
		signer *x509.Certificate
		algo   x509.SignatureAlgorithm
	)

	switch i.Provider {
	// TODO: gcp, azure
	case "aws":
		signer = ec2metadata.AWSIdentityCert
		algo = ec2metadata.AWSIdentitySignatureAlgorithm
	default:
		return errors.Wrapf(ErrInvalidProvider, "verification for provider %#v failed", i.Provider)
	}
	switch i.VerificationType {
	// TODO:
	//case JWTDocumentVerification:
	case DocumentSignatureVerification:
		id, err := verifySignedDocument(signer, algo, i.Document, i.Signature)
		if err != nil {
			return errors.Wrap(err, "document signature verification failed")
		}
		i.InstanceIdentity = id
	default:
		return errors.Wrapf(ErrInvalidVerificationType, "verification for verficiation type %#v failed", i.VerificationType)
	}
	i.verified = true
	return nil
}
