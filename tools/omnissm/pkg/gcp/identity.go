/*
Copyright 2018 Capital One Services, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

You may obtain a copy of the License at
	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package gcp

import (
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
)

const CertAddress = "https://www.googleapis.com/oauth2/v1/certs"

var PublicKeys = make(map[string]*rsa.PublicKey)

type InstanceIdentity struct {
	ProjectID                 string `json:"project_id"`
	ProjectNumber             uint   `json:"project_number"`
	Zone                      string `json:"zone"`
	InstanceID                string `json:"instance_id"`
	InstanceName              string `json:"instance_name"`
	InstanceCreationTimestamp uint   `json:"instance_creation_timestamp"`
}

type Verifier struct {
	keys   map[string]*rsa.PublicKey
	parser *jwt.Parser
}

func NewVerifier() (*Verifier, error) {
	// Acquire GCP public certificates, which rotate daily
	resp, err := http.Get(CertAddress)
	if err != nil {
		return nil, errors.Wrap(err, "unable to contact GCP cert endpoint")
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "bad response from GCP cert endpoint")
	}
	if resp.StatusCode != 200 {
		return nil, errors.Errorf("unexpected response from GCP cert endpoint: %s", string(b))
	}

	var keys map[string]string

	if err := json.Unmarshal(b, &keys); err != nil {
		return nil, errors.Wrap(err, "bad response from cert endpoint")
	}

	ver := &Verifier{
		keys: make(map[string]*rsa.PublicKey),
		parser: &jwt.Parser{
			ValidMethods:  []string{"RS256"},
			UseJSONNumber: true,
		},
	}

	// Populate RSA public key map
	for k, v := range keys {
		pub, err := jwt.ParseRSAPublicKeyFromPEM([]byte(v))
		if err != nil {
			return nil, err
		}
		ver.keys[k] = pub
	}
	return ver, nil
}

func (v *Verifier) Verify(signature string) (*InstanceIdentity, error) {
	var claims struct {
		jwt.StandardClaims
		Identity InstanceIdentity `json:"google"`
	}
	// signature is the signed JWT returned by the GCP instance
	// metadata service, which contains the identity document
	_, err := p.ParseWithClaims(signature, &claims, func(t *jwt.Token) (interface{}, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, errors.Errorf("unexpected kid in token header: %v", t.Header["kid"])
		}

		key, ok := v.keys[kid]
		if !ok {
			return nil, errors.Errorf("invalid key id: %s", kid)
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	return &claims.Identity, nil
}
