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
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/omnissm"
	"github.com/pkg/errors"
)

type RegistrationRequest struct {
	ManagedId     string `json:"managedId,omitempty"`
	ClientVersion string `json:"clientVersion,omitempty"`

	SecureIdentity
}

type ImageWhitelist struct {
	Images []struct {
		AccountId   string `json:"AccountId"`
		RegionName  string `json:"RegionName"`
		ImageId     string `json:"ImageId"`
		ReleaseDate string `json:"ReleaseDate"`
	} `json:"Images"`
}

type RequestAuthorizer struct {
	authorizedAccountIds map[string]struct{}
	authorizedImageIds   map[string]struct{}
	versionConstraint    version.Constraints
}

func NewRequestAuthorizer(config *Config) (*RequestAuthorizer, error) {
	ra := &RequestAuthorizer{
		authorizedAccountIds: make(map[string]struct{}),
	}
	if len(config.AccountWhitelist) == 0 {
		return nil, errors.New("unable to create request validator: no account whitelist provided")
	}
	for _, a := range config.AccountWhitelist {
		ra.authorizedAccountIds[a] = struct{}{}
	}

	if config.ClientVersionConstraints != "" {
		cs, err := version.NewConstraint(config.ClientVersionConstraints)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to create request validator: failed to parse version constraint %#v", config.ClientVersionConstraints)
		}
		ra.versionConstraint = cs
	}
	if config.AMIWhitelistFile != "" {
		b, err := ioutil.ReadFile(config.AMIWhitelistFile)
		if err != nil {
			return errors.Wrapf(err, "unable to read AMI whitelist %#v", config.AMIWhitelistFile)
		}
		var tmp omnissm.ImageWhitelist
		if err := json.Unmarshal(b, &tmp); err != nil {
			return errors.Wrap(err, "unable to unmarshal AMI whitelist file: %v")
		}
		ra.authorizedImageIds = make(map[string]struct{})
		for _, i := range tmp.Images {
			ra.authorizedImageIds[strings.Join([]string{i.AccountId, i.RegionName, i.ImageId}, ",")] = struct{}{}
		}
	}
	return ra, nil
}

func (ra *RequestAuthorizer) CheckRequest(r *RegistrationRequest) error {
	if !ra.IsAccountAuthorized(r.AccountId) {
		return ErrAccountNotAuthorized
	}
	if !ra.IsVersionAuthorized(r.ClientVersion) {
		return ErrClientVersionNotAuthorized
	}
	if !ra.IsImageAuthorized(r.AccountId, r.Region, r.ImageId) {
		return ErrImageNotAuthorized
	}
	return nil
}

func (ra *RequestAuthorizer) IsAccountAuthorized(accountId string) (ok bool) {
	_, ok = c.authorizedAccountIds[accountId]
	return
}

// IsImageAuthorized returns true if there is an image whitelist and the imageId
// is present in it, or if there is no image whitelist.
func (ra *RequestAuthorizer) IsImageAuthorized(accountId, region, imageId string) (ok bool) {
	if ra.authorizedImageIds == nil {
		return true
	} else if imageId == "" {
		return false
	}
	k := strings.Join([]string{accountId, region, imageId}, ",")
	_, ok = c.authorizedAccountIds[k]
	return ok
}

// IsVersionAuthorized returns true if vs passes the version constraint, or none was set
func (ra *RequestAuthorizer) IsVersionAuthorized(vs string) bool {
	if c.versionConstraint == nil {
		return true
	} else if vs == "" {
		return false
	}
	v, err := version.NewVersion(vs)
	if err != nil {
		return false
	}
	return c.versionConstraint.Check(v)
}
