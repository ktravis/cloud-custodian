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

package awsutil

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
)

var (
	DefaultMaxRetries = 10
)

type Config struct {
	*aws.Config

	Region        string
	MaxRetries    int
	AssumeRole    string
	EnableTracing bool
}

func (c *Config) WithAssumeRole(r string) *Config {
	c.AssumeRole = r
	return c
}

func Session(c *Config) *session.Session {
	if c == nil {
		return session.New(aws.NewConfig().WithMaxRetries(DefaultMaxRetries))
	}

	awsconf := c.Config
	if awsconf == nil {
		awsconf = aws.NewConfig()
	}
	if c.Region != "" {
		awsconf.WithRegion(c.Region)
	}
	if c.MaxRetries != 0 {
		awsconf.WithMaxRetries(c.MaxRetries)
	} else {
		awsconf.WithMaxRetries(DefaultMaxRetries)
	}
	if c.AssumeRole != "" {
		s := session.New(awsconf)
		awsconf.WithCredentials(stscreds.NewCredentials(s, c.AssumeRole))
	}
	return session.New(awsconf)
}
