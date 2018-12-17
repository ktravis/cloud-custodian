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
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/awsutil"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var (
	DefaultMaxRetries         = 0
	DefaultRegistrationsTable = "omnissm-registrations"
	DefaultSSMServiceRole     = "service-role/AmazonEC2RunCommandRoleForManagedInstances"
	DefaultResourceTags       = []string{
		"App",
		"OwnerContact",
		"Name",
	}
)

type Config struct {
	// A whitelist of accounts allowed to register with SSM
	AccountWhitelist []string `yaml:"accountWhitelist"`

	// The IAM role used when the SSM agent registers with the SSM service
	InstanceRole string `yaml:"instanceRole"`

	// Sets the number of retries attempted for AWS API calls. Defaults to 0
	// if not specified.
	MaxRetries int `yaml:"maxRetries"`

	// If provided, SSM API requests that are throttled will be sent to this
	// queue. Should be used in conjunction with MaxRetries since the
	// throttling that takes place should retry several times before attempting
	// to queue the request.
	QueueName string `yaml:"queueName"`

	// The DynamodDb table used for storing instance regisrations.
	RegistrationsTable string `yaml:"registrationsTable"`

	// The SNS topic published to when resources are registered (optional).
	ResourceRegisteredSNSTopic string `yaml:"resourceRegisteredSNSTopic"`

	// The SNS topic published to when resources are deleted (optional).
	ResourceDeletedSNSTopic string `yaml:"resourceDeletedSNSTopic"`

	// The name of tags that should be added to SSM tags if they are tagged on
	// the EC2 instance.
	ResourceTags []string `yaml:"resourceTags"`

	// The IAM role used for downloading Oversized ConfigurationItems from S3.
	S3DownloadRole string `yaml:"s3DownloadRole"`

	// The IAM role used for publishing to the Resource Deleted SNS topic (optional).
	SNSPublishRole string `yaml:"snsPublishRole"`

	// This is set by AWS when a Lambda instance is configured to use x-ray.
	// This is optional and x-ray is currently only supported when using lambda.
	XRayTracingEnabled bool `yaml:"xrayTracingEnabled"`

	// Version constraints for allowable client requests during registration. If
	// constraints are empty, all versions are allowed. Version string should
	// conform with github.com/hashicorp/go-version format, i.e. comma-separated
	// rules like ">= 1.1.0, < 2.0.0"
	ClientVersionConstraints string `yaml:"clientVersionConstraints"`

	// The role to assume in registering accounts
	ConfigServiceAssumeRoleName string `yaml:"assumeRole"`

	// The number of days to wait to clean up registered ssm instances that have a
	// PingStatus of ConnectionLost
	CleanupAfterDays float64 `yaml:"cleanupAfterDays"`

	// The name of a JSON file containing an ImageWhitelist structure. If the
	// value is not an empty string, the registration handler will attempt to
	// read the named file on lambda startup and construct a whitelist of valid
	// image IDs for each AccountId/RegionName pair. Instances presenting an
	// identity document with an image ID not present in the whitelist will not
	// be allowed to register.
	AMIWhitelistFile string `yaml:"amiWhitelistFile"`
}

func DefaultConfig() *Config {
	return &Config{
		MaxRetries:         DefaultMaxRetries,
		RegistrationsTable: DefaultRegistrationsTable,
		InstanceRole:       DefaultSSMServiceRole,
		ResourceTags:       DefaultResourceTags,
	}
}

// ReadConfig loads configuration values from a yaml file.
// The priority of the sources is the following:
// 1. environment variables
// 2. config file
// 3. defaults
func ReadConfig(path string) (*Config, error) {
	c := DefaultConfig()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "config file %#v not found", path)
	}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot read config file %#v", path)
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal config data")
	}
	return c.ReadEnv(), nil
}

func (c *Config) AWSConfig() *awsutil.Config {
	return &awsutil.Config{
		EnableTracing: config.XRayTracingEnabled,
		MaxRetries:    config.MaxRetries,
		Region:        config.Region,
	}
}

// splitNonEmpty returns a nil slice when s is blank
func splitNonEmpty(s string, sep string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, sep)
}

func (c *Config) ReadEnv() *Config {
	if aw := splitNonEmpty(os.Getenv("OMNISSM_ACCOUNT_WHITELIST"), ","); len(aw) > 0 {
		c.AccountWhitelist = aw
	}
	if s := os.Getenv("OMNISSM_MAX_RETRIES"); s != "" {
		maxRetries, err := strconv.Atoi(s)
		if err != nil {
			panic(fmt.Sprintf("invalid max retry count %#v", s))
		}
		c.MaxRetries = maxRetries
	}
	if s := os.Getenv("OMNISSM_INSTANCE_ROLE"); s != "" {
		c.InstanceRole = s
	}
	if s := os.Getenv("OMNISSM_REGISTRATIONS_TABLE"); s != "" {
		c.RegistrationsTable = s
	}
	if s := os.Getenv("OMNISSM_SPILLOVER_QUEUE"); s != "" {
		c.QueueName = s
	}
	if s := os.Getenv("OMNISSM_RESOURCE_REGISTERED_SNS_TOPIC"); s != "" {
		c.ResourceRegisteredSNSTopic = s
	}
	if s := os.Getenv("OMNISSM_RESOURCE_DELETED_SNS_TOPIC"); s != "" {
		c.ResourceDeletedSNSTopic = s
	}
	if rt := splitNonEmpty(os.Getenv("OMNISSM_RESOURCE_TAGS"), ","); len(rt) > 0 {
		c.ResourceTags = rt
	}
	if s := os.Getenv("OMNISSM_S3_DOWNLOAD_ROLE"); s != "" {
		c.S3DownloadRole = s
	}
	if s := os.Getenv("OMNISSM_SNS_PUBLISH_ROLE"); s != "" {
		c.SNSPublishRole = s
	}
	if s := os.Getenv("_X_AMZN_TRACE_ID"); s != "" {
		c.XRayTracingEnabled = true
	}
	return c
}

func (c *Config) HasResourceTag(tagName string) (ok bool) {
	// This list is expected to be very small, so it is probably acceptable to
	// do a linear search here in order for *Config to remain free of internal
	// state. If not, the caller should make a map to check.
	for _, t := range c.ResourceTags {
		if t == tagName {
			return true
		}
	}
	return false
}
