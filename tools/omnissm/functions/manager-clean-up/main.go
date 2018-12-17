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

package main

import (
	"context"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/omnissm"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

func main() {
	config, err := omnissm.ReadConfig("config.yaml")
	if err != nil {
		panic(err)
	}
	omni, err := omnissm.New(config)
	if err != nil {
		panic(err)
	}
	svc := ssm.New(config.AWSConfig().Config)
	cutoff := 24 * time.Hour * omni.Config.CleanupAfterDays

	lambda.Start(func(ctx context.Context) (err error) {
		return svc.DescribeOfflineInstances(ctx, func(page []*ssm.ManagedInstance, lastPage bool) bool {
			for _, instance := range page {
				if time.Since(instance.LastPingDate) > cutoff {
					entry, err := omni.GetByManagedId(ctx, instance.ManagedId)
					if err != nil {
						switch errors.Cause(err) {
						case omnissm.ErrRegistrationNotFound:
							//entry not found, just clean up ssm registry
							if err := svc.DeregisterManagedInstance(ctx, instance.ManagedId); err != nil {
								// if we fail here, log and try again with next run
								log.Error().Err(err)
							} else {
								log.Info().Msgf("Successfully removed managed instance: %#v", instance.ManagedId)
							}
						default:
							log.Error().Err(err)
						}
						continue
					}
					//entry found do full cleanup
					if err := omni.DeregisterInstance(ctx, entry); err != nil {
						log.Error().Err(err)
					} else {
						log.Info().Msgf("Successfully deregistered instance: %#v", entry.ManagedId)
					}
				}
			}
			return !lastPage
		})
	})
}
