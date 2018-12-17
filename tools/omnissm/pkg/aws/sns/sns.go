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

package sns

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/awsutil"
	"github.com/golang/time/rate"
	"github.com/pkg/errors"
)

//type Config struct {
//*aws.Config

//AssumeRole    string
//EnableTracing bool
//}

type SNS struct {
	snsiface.SNSAPI

	config  *awsutil.Config
	snsRate *rate.Limiter
}

func New(config *awsutil.Config) *SNS {
	svc := sns.New(awsutil.Session(config))
	if config.EnableTracing {
		xray.AWS(svc.Client)
	}
	s := &SNS{
		SNSAPI:  svc,
		config:  config,
		snsRate: rate.NewLimiter(300, 300),
	}
	return s
}

func (s *SNS) Publish(ctx context.Context, topicArn string, msg []byte) error {
	_, err := s.SNSAPI.PublishWithContext(ctx, &sns.PublishInput{
		Message:  aws.String(string(msg)),
		TopicArn: aws.String(topicArn),
	})
	return errors.Wrap(err, "sns.Publish")

}
