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

package sqs

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/awsutil"
	"github.com/pkg/errors"
)

type Config struct {
	AWSConfig *awsutil.Config
	QueueName string
	QueueURL  string
}

type Queue struct {
	svc    *SQS
	config *Config
}

func NewQueue(config *Config) (*Queue, error) {
	q := &Queue{
		svc:    New(config.AWSConfig),
		config: config,
	}

	if config.QueueURL == "" {
		url, err := q.svc.GetQueueURL(context.Background(), q.config.QueueName)
		if err != nil {
			// TODO: wrap error with context
			return nil, err
		}
		q.config.QueueURL = url
	}
	return q, nil
}

func (q *Queue) Send(ctx context.Context, m json.Marshaler) error {
	return q.svc.Send(ctx, q.config.QueueURL, m)
}

func (q *Queue) Receive(ctx context.Context) ([]*Message, error) {
	return q.svc.Receive(ctx, q.config.QueueURL)
}

func (q *Queue) Delete(ctx context.Context, receiptHandle string) error {
	return q.svc.Delete(ctx, q.config.QueueURL, receiptHandle)
}

type SQS struct {
	sqsiface.SQSAPI

	config *awsutil.Config
}

func New(config *awsutil.Config) *SQS {
	svc := sqs.New(awsutil.Session(config))
	if config != nil && config.EnableTracing {
		xray.AWS(svc.Client)
	}
	return &SQS{
		SQSAPI: svc,
		config: config,
	}
}

func (s *SQS) GetQueueURL(ctx context.Context, name string) (string, error) {
	resp, err := s.SQSAPI.GetQueueUrlWithContext(ctx, &sqs.GetQueueUrlInput{
		QueueName: aws.String(name),
	})
	if err != nil {
		return "", err
	}
	return *resp.QueueUrl, nil
}

func (s *SQS) Send(ctx context.Context, url string, m json.Marshaler) error {
	data, err := json.Marshal(m)
	if err != nil {
		return errors.Wrap(err, "cannot marshal SQS message")
	}
	_, err = s.SQSAPI.SendMessageWithContext(ctx, &sqs.SendMessageInput{
		MessageBody: aws.String(string(data)),
		QueueUrl:    aws.String(url),
	})
	return err
}

type Message struct {
	MessageId                        string
	MessageGroupId                   string
	MessageDeduplicationId           string
	SentTimestamp                    time.Time
	SenderId                         string
	SequenceNumber                   string
	Body                             string
	ReceiptHandle                    string
	ApproximateReceiveCount          int
	ApproximateFirstReceiveTimestamp time.Time
}

func parseUnixTime(s string) time.Time {
	ms, _ := strconv.ParseInt(s, 10, 64)
	return time.Unix(0, ms*int64(time.Millisecond))
}

func (s *SQS) Receive(ctx context.Context, url string) ([]*Message, error) {
	resp, err := s.SQSAPI.ReceiveMessageWithContext(ctx, &sqs.ReceiveMessageInput{
		AttributeNames:      aws.StringSlice([]string{"All"}),
		QueueUrl:            aws.String(url),
		WaitTimeSeconds:     aws.Int64(20),
		MaxNumberOfMessages: aws.Int64(10),
	})
	if err != nil {
		return nil, errors.Wrap(err, "cannot receive SQS message")
	}
	messages := make([]*Message, 0)
	for _, m := range resp.Messages {
		attrs := aws.StringValueMap(m.Attributes)
		msg := &Message{
			MessageId:                        *m.MessageId,
			MessageGroupId:                   attrs["MessageGroupId"],
			MessageDeduplicationId:           attrs["MessageDeduplicationId"],
			SentTimestamp:                    parseUnixTime(attrs["SentTimestamp"]),
			SenderId:                         attrs["SenderId"],
			SequenceNumber:                   attrs["SequenceNumber"],
			Body:                             *m.Body,
			ReceiptHandle:                    *m.ReceiptHandle,
			ApproximateFirstReceiveTimestamp: parseUnixTime(attrs["ApproximateFirstReceiveTimestamp"]),
		}
		msg.ApproximateReceiveCount, _ = strconv.Atoi(attrs["ApproximateReceiveCount"])
		messages = append(messages, msg)
	}
	return messages, nil
}

func (s *SQS) Delete(ctx context.Context, url, receiptHandle string) error {
	_, err := s.SQSAPI.DeleteMessageWithContext(ctx, &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(url),
		ReceiptHandle: aws.String(receiptHandle),
	})
	return errors.Wrap(err, "cannot delete SQS message")
}
