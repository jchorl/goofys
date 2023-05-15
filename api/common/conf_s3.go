// Copyright 2019 Databricks
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

package common

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/sirupsen/logrus"
)

type S3Config struct {
	RequesterPays bool

	StorageClass string

	UseSSE     bool
	UseKMS     bool
	KMSKeyID   string
	SseC       string
	SseCDigest string
	ACL        string

	Subdomain bool

	BucketOwner string
}

func (c *S3Config) ToAwsConfig(ctx context.Context, flags *FlagStorage) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithHTTPClient(&http.Client{
			Transport: GetHTTPTransport(),
			Timeout:   flags.HTTPTimeout,
		}),
	}

	logger := GetLogger("s3")
	if flags.DebugS3 {
		lvl := logrus.DebugLevel
		logger.Lvl = &lvl
		opts = append(opts, config.WithClientLogMode(aws.LogSigning|aws.LogRetries|aws.LogRequest|aws.LogRequestWithBody|aws.LogResponse|aws.LogResponseWithBody|aws.LogDeprecatedUsage|aws.LogRequestEventMessage|aws.LogResponseEventMessage))

	}
	opts = append(opts, config.WithLogger(logger))

	if flags.Endpoint != "" {
		opts = append(opts, config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{URL: flags.Endpoint}, nil
			})),
		)
	}

	cfg, err := config.LoadDefaultConfig(
		ctx,
		opts...,
	)
	if err != nil {
		return aws.Config{}, err
	}

	if c.SseC != "" {
		key, err := base64.StdEncoding.DecodeString(c.SseC)
		if err != nil {
			return aws.Config{}, fmt.Errorf("sse-c is not base64-encoded: %v", err)
		}

		c.SseC = string(key)
		m := md5.Sum(key)
		c.SseCDigest = base64.StdEncoding.EncodeToString(m[:])
	}

	return cfg, nil
}
