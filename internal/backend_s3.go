// Copyright 2019 Ka-Hing Cheung
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

package internal

import (
	"context"
	"reflect"

	. "github.com/kahing/goofys/api/common"

	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithymiddleware "github.com/aws/smithy-go/middleware"
)

type S3Backend struct {
	S3  *s3.Client
	cap Capabilities

	bucket    string
	awsConfig aws.Config
	flags     *FlagStorage
	config    *S3Config
	sseType   types.ServerSideEncryption

	aws bool
	gcs bool
}

func NewS3(ctx context.Context, bucket string, flags *FlagStorage, config *S3Config) (*S3Backend, error) {
	awsConfig, err := config.ToAwsConfig(ctx, flags)
	if err != nil {
		return nil, err
	}
	s := &S3Backend{
		bucket:    bucket,
		awsConfig: awsConfig,
		flags:     flags,
		config:    config,
		cap: Capabilities{
			Name:             "s3",
			MaxMultipartSize: 5 * 1024 * 1024 * 1024,
		},
	}

	if config.UseKMS {
		//SSE header string for KMS server-side encryption (SSE-KMS)
		s.sseType = types.ServerSideEncryptionAwsKms
	} else if config.UseSSE {
		//SSE header string for non-KMS server-side encryption (SSE-S3)
		s.sseType = types.ServerSideEncryptionAes256
	}

	s.newS3()
	return s, nil
}

func (s *S3Backend) Init(key string) error {
	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	region, err := manager.GetBucketRegion(ctx, s.S3, s.Bucket())
	if err != nil {
		s3Log.Warnf("initial call to get bucket region failed, something is likely wrong %s: %+v", reflect.TypeOf(err), err)
		return mapAwsError(err)
	}

	if s.awsConfig.Region != region {
		s.awsConfig.Region = region
		s.newS3()
	}

	return nil
}

func (s *S3Backend) Bucket() string {
	return s.bucket
}

func (s *S3Backend) Capabilities() *Capabilities {
	return &s.cap
}

func (s *S3Backend) newS3() {
	s.S3 = s3.NewFromConfig(
		s.awsConfig,
		func(o *s3.Options) {
			o.UsePathStyle = !s.config.Subdomain
		},
	)
}

func (s *S3Backend) ListObjectsV2(params *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, string, error) {
	if s.config.RequesterPays {
		params.RequestPayer = types.RequestPayerRequester
	}

	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	resp, err := s.S3.ListObjectsV2(ctx, params)
	if err != nil {
		return nil, "", err
	}

	return resp, s.getRequestId(resp.ResultMetadata), nil
}

func metadataToLower(m map[string]string) map[string]string {
	nm := map[string]string{}

	for k, v := range m {
		nm[strings.ToLower(k)] = v
	}

	return nm
}

func metadataToPtr(m map[string]string) map[string]*string {
	nm := map[string]*string{}

	for k, v := range m {
		v := v
		nm[strings.ToLower(k)] = &v
	}

	return nm
}

func metadataFromPtr(m map[string]*string) map[string]string {
	nm := map[string]string{}

	for k, v := range m {
		v := v
		nm[strings.ToLower(k)] = *v
	}

	return nm
}

func (s *S3Backend) getRequestId(resultMetadata smithymiddleware.Metadata) string {
	requestID, ok := middleware.GetRequestIDMetadata(resultMetadata)
	if !ok {
		return "goofys no request id"
	}

	return requestID
}

func (s *S3Backend) HeadBlob(param *HeadBlobInput) (*HeadBlobOutput, error) {
	head := s3.HeadObjectInput{Bucket: &s.bucket,
		Key: &param.Key,
	}
	if s.config.SseC != "" {
		head.SSECustomerAlgorithm = PString("AES256")
		head.SSECustomerKey = &s.config.SseC
		head.SSECustomerKeyMD5 = &s.config.SseCDigest
	}

	if s.config.RequesterPays {
		head.RequestPayer = types.RequestPayerRequester
	}

	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	resp, err := s.S3.HeadObject(ctx, &head)
	if err != nil {
		s3Log.Infof("JOSH: head bucket=%s key=%s err: %+v", s.bucket, param.Key, err)
		return nil, mapAwsError(err)
	}

	storageClassStr := string(resp.StorageClass)
	return &HeadBlobOutput{
		BlobItemOutput: BlobItemOutput{
			Key:          &param.Key,
			ETag:         resp.ETag,
			LastModified: resp.LastModified,
			Size:         uint64(resp.ContentLength),
			StorageClass: &storageClassStr,
		},
		ContentType: resp.ContentType,
		Metadata:    metadataToPtr(metadataToLower(resp.Metadata)),
		IsDirBlob:   strings.HasSuffix(param.Key, "/"),
		RequestId:   s.getRequestId(resp.ResultMetadata),
	}, nil
}

func (s *S3Backend) ListBlobs(param *ListBlobsInput) (*ListBlobsOutput, error) {
	var maxKeys int32 = 0
	if param.MaxKeys != nil {
		maxKeys = int32(*param.MaxKeys)
	}

	resp, reqId, err := s.ListObjectsV2(&s3.ListObjectsV2Input{
		Bucket:            &s.bucket,
		Prefix:            param.Prefix,
		Delimiter:         param.Delimiter,
		MaxKeys:           maxKeys,
		StartAfter:        param.StartAfter,
		ContinuationToken: param.ContinuationToken,
	})
	if err != nil {
		return nil, mapAwsError(err)
	}

	prefixes := make([]BlobPrefixOutput, 0)
	items := make([]BlobItemOutput, 0)

	for _, p := range resp.CommonPrefixes {
		prefixes = append(prefixes, BlobPrefixOutput{Prefix: p.Prefix})
	}
	for _, i := range resp.Contents {
		storageClassStr := string(i.StorageClass)
		items = append(items, BlobItemOutput{
			Key:          i.Key,
			ETag:         i.ETag,
			LastModified: i.LastModified,
			Size:         uint64(i.Size),
			StorageClass: &storageClassStr,
		})
	}

	return &ListBlobsOutput{
		Prefixes:              prefixes,
		Items:                 items,
		NextContinuationToken: resp.NextContinuationToken,
		IsTruncated:           resp.IsTruncated,
		RequestId:             reqId,
	}, nil
}

func (s *S3Backend) DeleteBlob(param *DeleteBlobInput) (*DeleteBlobOutput, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	resp, err := s.S3.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &s.bucket,
		Key:    &param.Key,
	})
	if err != nil {
		return nil, mapAwsError(err)
	}
	return &DeleteBlobOutput{s.getRequestId(resp.ResultMetadata)}, nil
}

func (s *S3Backend) DeleteBlobs(param *DeleteBlobsInput) (*DeleteBlobsOutput, error) {
	num_objs := len(param.Items)

	var items types.Delete
	items.Objects = make([]types.ObjectIdentifier, num_objs)

	for i := range param.Items {
		items.Objects[i] = types.ObjectIdentifier{Key: &param.Items[i]}
	}

	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	resp, err := s.S3.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: &s.bucket,
		Delete: &items,
	})
	if err != nil {
		return nil, mapAwsError(err)
	}

	return &DeleteBlobsOutput{s.getRequestId(resp.ResultMetadata)}, nil
}

func (s *S3Backend) RenameBlob(param *RenameBlobInput) (*RenameBlobOutput, error) {
	return nil, syscall.ENOTSUP
}

func (s *S3Backend) mpuCopyPart(from string, to string, mpuId string, bytes string, part int64,
	sem semaphore, srcEtag *string, etag **string, errout *error) {

	defer sem.P(1)

	// XXX use CopySourceIfUnmodifiedSince to ensure that
	// we are copying from the same object
	params := &s3.UploadPartCopyInput{
		Bucket:            &s.bucket,
		Key:               &to,
		CopySource:        aws.String(url.QueryEscape(from)),
		UploadId:          &mpuId,
		CopySourceRange:   &bytes,
		CopySourceIfMatch: srcEtag,
		PartNumber:        int32(part),
	}
	if s.config.SseC != "" {
		params.SSECustomerAlgorithm = PString("AES256")
		params.SSECustomerKey = &s.config.SseC
		params.SSECustomerKeyMD5 = &s.config.SseCDigest
		params.CopySourceSSECustomerAlgorithm = PString("AES256")
		params.CopySourceSSECustomerKey = &s.config.SseC
		params.CopySourceSSECustomerKeyMD5 = &s.config.SseCDigest
	}

	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	resp, err := s.S3.UploadPartCopy(ctx, params)
	if err != nil {
		s3Log.Errorf("UploadPartCopy %v = %v", params, err)
		*errout = mapAwsError(err)
		return
	}

	*etag = resp.CopyPartResult.ETag
	return
}

func sizeToParts(size int64) (int, int64) {
	const MAX_S3_MPU_SIZE int64 = 5 * 1024 * 1024 * 1024 * 1024
	if size > MAX_S3_MPU_SIZE {
		panic(fmt.Sprintf("object size: %v exceeds maximum S3 MPU size: %v", size, MAX_S3_MPU_SIZE))
	}

	// Use the maximum number of parts to allow the most server-side copy
	// parallelism.
	const MAX_PARTS = 10 * 1000
	const MIN_PART_SIZE = 50 * 1024 * 1024
	partSize := MaxInt64(size/(MAX_PARTS-1), MIN_PART_SIZE)

	nParts := int(size / partSize)
	if size%partSize != 0 {
		nParts++
	}

	return nParts, partSize
}

func (s *S3Backend) mpuCopyParts(size int64, from string, to string, mpuId string,
	srcEtag *string, etags []*string, partSize int64, err *error) {

	rangeFrom := int64(0)
	rangeTo := int64(0)

	MAX_CONCURRENCY := MinInt(100, len(etags))
	sem := make(semaphore, MAX_CONCURRENCY)
	sem.P(MAX_CONCURRENCY)

	for i := int64(1); rangeTo < size; i++ {
		rangeFrom = rangeTo
		rangeTo = i * partSize
		if rangeTo > size {
			rangeTo = size
		}
		bytes := fmt.Sprintf("bytes=%v-%v", rangeFrom, rangeTo-1)

		sem.V(1)
		go s.mpuCopyPart(from, to, mpuId, bytes, i, sem, srcEtag, &etags[i-1], err)
	}

	sem.V(MAX_CONCURRENCY)
}

func (s *S3Backend) copyObjectMultipart(size int64, from string, to string, mpuId string,
	srcEtag *string, metadata map[string]*string, storageClass string) (requestId string, err error) {
	nParts, partSize := sizeToParts(size)
	etags := make([]*string, nParts)

	if mpuId == "" {
		params := &s3.CreateMultipartUploadInput{
			Bucket:       &s.bucket,
			Key:          &to,
			StorageClass: types.StorageClass(storageClass),
			ContentType:  s.flags.GetMimeType(to),
			Metadata:     metadataToLower(metadataFromPtr(metadata)),
		}

		if s.config.UseSSE {
			params.ServerSideEncryption = s.sseType
			if s.config.UseKMS && s.config.KMSKeyID != "" {
				params.SSEKMSKeyId = &s.config.KMSKeyID
			}
		} else if s.config.SseC != "" {
			params.SSECustomerAlgorithm = PString("AES256")
			params.SSECustomerKey = &s.config.SseC
			params.SSECustomerKeyMD5 = &s.config.SseCDigest
		}

		if s.config.ACL != "" {
			params.ACL = types.ObjectCannedACL(s.config.ACL)
		}

		ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
		defer cancel()

		resp, err := s.S3.CreateMultipartUpload(ctx, params)
		if err != nil {
			return "", mapAwsError(err)
		}

		mpuId = *resp.UploadId
	}

	s.mpuCopyParts(size, from, to, mpuId, srcEtag, etags, partSize, &err)

	if err != nil {
		return
	} else {
		parts := make([]types.CompletedPart, nParts)
		for i := 0; i < nParts; i++ {
			parts[i] = types.CompletedPart{
				ETag:       etags[i],
				PartNumber: int32(i + 1),
			}
		}

		params := &s3.CompleteMultipartUploadInput{
			Bucket:   &s.bucket,
			Key:      &to,
			UploadId: &mpuId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: parts,
			},
		}

		ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
		defer cancel()

		resp, err := s.S3.CompleteMultipartUpload(ctx, params)
		if err != nil {
			err = mapAwsError(err)
		} else {
			requestId = s.getRequestId(resp.ResultMetadata)
		}
	}

	return
}

func (s *S3Backend) CopyBlob(param *CopyBlobInput) (*CopyBlobOutput, error) {
	metadataDirective := types.MetadataDirectiveCopy
	if param.Metadata != nil {
		metadataDirective = types.MetadataDirectiveReplace
	}

	COPY_LIMIT := uint64(5 * 1024 * 1024 * 1024)

	if param.Size == nil || param.ETag == nil || (*param.Size > COPY_LIMIT &&
		(param.Metadata == nil || param.StorageClass == nil)) {

		params := &HeadBlobInput{Key: param.Source}
		resp, err := s.HeadBlob(params)
		if err != nil {
			return nil, err
		}

		param.Size = &resp.Size
		param.ETag = resp.ETag
		if param.Metadata == nil {
			param.Metadata = resp.Metadata
		}
		param.StorageClass = resp.StorageClass
	}

	if param.StorageClass == nil {
		if *param.Size < 128*1024 && s.config.StorageClass == "STANDARD_IA" {
			param.StorageClass = PString("STANDARD")
		} else {
			param.StorageClass = &s.config.StorageClass
		}
	}

	from := s.bucket + "/" + param.Source

	if !s.gcs && *param.Size > COPY_LIMIT {
		reqId, err := s.copyObjectMultipart(int64(*param.Size), from, param.Destination, "", param.ETag, param.Metadata, *param.StorageClass)
		if err != nil {
			return nil, err
		}
		return &CopyBlobOutput{reqId}, nil
	}

	params := &s3.CopyObjectInput{
		Bucket:            &s.bucket,
		CopySource:        aws.String(url.QueryEscape(from)),
		Key:               &param.Destination,
		StorageClass:      types.StorageClass(*param.StorageClass),
		ContentType:       s.flags.GetMimeType(param.Destination),
		Metadata:          metadataToLower(metadataFromPtr(param.Metadata)),
		MetadataDirective: metadataDirective,
	}

	s3Log.Debug(params)

	if s.config.UseSSE {
		params.ServerSideEncryption = s.sseType
		if s.config.UseKMS && s.config.KMSKeyID != "" {
			params.SSEKMSKeyId = &s.config.KMSKeyID
		}
	} else if s.config.SseC != "" {
		params.SSECustomerAlgorithm = PString("AES256")
		params.SSECustomerKey = &s.config.SseC
		params.SSECustomerKeyMD5 = &s.config.SseCDigest
		params.CopySourceSSECustomerAlgorithm = PString("AES256")
		params.CopySourceSSECustomerKey = &s.config.SseC
		params.CopySourceSSECustomerKeyMD5 = &s.config.SseCDigest
	}

	if s.config.ACL != "" {
		params.ACL = types.ObjectCannedACL(s.config.ACL)
	}

	ctx, cancel := context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()
	resp, err := s.S3.CopyObject(ctx, params)
	if err != nil {
		return nil, mapAwsError(err)
	}

	return &CopyBlobOutput{s.getRequestId(resp.ResultMetadata)}, nil
}

func (s *S3Backend) GetBlob(param *GetBlobInput) (*GetBlobOutput, error) {
	get := s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &param.Key,
	}

	if s.config.SseC != "" {
		get.SSECustomerAlgorithm = PString("AES256")
		get.SSECustomerKey = &s.config.SseC
		get.SSECustomerKeyMD5 = &s.config.SseCDigest
	}

	if param.Start != 0 || param.Count != 0 {
		var bytes string
		if param.Count != 0 {
			bytes = fmt.Sprintf("bytes=%v-%v", param.Start, param.Start+param.Count-1)
		} else {
			bytes = fmt.Sprintf("bytes=%v-", param.Start)
		}
		get.Range = &bytes
	}
	// TODO handle IfMatch

	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	resp, err := s.S3.GetObject(ctx, &get)
	if err != nil {
		return nil, mapAwsError(err)
	}

	storageClassStr := string(resp.StorageClass)
	return &GetBlobOutput{
		HeadBlobOutput: HeadBlobOutput{
			BlobItemOutput: BlobItemOutput{
				Key:          &param.Key,
				ETag:         resp.ETag,
				LastModified: resp.LastModified,
				Size:         uint64(resp.ContentLength),
				StorageClass: &storageClassStr,
			},
			ContentType: resp.ContentType,
			Metadata:    metadataToPtr(metadataToLower(resp.Metadata)),
		},
		Body:      resp.Body,
		RequestId: s.getRequestId(resp.ResultMetadata),
	}, nil
}

func (s *S3Backend) PutBlob(param *PutBlobInput) (*PutBlobOutput, error) {
	storageClass := s.config.StorageClass
	if param.Size != nil && *param.Size < 128*1024 && storageClass == "STANDARD_IA" {
		storageClass = "STANDARD"
	}

	put := &s3.PutObjectInput{
		Bucket:       &s.bucket,
		Key:          &param.Key,
		Metadata:     metadataToLower(metadataFromPtr(param.Metadata)),
		Body:         param.Body,
		StorageClass: types.StorageClass(storageClass),
		ContentType:  param.ContentType,
	}

	if s.config.UseSSE {
		put.ServerSideEncryption = s.sseType
		if s.config.UseKMS && s.config.KMSKeyID != "" {
			put.SSEKMSKeyId = &s.config.KMSKeyID
		}
	} else if s.config.SseC != "" {
		put.SSECustomerAlgorithm = PString("AES256")
		put.SSECustomerKey = &s.config.SseC
		put.SSECustomerKeyMD5 = &s.config.SseCDigest
	}

	if s.config.ACL != "" {
		put.ACL = types.ObjectCannedACL(s.config.ACL)
	}

	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	resp, err := s.S3.PutObject(ctx, put)
	if err != nil {
		return nil, mapAwsError(err)
	}

	now := time.Now() // put-blob doesn't return a LastModified, so just take current timestamp
	return &PutBlobOutput{
		ETag:         resp.ETag,
		LastModified: &now,
		StorageClass: &storageClass,
		RequestId:    s.getRequestId(resp.ResultMetadata),
	}, nil
}

func (s *S3Backend) MultipartBlobBegin(param *MultipartBlobBeginInput) (*MultipartBlobCommitInput, error) {
	mpu := s3.CreateMultipartUploadInput{
		Bucket:       &s.bucket,
		Key:          &param.Key,
		StorageClass: types.StorageClass(s.config.StorageClass),
		ContentType:  param.ContentType,
	}

	if s.config.UseSSE {
		mpu.ServerSideEncryption = s.sseType
		if s.config.UseKMS && s.config.KMSKeyID != "" {
			mpu.SSEKMSKeyId = &s.config.KMSKeyID
		}
	} else if s.config.SseC != "" {
		mpu.SSECustomerAlgorithm = PString("AES256")
		mpu.SSECustomerKey = &s.config.SseC
		mpu.SSECustomerKeyMD5 = &s.config.SseCDigest
	}

	if s.config.ACL != "" {
		mpu.ACL = types.ObjectCannedACL(s.config.ACL)
	}

	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	resp, err := s.S3.CreateMultipartUpload(ctx, &mpu)
	if err != nil {
		return nil, mapAwsError(err)
	}

	return &MultipartBlobCommitInput{
		Key:      &param.Key,
		Metadata: metadataToPtr(metadataToLower(metadataFromPtr(param.Metadata))),
		UploadId: resp.UploadId,
		Parts:    make([]*string, 10000), // at most 10K parts
	}, nil
}

func (s *S3Backend) MultipartBlobAdd(param *MultipartBlobAddInput) (*MultipartBlobAddOutput, error) {
	en := &param.Commit.Parts[param.PartNumber-1]
	atomic.AddUint32(&param.Commit.NumParts, 1)

	params := s3.UploadPartInput{
		Bucket:     &s.bucket,
		Key:        param.Commit.Key,
		PartNumber: int32(param.PartNumber),
		UploadId:   param.Commit.UploadId,
		Body:       param.Body,
	}
	if s.config.SseC != "" {
		params.SSECustomerAlgorithm = PString("AES256")
		params.SSECustomerKey = &s.config.SseC
		params.SSECustomerKeyMD5 = &s.config.SseCDigest
	}
	s3Log.Debug(params)

	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	resp, err := s.S3.UploadPart(ctx, &params)
	if err != nil {
		return nil, mapAwsError(err)
	}

	if *en != nil {
		s3Log.Fatalf("etags for part %v already set: %v", param.PartNumber, **en)
	}
	*en = resp.ETag

	return &MultipartBlobAddOutput{s.getRequestId(resp.ResultMetadata)}, nil
}

func (s *S3Backend) MultipartBlobCommit(param *MultipartBlobCommitInput) (*MultipartBlobCommitOutput, error) {
	parts := make([]types.CompletedPart, param.NumParts)
	for i := uint32(0); i < param.NumParts; i++ {
		parts[i] = types.CompletedPart{
			ETag:       param.Parts[i],
			PartNumber: int32(i + 1),
		}
	}

	mpu := s3.CompleteMultipartUploadInput{
		Bucket:   &s.bucket,
		Key:      param.Key,
		UploadId: param.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: parts,
		},
	}

	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	resp, err := s.S3.CompleteMultipartUpload(ctx, &mpu)
	if err != nil {
		return nil, mapAwsError(err)
	}

	now := time.Now() // CompleteMultipartUpload doesn't give a LastModified, so just take current timestamp
	return &MultipartBlobCommitOutput{
		ETag:         resp.ETag,
		LastModified: &now,
		RequestId:    s.getRequestId(resp.ResultMetadata),
	}, nil
}

func (s *S3Backend) MultipartBlobAbort(param *MultipartBlobCommitInput) (*MultipartBlobAbortOutput, error) {
	mpu := s3.AbortMultipartUploadInput{
		Bucket:   &s.bucket,
		Key:      param.Key,
		UploadId: param.UploadId,
	}

	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	resp, err := s.S3.AbortMultipartUpload(ctx, &mpu)
	if err != nil {
		return nil, mapAwsError(err)
	}
	return &MultipartBlobAbortOutput{s.getRequestId(resp.ResultMetadata)}, nil
}

func (s *S3Backend) MultipartExpire(param *MultipartExpireInput) (*MultipartExpireOutput, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	mpu, err := s.S3.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket: &s.bucket,
	})
	if err != nil {
		return nil, mapAwsError(err)
	}

	now := time.Now()
	for _, upload := range mpu.Uploads {
		expireTime := upload.Initiated.Add(48 * time.Hour)

		if !expireTime.After(now) {
			params := &s3.AbortMultipartUploadInput{
				Bucket:   &s.bucket,
				Key:      upload.Key,
				UploadId: upload.UploadId,
			}

			ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
			defer cancel()

			_, err := s.S3.AbortMultipartUpload(ctx, params)
			if mapAwsError(err) == syscall.EACCES {
				break
			} else if err != nil {
				s3Log.Warnf("error aborting multipart upload: %+v: %+v", params, err)
			}
		} else {
			s3Log.Debugf("Keeping MPU Key=%v Id=%v", *upload.Key, *upload.UploadId)
		}
	}

	return &MultipartExpireOutput{}, nil
}

func (s *S3Backend) RemoveBucket(param *RemoveBucketInput) (*RemoveBucketOutput, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	_, err := s.S3.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &s.bucket})
	if err != nil {
		return nil, mapAwsError(err)
	}
	return &RemoveBucketOutput{}, nil
}

func (s *S3Backend) MakeBucket(param *MakeBucketInput) (*MakeBucketOutput, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
	defer cancel()

	_, err := s.S3.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: &s.bucket,
		ACL:    types.BucketCannedACL(s.config.ACL),
	})
	if err != nil {
		return nil, mapAwsError(err)
	}

	if s.config.BucketOwner != "" {
		ownerStr := "Owner"
		owner := types.Tag{
			Key:   &ownerStr,
			Value: &s.config.BucketOwner,
		}

		param := s3.PutBucketTaggingInput{
			Bucket: &s.bucket,
			Tagging: &types.Tagging{
				TagSet: []types.Tag{owner},
			},
		}

		for i := 0; i < 10; i++ {
			ctx, cancel := context.WithTimeout(context.TODO(), s.flags.HTTPTimeout)
			defer cancel()

			_, err = s.S3.PutBucketTagging(ctx, &param)
			err = mapAwsError(err)
			switch err {
			case nil:
				break
			case syscall.ENXIO, syscall.EINTR:
				s3Log.Infof("waiting for bucket")
				time.Sleep((time.Duration(i) + 1) * 2 * time.Second)
			default:
				s3Log.Errorf("Failed to tag bucket %v: %v", s.bucket, err)
				return nil, err
			}
		}
	}

	return &MakeBucketOutput{}, err
}

func (s *S3Backend) Delegate() interface{} {
	return s
}
