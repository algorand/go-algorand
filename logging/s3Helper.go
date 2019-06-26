// Copyright (C) 2019 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package logging

import (
	"io"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type s3Helper struct {
	session *session.Session
	bucket  string
}

const s3DefaultUploadBucket = "algorand-uploads"
const s3DefaultRegion = "us-east-1"

func makeS3SessionForUpload() (s3Helper, error) {
	awsID := os.Getenv("AWS_ACCESS_KEY_ID")
	awsKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	creds := credentials.NewStaticCredentials(awsID, awsKey, "")
	return makeS3Session(creds)
}

func getS3Bucket() (bucketName string) {
	bucketName, found := os.LookupEnv("S3_UPLOAD_BUCKET")
	if !found {
		bucketName = s3DefaultUploadBucket
	}
	return
}

func getS3Region() (region string) {
	region, found := os.LookupEnv("S3_REGION")
	if !found {
		region = s3DefaultRegion
	}
	return
}

func makeS3Session(credentials *credentials.Credentials) (s3Helper, error) {
	sess, err := session.NewSession(&aws.Config{Region: aws.String(getS3Region()),
		Credentials: credentials})
	if err != nil {
		return s3Helper{}, err
	}
	return s3Helper{
		session: sess,
		bucket:  getS3Bucket(),
	}, nil
}

func (helper *s3Helper) uploadFileStream(filename string, reader io.Reader) error {
	uploader := s3manager.NewUploader(helper.session)
	_, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(helper.bucket),
		Key:    aws.String(filepath.Base(filename)),
		Body:   reader,
	})
	if err != nil {
		return err
	}
	return nil
}
