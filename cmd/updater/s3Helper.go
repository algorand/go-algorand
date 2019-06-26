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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

const algorandReleasesBucketName = "algorand-releases"
const algorandBuildsBucketName = "algorand-builds"

type s3Helper struct {
	session *session.Session
	bucket  string
}

type s3Keys struct {
	ID     string
	Secret string
	Bucket string
}

func loadS3Keys(keyFile string) (keys s3Keys, err error) {
	keys = s3Keys{}
	configpath := keyFile
	f, err := os.Open(configpath)
	if err != nil {
		return
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	err = dec.Decode(&keys)
	return
}

func makeS3SessionForDownload(bucket string) (s3Helper, error) {
	if bucket == "" {
		return makePublicS3SessionForDownload()
	}
	return makePrivateS3SessionForDownload(bucket)
}

func makePrivateS3SessionForDownload(bucket string) (s3Helper, error) {
	// If a bucket is provided, lookup credentials from standard location.
	awsID, _ := os.LookupEnv("AWS_ACCESS_KEY_ID")
	awsKey, _ := os.LookupEnv("AWS_SECRET_ACCESS_KEY")
	if awsID == "" || awsKey == "" || bucket == "" {
		exitErrorf("unable to upload. Credentials must be specified in AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY and a valid bucket provided.")
	}
	creds := credentials.NewStaticCredentials(awsID, awsKey, "")
	return makeS3Session(creds, bucket)
}

func makePublicS3SessionForDownload() (s3Helper, error) {
	// Create a session without credentials for the public algorand-releases bucket.
	// Upload requires write access and uses different credentials, read from
	// the environment so they're not publicly-available.

	return makeS3Session(nil, algorandReleasesBucketName)
}

func makeS3SessionForUpload(bucket string) (s3Helper, error) {
	if bucket == "" {
		return makeTravisS3SessionForUpload()
	}
	return makeLocalS3SessionForUpload(bucket)
}

func makeLocalS3SessionForUpload(bucket string) (s3Helper, error) {
	// Use special Algorand environment variables from build environment.
	awsID, _ := os.LookupEnv("AWS_ACCESS_KEY_ID")
	awsKey, _ := os.LookupEnv("AWS_SECRET_ACCESS_KEY")
	if awsID == "" || awsKey == "" || bucket == "" {
		exitErrorf("unable to upload. Credentials must be specified in AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY and a non empty bucket provided")
	}
	creds := credentials.NewStaticCredentials(awsID, awsKey, "")
	return makeS3Session(creds, bucket)
}

func makeTravisS3SessionForUpload() (s3Helper, error) {
	// Use special Algorand environment variables from build environment.
	awsID, _ := os.LookupEnv("AWS_ACCESS_KEY_ID")
	awsKey, _ := os.LookupEnv("AWS_SECRET_ACCESS_KEY")
	awsBucket := algorandBuildsBucketName
	if awsID == "" || awsKey == "" || awsBucket == "" {
		exitErrorf("unable to upload. Credentials must be specified in AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY and a bucket specified in S3_UPLOAD_BUCKET")
	}
	creds := credentials.NewStaticCredentials(awsID, awsKey, "")
	return makeS3Session(creds, awsBucket)
}

func makeS3Session(credentials *credentials.Credentials, bucket string) (helper s3Helper, err error) {
	sess, err := session.NewSession(&aws.Config{Region: aws.String("us-east-1"),
		Credentials: credentials})
	if err != nil {
		return s3Helper{}, err
	}
	return s3Helper{
		session: sess,
		bucket:  bucket,
	}, nil
}

func (helper *s3Helper) getLatestVersion(channel string) (maxVersion uint64, maxVersionName string, err error) {
	return helper.getVersion(channel, 0)
}

func (helper *s3Helper) getPackageVersion(pkg string, channel string, specificVersion uint64) (maxVersion uint64, maxVersionName string, err error) {
	maxVersion = 0
	maxVersionName = ""

	os := runtime.GOOS
	arch := runtime.GOARCH
	prefix := fmt.Sprintf("%s_%s_%s-%s", pkg, channel, os, arch)
	svc := s3.New(helper.session)
	input := &s3.ListObjectsInput{
		Bucket:  &helper.bucket,
		Prefix:  &prefix,
		MaxKeys: aws.Int64(500),
	}

	result, err := svc.ListObjects(input)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			err = awsErr
		}
		return
	}

	for _, item := range result.Contents {
		var version uint64
		name := string(*item.Key)
		version, err = getVersionFromName(name)
		if err != nil {
			return
		}
		if specificVersion != 0 {
			if version == specificVersion {
				maxVersion = version
				maxVersionName = name
				break
			}
		} else if version > maxVersion {
			maxVersion = version
			maxVersionName = name
		}
	}
	return
}

func (helper *s3Helper) getVersion(channel string, specificVersion uint64) (maxVersion uint64, maxVersionName string, err error) {
	return helper.getPackageVersion("node", channel, specificVersion)
}

func (helper *s3Helper) downloadFile(name string, writer io.WriterAt) error {
	downloader := s3manager.NewDownloader(helper.session)
	_, err := downloader.Download(writer,
		&s3.GetObjectInput{
			Bucket: &helper.bucket,
			Key:    aws.String(name),
		})
	if err != nil {
		return err
	}
	return nil
}

func (helper *s3Helper) uploadFiles(files []string) error {
	for _, f := range files {
		fmt.Printf("Uploading file: %s\n", f)
	}
	uploader := s3manager.NewUploader(helper.session)
	iter := makeFileIterator(files, helper.bucket)
	err := uploader.UploadWithIterator(aws.BackgroundContext(), iter)
	if err != nil {
		return err
	}
	return nil
}

func getVersionFromName(name string) (version uint64, err error) {
	re := regexp.MustCompile(`_(\d*)\.(\d*)\.(\d*)`)
	submatchAll := re.FindAllStringSubmatch(name, -1)
	if submatchAll == nil || len(submatchAll) == 0 || len(submatchAll[0]) != 4 {
		err = errors.New("unable to parse version from filename " + name)
		return
	}
	var val uint64
	for index, match := range submatchAll[0] {
		if index > 0 {
			version <<= 16
			val, err = strconv.ParseUint(match, 10, 0)
			if err != nil {
				return
			}
			version += val
		}
	}
	return
}
