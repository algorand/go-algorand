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

package s3

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

const s3DefaultReleaseBucket = "algorand-releases"
const s3DefaultUploadBucket = "algorand-uploads"
const s3DefaultRegion = "us-east-1"

// Helper encapsulates the s3 session state for interactive with our default S3 bucket with appropriate credentials
type Helper struct {
	session *session.Session
	bucket  string
}

func getS3UploadBucket() (bucketName string) {
	bucketName, found := os.LookupEnv("S3_UPLOAD_BUCKET")
	if !found {
		bucketName = s3DefaultUploadBucket
	}
	return
}

func getS3ReleaseBucket() (bucketName string) {
	bucketName, found := os.LookupEnv("S3_RELEASE_BUCKET")
	if !found {
		bucketName = s3DefaultReleaseBucket
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

func getAWSCredentials() (awsID string, awsKey string) {
	awsID, _ = os.LookupEnv("AWS_ACCESS_KEY_ID")
	awsKey, _ = os.LookupEnv("AWS_SECRET_ACCESS_KEY")
	return
}

func validateS3Params(action string, awsID string, awsKey string, awsBucket string) (err error) {
	if awsID == "" || awsKey == "" {
		err = fmt.Errorf("unable to %s. Credentials must be specified in AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY", action)
		return
	}
	if awsBucket == "" {
		err = fmt.Errorf("unable to %s, bucket name is empty", action)
		return
	}
	return
}

// UploadFileStream sends file as stream to s3
func (helper *Helper) UploadFileStream(filename string, reader io.Reader) error {
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

// MakeS3SessionForUpload returns an s3.Helper with default bucket for upload
func MakeS3SessionForUpload() (helper Helper, err error) {
	return MakeS3SessionForUploadWithBucket(getS3UploadBucket())
}

// MakeS3SessionForUploadWithBucket upload to bucket
func MakeS3SessionForUploadWithBucket(awsBucket string) (helper Helper, err error) {
	awsID, awsKey := getAWSCredentials()
	if awsBucket == "" {
		awsBucket = s3DefaultUploadBucket
	}
	err = validateS3Params("upload", awsID, awsKey, awsBucket)
	if err != nil {
		return
	}
	creds := credentials.NewStaticCredentials(awsID, awsKey, "")
	return makeS3Session(creds, awsBucket)
}

// MakeS3SessionForDownload returns an s3.Helper with default bucket for download
func MakeS3SessionForDownload() (helper Helper, err error) {
	return MakeS3SessionForDownloadWithBucket(getS3ReleaseBucket())
}

// MakeS3SessionForDownloadWithBucket download from bucket
func MakeS3SessionForDownloadWithBucket(awsBucket string) (helper Helper, err error) {
	awsID, awsKey := getAWSCredentials()
	if awsBucket == "" {
		awsBucket = s3DefaultReleaseBucket
	}
	err = validateS3Params("download", awsID, awsKey, awsBucket)
	if err != nil {
		return
	}
	creds := credentials.NewStaticCredentials(awsID, awsKey, "")
	return makeS3Session(creds, awsBucket)
}

func makeS3Session(credentials *credentials.Credentials, bucket string) (helper Helper, err error) {
	sess, err := session.NewSession(&aws.Config{Region: aws.String(getS3Region()),
		Credentials: credentials})
	if err != nil {
		return
	}
	helper = Helper{
		session: sess,
		bucket:  bucket,
	}
	return
}

// GetLatestVersion returns the latest version details for a given standard filename prefix
func (helper *Helper) GetLatestVersion(prefix string) (maxVersion uint64, maxVersionName string, err error) {
	return helper.GetVersion(prefix, 0)
}

// GetVersion ensures the specified version is present and returns the name of the file, if found
// Or if specificVersion == 0, returns the name of the file with the max version
func (helper *Helper) GetVersion(prefix string, specificVersion uint64) (maxVersion uint64, maxVersionName string, err error) {
	maxVersion = 0
	maxVersionName = ""

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

// DownloadFile downloads the specified file to the provided Writer
func (helper *Helper) DownloadFile(name string, writer io.WriterAt) error {
	downloader := s3manager.NewDownloader(helper.session)
	_, err := downloader.Download(writer,
		&s3.GetObjectInput{
			Bucket: &helper.bucket,
			Key:    aws.String(name),
		})
	return err
}

// UploadFiles uploads the provided set of files in a batch
func (helper *Helper) UploadFiles(files []string) error {
	for _, f := range files {
		fmt.Printf("Uploading file: %s\n", f)
	}
	uploader := s3manager.NewUploader(helper.session)
	iter := makeFileIterator(files, helper.bucket)
	err := uploader.UploadWithIterator(aws.BackgroundContext(), iter)
	return err
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

// GetPackageVersion return the package version
func (helper *Helper) GetPackageVersion(pkg string, channel string, specificVersion uint64) (maxVersion uint64, maxVersionName string, err error) {
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

// GetVersionFromName return the version for the given name
func GetVersionFromName(name string) (version uint64, err error) {
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
