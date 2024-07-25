// Copyright (C) 2019-2024 Algorand, Inc.
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
	"reflect"
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

const (
	s3UploadBucketEnvVariable  = "S3_UPLOAD_BUCKET"
	s3ReleaseBucketEnvVariable = "S3_RELEASE_BUCKET"
	s3RegionEnvVariable        = "S3_REGION"

	s3DefaultReleaseBucket = "algorand-releases"
	s3DefaultUploadBucket  = "algorand-uploads"
	s3DefaultRegion        = "us-east-1"
)

// Helper encapsulates the s3 session state for interactive with our default S3 bucket with appropriate credentials
type Helper struct {
	session *session.Session
	bucket  string
}

// GetS3UploadBucket returns bucket name for uploading log files (private read access, public write access)
func GetS3UploadBucket() (bucketName string) {
	bucketName, found := os.LookupEnv(s3UploadBucketEnvVariable)
	if !found {
		bucketName = s3DefaultUploadBucket
	}
	return
}

// GetS3ReleaseBucket returns bucket name for public releases (public read access, private write access)
func GetS3ReleaseBucket() (bucketName string) {
	bucketName, found := os.LookupEnv(s3ReleaseBucketEnvVariable)
	if !found {
		bucketName = s3DefaultReleaseBucket
	}
	return
}

func getS3Region() (region string) {
	region, found := os.LookupEnv(s3RegionEnvVariable)
	if !found {
		region = s3DefaultRegion
	}
	return
}

// MakeS3SessionForUploadWithBucket upload to bucket
func MakeS3SessionForUploadWithBucket(awsBucket string) (helper Helper, err error) {
	return makeS3Session(awsBucket)
}

// MakeS3SessionForDownloadWithBucket download from bucket
func MakeS3SessionForDownloadWithBucket(awsBucket string) (helper Helper, err error) {
	return makeS3Session(awsBucket)
}

// UploadFileStream sends file as stream to s3
func (helper *Helper) UploadFileStream(targetFile string, reader io.Reader) error {
	uploader := s3manager.NewUploader(helper.session)
	_, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(helper.bucket),
		Key:    aws.String(targetFile),
		Body:   reader,
	})
	if err != nil {
		return err
	}
	return nil
}

func validateS3Bucket(awsBucket string) (err error) {
	if awsBucket == "" {
		err = fmt.Errorf("bucket name is empty")
		return
	}
	return
}

func makeS3Session(bucket string) (helper Helper, err error) {
	err = validateS3Bucket(bucket)
	if err != nil {
		return
	}

	awsConfig := &aws.Config{
		CredentialsChainVerboseErrors: aws.Bool(true),
		Region:                        aws.String(getS3Region()),
	}

	// s3DefaultReleaseBucket should be public, use AnonymousCredentials
	if bucket == s3DefaultReleaseBucket {
		awsConfig.Credentials = credentials.AnonymousCredentials
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            *awsConfig,
	})
	if err != nil {
		return
	}

	// use AnonymousCredentials if none are found
	if creds, err := sess.Config.Credentials.Get(); err != nil && !reflect.DeepEqual(creds, credentials.AnonymousCredentials) {
		sess.Config.Credentials = credentials.AnonymousCredentials
	}

	helper = Helper{
		session: sess,
		bucket:  bucket,
	}
	return
}

// GetLatestPackageVersion returns the latest version details for a given package name (eg node, install, tools)
func (helper *Helper) GetLatestPackageVersion(channel string, packageName string) (maxVersion uint64, maxVersionName string, err error) {
	return helper.GetPackageVersion(channel, packageName, 0)
}

// GetLatestPackageFilesVersion returns the latest version details for a given standard filename prefix
func (helper *Helper) GetLatestPackageFilesVersion(channel string, packagePrefix string) (maxVersion uint64, maxVersionName string, err error) {
	return helper.GetPackageFilesVersion(channel, packagePrefix, 0)
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

// UploadChannelFiles uploads the provided set of package files in a batch
func (helper *Helper) UploadChannelFiles(channel string, files []string) error {
	subFolder := filepath.Join("channel", channel)
	return helper.UploadFiles(subFolder, files)
}

// UploadFiles uploads the provided set of files in a batch
func (helper *Helper) UploadFiles(subFolder string, files []string) error {
	target := filepath.Join(helper.bucket, subFolder)
	for _, f := range files {
		fmt.Printf("Uploading file: '%s' to '%s'\n", f, target)
	}
	uploader := s3manager.NewUploader(helper.session)
	iter := makeFileIterator(files, helper.bucket, subFolder)
	err := uploader.UploadWithIterator(aws.BackgroundContext(), iter)
	return err
}

// GetPackageVersion return the package version
func (helper *Helper) GetPackageVersion(channel string, pkg string, specificVersion uint64) (maxVersion uint64, maxVersionName string, err error) {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	prefix := fmt.Sprintf("%s_%s_%s-%s_", pkg, channel, osName, arch)

	maxVersion, maxVersionName, err = helper.GetPackageFilesVersion(channel, prefix, specificVersion)
	// For darwin, we want to also look at universal binaries
	if osName == "darwin" {
		universalPrefix := fmt.Sprintf("%s_%s_%s-%s_", pkg, channel, osName, "universal")
		universalMaxVersion, universalMaxVersionName, universalErr := helper.GetPackageFilesVersion(channel, universalPrefix, specificVersion)
		if universalMaxVersion > maxVersion {
			return universalMaxVersion, universalMaxVersionName, universalErr
		}
	}
	return maxVersion, maxVersionName, err
}

// GetPackageFilesVersion return the package version
func (helper *Helper) GetPackageFilesVersion(channel string, pkgFiles string, specificVersion uint64) (maxVersion uint64, maxVersionName string, err error) {
	maxVersion = 0
	maxVersionName = ""

	prefix := fmt.Sprintf("channel/%s/%s", channel, pkgFiles)
	svc := s3.New(helper.session)
	input := &s3.ListObjectsInput{
		Bucket:  &helper.bucket,
		Prefix:  &prefix,
		MaxKeys: aws.Int64(500),
	}

	fmt.Fprintf(os.Stdout, "Checking for files matching: '%s' in bucket %s\n", prefix, helper.bucket)

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
		version, err = GetVersionFromName(name)
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
	if len(submatchAll) == 0 || len(submatchAll[0]) != 4 {
		err = errors.New("unable to parse version from filename " + name)
		return
	}
	var val uint64
	submatch := submatchAll[0][1:] // skip the first match which is the whole string
	offsets := []int{0, 16, 24}    // some bits for major (not really restricted), 16 bits for minor, 24 bits for patch
	for index, match := range submatch {
		version <<= offsets[index]
		val, err = strconv.ParseUint(match, 10, 0)
		if err != nil {
			return
		}
		version += val
	}
	return
}

// GetVersionPartsFromVersion converts the merged version number back into parts.
func GetVersionPartsFromVersion(version uint64) (major uint64, minor uint64, patch uint64, err error) {
	val := version

	if val < 1<<40 {
		err = errors.New("versions below 1.0.0 not supported")
		return
	}

	patch = val & 0xffffff
	val >>= 24
	minor = val & 0xffff
	val >>= 16
	major = val
	return
}
