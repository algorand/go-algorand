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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

// Helper encapsulates the s3 session state for interactive with our default S3 bucket with appropriate credentials
type Helper struct {
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

// MakeS3SessionForDownload returns an s3.Helper for the default algorand S3 bucket - for downloading
func MakeS3SessionForDownload() (helper Helper, err error) {
	// Create a session with our read-only credentials for the algorand-testnet bucket.
	// Upload requires write access and uses different credentials, read from
	// the environment so they're not publicly-available.
	// Download keys are loaded from updatekey.json

	ex, err := os.Executable()
	if err != nil {
		return
	}
	baseDir := filepath.Dir(ex)
	keyFile := filepath.Join(baseDir, "updatekey.json")

	keys, err := loadS3Keys(keyFile)
	if err != nil {
		err = fmt.Errorf("unable to access remote store - error loading keys: %v", err)
		return
	}
	creds := credentials.NewStaticCredentials(keys.ID, keys.Secret, "")
	helper, err = makeS3Session(creds, keys.Bucket)
	return
}

// MakeS3SessionForUpload returns an s3.Helper for the default algorand S3 bucket - for uploading
func MakeS3SessionForUpload() (helper Helper, err error) {
	awsID, _ := os.LookupEnv("S3_UPLOAD_ID")
	awsKey, _ := os.LookupEnv("S3_UPLOAD_SECRET")
	awsBucket, _ := os.LookupEnv("S3_UPLOAD_BUCKET")
	if awsID == "" || awsKey == "" || awsBucket == "" {
		err = fmt.Errorf("unable to upload. Credentials must be specified in S3_UPLOAD_ID and S3_UPLOAD_SECRET")
		return
	}
	creds := credentials.NewStaticCredentials(awsID, awsKey, "")
	helper, err = makeS3Session(creds, awsBucket)
	return
}

func makeS3Session(credentials *credentials.Credentials, bucket string) (helper Helper, err error) {
	sess, err := session.NewSession(&aws.Config{Region: aws.String("us-east-1"),
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
	if err != nil {
		return err
	}
	return nil
}

// UploadFiles uploads the provided set of files in a batch
func (helper *Helper) UploadFiles(files []string) error {
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
