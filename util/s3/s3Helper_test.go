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
	"os"
	"reflect"
	"testing"
)

func TestGetS3UploadBucket(t *testing.T) {
	tests := []struct {
		name           string
		getDefault     bool
		wantBucketName string
	}{
		{name: "test1", wantBucketName: "test-bucket"},
		{name: "test2", wantBucketName: "anotherbucket"},
		{name: "test3", wantBucketName: ""},
		{name: "test4", getDefault: true, wantBucketName: "algorand-uploads"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.getDefault {
				os.Unsetenv("S3_UPLOAD_BUCKET")
			} else {
				os.Setenv("S3_UPLOAD_BUCKET", tt.wantBucketName)
			}
			if gotBucketName := GetS3UploadBucket(); gotBucketName != tt.wantBucketName {
				t.Errorf("GetS3UploadBucket() = %v, want %v", gotBucketName, tt.wantBucketName)
			}
		})
	}
}

func TestGetS3ReleaseBucket(t *testing.T) {
	tests := []struct {
		name           string
		getDefault     bool
		wantBucketName string
	}{
		{name: "test1", wantBucketName: "test-bucket"},
		{name: "test2", wantBucketName: "anotherbucket"},
		{name: "test3", wantBucketName: ""},
		{name: "test4", getDefault: true, wantBucketName: "algorand-releases"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.getDefault {
				os.Unsetenv("S3_RELEASE_BUCKET")
			} else {
				os.Setenv("S3_RELEASE_BUCKET", tt.wantBucketName)
			}
			if gotBucketName := GetS3ReleaseBucket(); gotBucketName != tt.wantBucketName {
				t.Errorf("GetS3ReleaseBucket() = %v, want %v", gotBucketName, tt.wantBucketName)
			}
		})
	}
}

func Test_getS3Region(t *testing.T) {
	tests := []struct {
		name       string
		getDefault bool
		wantRegion string
	}{
		{name: "test1", wantRegion: "us-east1"},
		{name: "test2", wantRegion: "us-west2"},
		{name: "test3", wantRegion: ""},
		{name: "test3", getDefault: true, wantRegion: "us-east-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.getDefault {
				os.Unsetenv("S3_REGION")
			} else {
				os.Setenv("S3_REGION", tt.wantRegion)
			}
			if gotRegion := getS3Region(); gotRegion != tt.wantRegion {
				t.Errorf("getS3Region() = %v, want %v", gotRegion, tt.wantRegion)
			}
		})
	}
}

func TestMakeS3SessionForUploadWithBucket(t *testing.T) {
	const bucket1 = "test-bucket"
	const publicUploadBucket = "algorand-uploads"
	const emptyBucket = ""
	type args struct {
		awsBucket string
		awsID     string
		awsSecret string
	}
	tests := []struct {
		name       string
		args       args
		wantHelper Helper
		wantErr    bool
	}{
		{name: "test1", args: args{awsBucket: bucket1, awsID: "AWS_ID", awsSecret: "AWS_SECRET"}, wantHelper: Helper{bucket: bucket1}, wantErr: false},
		{name: "test2", args: args{awsBucket: emptyBucket, awsID: "AWS_ID", awsSecret: "AWS_SECRET"}, wantHelper: Helper{bucket: emptyBucket}, wantErr: true},
		{name: "test3", args: args{awsBucket: bucket1, awsID: "", awsSecret: "AWS_SECRET"}, wantHelper: Helper{bucket: bucket1}, wantErr: true},
		{name: "test4", args: args{awsBucket: bucket1, awsID: "AWS_ID", awsSecret: ""}, wantHelper: Helper{bucket: bucket1}, wantErr: true},
		{name: "test5", args: args{awsBucket: bucket1, awsID: "", awsSecret: ""}, wantHelper: Helper{bucket: bucket1}, wantErr: true},
		// public upload bucket requires AWS credentials for uploads
		{name: "test6", args: args{awsBucket: publicUploadBucket, awsID: "AWS_ID", awsSecret: "AWS_SECRET"}, wantHelper: Helper{bucket: publicUploadBucket}, wantErr: false},
		{name: "test7", args: args{awsBucket: publicUploadBucket, awsID: "", awsSecret: "AWS_SECRET"}, wantHelper: Helper{bucket: publicUploadBucket}, wantErr: true},
		{name: "test8", args: args{awsBucket: publicUploadBucket, awsID: "AWS_ID", awsSecret: ""}, wantHelper: Helper{bucket: publicUploadBucket}, wantErr: true},
		{name: "test9", args: args{awsBucket: publicUploadBucket, awsID: "", awsSecret: ""}, wantHelper: Helper{bucket: publicUploadBucket}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("AWS_ACCESS_KEY_ID", tt.args.awsID)
			os.Setenv("AWS_SECRET_ACCESS_KEY", tt.args.awsSecret)
			gotHelper, err := MakeS3SessionForUploadWithBucket(tt.args.awsBucket)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeS3SessionForUploadWithBucket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && !reflect.DeepEqual(gotHelper.bucket, tt.wantHelper.bucket) {
				t.Errorf("MakeS3SessionForUploadWithBucket() = %v, want %v", gotHelper, tt.wantHelper)
			}
		})
	}
}

func TestMakeS3SessionForDownloadWithBucket(t *testing.T) {
	const bucket1 = "test-bucket"
	const publicReleaseBucket = "algorand-releases"
	const emptyBucket = ""
	type args struct {
		awsBucket string
		awsID     string
		awsSecret string
	}
	tests := []struct {
		name       string
		args       args
		wantHelper Helper
		wantErr    bool
	}{
		{name: "test1", args: args{awsBucket: bucket1, awsID: "AWS_ID", awsSecret: "AWS_SECRET"}, wantHelper: Helper{bucket: bucket1}, wantErr: false},
		{name: "test2", args: args{awsBucket: emptyBucket, awsID: "AWS_ID", awsSecret: "AWS_SECRET"}, wantHelper: Helper{bucket: emptyBucket}, wantErr: true},
		{name: "test3", args: args{awsBucket: bucket1, awsID: "", awsSecret: "AWS_SECRET"}, wantHelper: Helper{bucket: bucket1}, wantErr: true},
		{name: "test4", args: args{awsBucket: bucket1, awsID: "AWS_ID", awsSecret: ""}, wantHelper: Helper{bucket: bucket1}, wantErr: true},
		{name: "test5", args: args{awsBucket: bucket1, awsID: "", awsSecret: ""}, wantHelper: Helper{bucket: bucket1}, wantErr: true},
		// public release bucket does not require AWS credentials for downloads
		{name: "test6", args: args{awsBucket: publicReleaseBucket, awsID: "AWS_ID", awsSecret: "AWS_SECRET"}, wantHelper: Helper{bucket: publicReleaseBucket}, wantErr: false},
		{name: "test7", args: args{awsBucket: publicReleaseBucket, awsID: "", awsSecret: "AWS_SECRET"}, wantHelper: Helper{bucket: publicReleaseBucket}, wantErr: false},
		{name: "test8", args: args{awsBucket: publicReleaseBucket, awsID: "AWS_ID", awsSecret: ""}, wantHelper: Helper{bucket: publicReleaseBucket}, wantErr: false},
		{name: "test9", args: args{awsBucket: publicReleaseBucket, awsID: "", awsSecret: ""}, wantHelper: Helper{bucket: publicReleaseBucket}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("AWS_ACCESS_KEY_ID", tt.args.awsID)
			os.Setenv("AWS_SECRET_ACCESS_KEY", tt.args.awsSecret)
			gotHelper, err := MakeS3SessionForDownloadWithBucket(tt.args.awsBucket)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeS3SessionForDownloadWithBucket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && !reflect.DeepEqual(gotHelper.bucket, tt.wantHelper.bucket) {
				t.Errorf("MakeS3SessionForDownloadWithBucket() = %v, want %v", gotHelper, tt.wantHelper)
			}
		})
	}
}
