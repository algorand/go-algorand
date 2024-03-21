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
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestGetS3UploadBucket(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

	const bucket1 = "test-bucket"
	const publicUploadBucket = "algorand-uploads"
	const emptyBucket = ""
	type args struct {
		awsBucket string
	}
	tests := []struct {
		name       string
		args       args
		wantHelper Helper
		wantErr    bool
	}{
		{name: "test1", args: args{awsBucket: bucket1}, wantHelper: Helper{bucket: bucket1}, wantErr: false},
		{name: "test2", args: args{awsBucket: emptyBucket}, wantHelper: Helper{bucket: emptyBucket}, wantErr: true},
		{name: "test6", args: args{awsBucket: publicUploadBucket}, wantHelper: Helper{bucket: publicUploadBucket}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	partitiontest.PartitionTest(t)

	const bucket1 = "test-bucket"
	const publicReleaseBucket = "algorand-releases"
	const emptyBucket = ""
	type args struct {
		awsBucket string
	}
	tests := []struct {
		name       string
		args       args
		wantHelper Helper
		wantErr    bool
	}{
		{name: "test1", args: args{awsBucket: bucket1}, wantHelper: Helper{bucket: bucket1}, wantErr: false},
		{name: "test2", args: args{awsBucket: emptyBucket}, wantHelper: Helper{bucket: emptyBucket}, wantErr: true},
		{name: "test6", args: args{awsBucket: publicReleaseBucket}, wantHelper: Helper{bucket: publicReleaseBucket}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func TestGetVersionFromName(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type args struct {
		name     string
		version  string
		expected uint64
	}
	tests := []args{
		{name: "test 1 (major)", version: "_1.0.0", expected: 1 * 1 << 40},
		{name: "test 2 (major)", version: "_2.0.0", expected: 2 * 1 << 40},
		{name: "test 3 (minor)", version: "_1.1.0", expected: 1*1<<40 + 1*1<<24},
		{name: "test 4 (minor)", version: "_1.2.0", expected: 1*1<<40 + 2*1<<24},
		{name: "test 5 (patch)", version: "_1.0.1", expected: 1*1<<40 + 1},
		{name: "test 6 (patch)", version: "_1.0.2", expected: 1*1<<40 + 2},
	}

	for _, test := range tests {
		actual, err := GetVersionFromName(test.version)
		require.NoError(t, err, test.name)
		require.Equal(t, test.expected, actual, test.name)
	}
}

func TestGetVersionFromNameCompare(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	name1 := "config_3.13.170018.tar.gz"
	name2 := "config_3.15.157.tar.gz"

	ver1, err := GetVersionFromName(name1)
	require.NoError(t, err)
	ver2, err := GetVersionFromName(name2)
	require.NoError(t, err)

	require.Less(t, ver1, ver2)
}

func TestGetPartsFromVersion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type args struct {
		name     string
		version  uint64
		expMajor uint64
		expMinor uint64
		expPatch uint64
	}
	tests := []args{
		{name: "test 1 (major)", version: 1 * 1 << 40, expMajor: 1, expMinor: 0, expPatch: 0},
		{name: "test 2 (major)", version: 2 * 1 << 40, expMajor: 2, expMinor: 0, expPatch: 0},
		{name: "test 3 (minor)", version: 1*1<<40 + 1*1<<24, expMajor: 1, expMinor: 1, expPatch: 0},
		{name: "test 4 (minor)", version: 1*1<<40 + 2*1<<24, expMajor: 1, expMinor: 2, expPatch: 0},
		{name: "test 5 (patch)", version: 1*1<<40 + 1, expMajor: 1, expMinor: 0, expPatch: 1},
		{name: "test 6 (patch)", version: 1*1<<40 + 2, expMajor: 1, expMinor: 0, expPatch: 2},
		{name: "test 6 (patch)", version: 3298803318784, expMajor: 3, expMinor: 16, expPatch: 0},
	}

	for _, test := range tests {
		actualMajor, actualMinor, actualPatch, err := GetVersionPartsFromVersion(test.version)
		require.NoError(t, err, test.name)
		require.Equal(t, test.expMajor, actualMajor, test.name)
		require.Equal(t, test.expMinor, actualMinor, test.name)
		require.Equal(t, test.expPatch, actualPatch, test.name)
	}

	_, _, _, err := GetVersionPartsFromVersion(1<<40 - 1)
	require.Error(t, err, "Versions less than 1.0.0 should not be parsed.")
}

func TestGetPartsFromVersionEndToEnd(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type args struct {
		major uint64
		minor uint64
		patch uint64
	}
	tests := []args{
		{major: 1, minor: 0, patch: 0},
		{major: 3, minor: 13, patch: 170018},
		{major: 3, minor: 15, patch: 157},
	}

	for _, test := range tests {
		name := fmt.Sprintf("config_%d.%d.%d.tar.gz", test.major, test.minor, test.patch)
		t.Run(name, func(t *testing.T) {
			ver, err := GetVersionFromName(name)
			require.NoError(t, err)
			actualMajor, actualMinor, actualPatch, err := GetVersionPartsFromVersion(ver)
			require.NoError(t, err)
			require.Equal(t, test.major, actualMajor)
			require.Equal(t, test.minor, actualMinor)
			require.Equal(t, test.patch, actualPatch)
		})
	}
}
