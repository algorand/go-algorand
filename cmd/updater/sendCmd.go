// Copyright (C) 2019-2021 Algorand, Inc.
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
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/util/s3"
)

var sourcePath string
var uploadBucket string

func init() {
	sendCmd.Flags().StringVarP(&sourcePath, "sourcePath", "s", "", "Path containing versions to send (required)")
	sendCmd.Flags().StringVarP(&uploadBucket, "bucket", "b", "", "S3 bucket to upload files to.")
	sendCmd.MarkFlagRequired("sourcePath")
	sendCmd.MarkFlagRequired("bucket")
}

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Upload versions to S3",
	Long:  "Uploads *.tar.gz files from specified path",
	Run: func(cmd *cobra.Command, args []string) {
		s3Session, err := s3.MakeS3SessionForUploadWithBucket(uploadBucket)
		if err != nil {
			exitErrorf("Error creating s3 session %s", err.Error())
		}

		var files []string
		if files, err = getPackageFilesInPath(sourcePath); err == nil {
			err = s3Session.UploadChannelFiles(channel, files)
		}
		if err != nil {
			exitErrorf("Error uploading files", err.Error())
		}
	},
}

func getPackageFilesInPath(sourcePath string) ([]string, error) {
	pattern := filepath.Join(sourcePath, "*.tar.gz")
	paths, err := filepath.Glob(pattern)
	return paths, err
}
