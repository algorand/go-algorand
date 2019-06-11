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
	"os"

	"github.com/spf13/cobra"
)

var toolsDestFile string
var toolsBucket string

func init() {
	getToolsCmd.Flags().StringVarP(&toolsDestFile, "outputFile", "o", "", "Path for downloaded file (required)")
	getToolsCmd.Flags().StringVarP(&toolsBucket, "bucket", "b", "", "S3 bucket to check for tools.")
	getToolsCmd.MarkFlagRequired("outputFile")
}

var getToolsCmd = &cobra.Command{
	Use:   "gettools",
	Short: "Download the latest version of tools package available for specified channel",
	Long:  "Download the latest version of tools package available for specified channel",
	Run: func(cmd *cobra.Command, args []string) {
		s3, err := makeS3SessionForDownload(toolsBucket)
		if err != nil {
			exitErrorf("Error creating s3 session %s\n", err.Error())
		}

		version, name, err := s3.getPackageVersion("tools", channel, specificVersion)
		if err != nil {
			exitErrorf("Error getting latest tools version from s3 %s\n", err.Error())
		}
		if version == 0 {
			exitErrorf("No version found\n")
		}

		file, err := os.Create(os.ExpandEnv(toolsDestFile))
		defer file.Close()
		if err != nil {
			exitErrorf("Error creating output file: %s\n", err.Error())
		}

		err = s3.downloadFile(name, file)
		if err != nil {
			exitErrorf("Error downloading file: %s\n", err.Error())
			// script should delete the file.
		}
	},
}
