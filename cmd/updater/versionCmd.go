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
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/util/s3"
)

var (
	destFile        string
	versionBucket   string
	specificVersion uint64
	semanticOutput  bool
)

func init() {
	versionCmd.AddCommand(checkCmd)
	versionCmd.AddCommand(getCmd)

	checkCmd.Flags().StringVarP(&versionBucket, "bucket", "b", "", "S3 bucket containing updates.")
	checkCmd.Flags().BoolVarP(&semanticOutput, "semantic", "s", false, "Human readable semantic version output.")

	getCmd.Flags().StringVarP(&destFile, "outputFile", "o", "", "Path for downloaded file (required).")
	getCmd.Flags().StringVarP(&versionBucket, "bucket", "b", "", "S3 bucket containing updates.")
	getCmd.Flags().Uint64VarP(&specificVersion, "version", "v", 0, "Specific version to download.")
	getCmd.MarkFlagRequired("outputFile")
}

var versionCmd = &cobra.Command{
	Use:   "ver",
	Short: "Get latest version number or download latest version",
	Long:  `Allows checking the version of the latest update and downloading it `,
	Run: func(cmd *cobra.Command, args []string) {
		// Fall back
		cmd.HelpFunc()(cmd, args)
	},
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check the latest version available",
	Long:  `Check the latest version available`,
	Run: func(cmd *cobra.Command, args []string) {
		if versionBucket == "" {
			versionBucket = s3.GetS3ReleaseBucket()
		}
		s3Session, err := s3.MakeS3SessionForDownloadWithBucket(versionBucket)
		if err != nil {
			exitErrorf("Error creating s3 session %s\n", err.Error())
		} else {
			version, _, err := s3Session.GetLatestUpdateVersion(channel)
			if err != nil {
				exitErrorf("Error getting latest version from s3 %s\n", err.Error())
			}

			if version == 0 {
				fmt.Fprintf(os.Stderr, "no updates found for channel '%s'\n", channel)
				os.Exit(1)
			}

			if semanticOutput {
				major, minor, patch, err := s3.GetVersionPartsFromVersion(version)
				if err != nil {
					exitErrorf("Problem converting '%d' to a semantic version string: %v", version, err)
				}
				fmt.Fprintf(os.Stdout, "%d.%d.%d\n", major, minor, patch)
			} else {
				fmt.Fprintf(os.Stdout, "%d\n", version)
			}
		}
	},
}

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Download the latest version available",
	Long:  `Download the latest version available`,
	Run: func(cmd *cobra.Command, args []string) {
		if versionBucket == "" {
			versionBucket = s3.GetS3ReleaseBucket()
		}
		s3Session, err := s3.MakeS3SessionForDownloadWithBucket(versionBucket)
		if err != nil {
			exitErrorf("Error creating s3 session %s\n", err.Error())
		} else {
			version, name, err := s3Session.GetUpdateVersion(channel, specificVersion)
			if err != nil {
				exitErrorf("Error getting latest version from s3 %s\n", err.Error())
			}
			if version == 0 {
				exitErrorf("No updates found\n")
			}

			file, err := os.Create(os.ExpandEnv(destFile))
			defer file.Close()
			if err != nil {
				exitErrorf("Error creating output file: %s\n", err.Error())
			}

			err = s3Session.DownloadFile(name, file)
			if err != nil {
				exitErrorf("Error downloading file: %s\n", err.Error())
				// script should delete the file.
			}
		}
	},
}
