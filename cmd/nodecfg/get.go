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
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/netdeploy/remote"
	"github.com/algorand/go-algorand/util"
)

var getChannel string
var getRootDir string
var configBucket string

func init() {
	getCmd.Flags().StringVarP(&getChannel, "channel", "c", "", "Channel for the nodes we are configuring")
	getCmd.MarkFlagRequired("channel")

	getCmd.Flags().StringVarP(&getRootDir, "rootdir", "r", "", "The rootdir containing the node configuration files")

	getCmd.Flags().StringVarP(&configBucket, "bucket", "b", "", "S3 bucket to get configuration from.")
}

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "get the latest configuration package for the specified channel from s3",
	Long:  `get the latest configuration package for the specified channel from s3`,
	Run: func(cmd *cobra.Command, args []string) {
		networkRootDir, err := filepath.Abs(getRootDir)
		if err != nil {
			return
		}
		// Make sure target directory doesn't already exist
		exists := util.FileExists(networkRootDir)
		if exists {
			reportErrorf("Target rootdir '%s' already exists", networkRootDir)
		}

		if err := doGet(getChannel, getRootDir); err != nil {
			reportErrorf("Error retrieving configuration: %v", err)
		}

		cfg, err := remote.LoadDeployedNetworkConfigFromDir(getRootDir)
		if err != nil {
			reportErrorf("Error loading configuration file: %v", err)
		}
		fmt.Fprintf(os.Stdout, "Configuration for '%s' ready - network contains %d Hosts.\n", getChannel, len(cfg.Hosts))
	},
}

func doGet(channel, rootDir string) (err error) {
	if err = os.Mkdir(rootDir, 0700); err != nil {
		return
	}
	return downloadAndExtractConfigPackage(channel, rootDir, configBucket)
}
