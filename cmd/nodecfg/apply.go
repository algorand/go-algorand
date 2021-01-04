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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/netdeploy/remote"
	"github.com/algorand/go-algorand/netdeploy/remote/nodecfg"
	"github.com/algorand/go-algorand/util"
)

var applyChannel string
var applyHostName string
var applyRootDir string
var applyRootNodeDir string
var applyPublicAddress string
var nodeConfigBucket string

func init() {
	applyCmd.Flags().StringVarP(&applyChannel, "channel", "c", "", "Channel for the nodes we are configuring")
	applyCmd.MarkFlagRequired("channel")

	applyCmd.Flags().StringVarP(&applyHostName, "host", "H", "", "Name of the Host we are configuring")
	applyCmd.MarkFlagRequired("host")

	applyCmd.Flags().StringVarP(&applyRootDir, "rootdir", "r", "", "The rootdir containing the node configuration files")

	applyCmd.Flags().StringVarP(&applyRootNodeDir, "rootnodedir", "n", "", "The root directory for node directories")

	applyCmd.Flags().StringVarP(&applyPublicAddress, "publicaddress", "a", "", "The public address to use if registering Relay or for Metrics")

	applyCmd.Flags().StringVarP(&nodeConfigBucket, "bucket", "b", "", "S3 bucket to get node configuration from.")
}

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply a node configuration to a new host",
	Long:  `Apply a node configuration to a new host providing feedback on progress`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := validateArgs(); err != nil {
			reportErrorf("Error validating arguments: %v", err)
		}

		if applyRootNodeDir == "" {
			applyRootNodeDir = filepath.Join(os.ExpandEnv("~/algorand"), applyChannel)
			reportInfof("--rootnodedir / -n not specified, defaulting to %s", applyRootNodeDir)
		}

		if !util.FileExists(filepath.Join(applyRootNodeDir, "algod")) {
			reportErrorf("rootnodedir does not appear to be a valid algod installation - algod is missing\n")
		}

		// Force all nodes to be under the <bin>/data folder.
		applyRootNodeDir = filepath.Join(applyRootNodeDir, "data")
		if err := os.Mkdir(applyRootNodeDir, 0700); err != nil && !os.IsExist(err) {
			reportErrorf("Error creating data dir: %v", err)
		}

		if err := doApply(applyRootDir, applyRootNodeDir, applyChannel, applyHostName, applyPublicAddress); err != nil {
			reportErrorf("Error applying configuration: %v", err)
		}
	},
}

func doApply(rootDir string, rootNodeDir, channel string, hostName string, dnsName string) (err error) {
	var missing bool
	var cfg remote.DeployedNetworkConfig
	if rootDir == "" {
		missing = true
	} else {
		fmt.Fprintf(os.Stdout, "Loading config from %s...\n", rootDir)
		cfg, err = remote.LoadDeployedNetworkConfigFromDir(rootDir)
		if err != nil {
			missing = os.IsNotExist(err)
			if !missing {
				return
			}
		}
	}

	// If config doesn't already exist, download it to specified root dir
	if missing {
		fmt.Fprintf(os.Stdout, "Configuration rootdir not specified - downloading latest version...\n")
		rootDir, err = ioutil.TempDir("", channel)
		if err != nil {
			return fmt.Errorf("error creating temp dir for extracting config package: %v", err)
		}
		defer os.RemoveAll(rootDir)

		if err = downloadAndExtractConfigPackage(channel, rootDir, nodeConfigBucket); err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stdout, "Loading config from %s...\n", rootDir)
	cfg, err = remote.LoadDeployedNetworkConfigFromDir(rootDir)
	if err != nil {
		return fmt.Errorf("error loading configuration file: %v", err)
	}

	hostCfg, has := cfg.TryGetHostConfig(hostName)
	if !has {
		return fmt.Errorf("configuration does not include this host: %s", hostName)
	}

	if hostNeedsDNSName(hostCfg) && dnsName == "" {
		return fmt.Errorf("publicaddress is required - Host contains Relays or exposes Metrics")
	}

	fmt.Fprintf(os.Stdout, "Applying config for host '%s' (%d nodes)...\n", hostName, len(hostCfg.Nodes))
	err = nodecfg.ApplyConfigurationToHost(hostCfg, rootDir, rootNodeDir, dnsName)

	return
}

func hostNeedsDNSName(config remote.HostConfig) bool {
	for _, node := range config.Nodes {
		if node.IsRelay() || node.EnableMetrics {
			return true
		}
	}
	return false
}

func validateArgs() (err error) {
	if applyHostName == "" {
		return fmt.Errorf("--host / -H must be specified")
	}
	if applyChannel == "" {
		return fmt.Errorf("--channel / -c must be specified")
	}
	return
}
