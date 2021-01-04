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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/netdeploy"
	"github.com/algorand/go-algorand/util"
)

var networkRootDir string
var networkName string
var networkTemplateFile string
var startNode string
var noImportKeys bool
var noClean bool

func init() {
	networkCmd.AddCommand(networkCreateCmd)
	networkCmd.PersistentFlags().StringVarP(&networkRootDir, "rootdir", "r", "", "Root directory for the private network directories")
	networkCmd.MarkPersistentFlagRequired("rootdir")

	networkCreateCmd.Flags().StringVarP(&networkName, "network", "n", "", "Specify the name to use for the private network")
	networkCreateCmd.MarkFlagRequired("network")
	networkCreateCmd.Flags().StringVarP(&networkTemplateFile, "template", "t", "", "Specify the path to the template file for the network")
	networkCreateCmd.MarkFlagRequired("template")
	networkCreateCmd.Flags().BoolVarP(&noImportKeys, "noimportkeys", "K", false, "Do not import root keys when creating the network (by default will import)")
	networkCreateCmd.Flags().BoolVar(&noClean, "noclean", false, "Prevents auto-cleanup on error - for diagnosing problems")

	networkStartCmd.Flags().StringVarP(&startNode, "node", "n", "", "Specify the name of a specific node to start")

	networkCmd.AddCommand(networkStartCmd)
	networkCmd.AddCommand(networkRestartCmd)
	networkCmd.AddCommand(networkStopCmd)
	networkCmd.AddCommand(networkStatusCmd)
	networkCmd.AddCommand(networkDeleteCmd)
}

var networkCmd = &cobra.Command{
	Use:   "network",
	Short: "Create and manage private, multi-node, locally-hosted networks",
	Long: `Collection of commands to support the creation and management of 'private networks'. These are fully-formed Algorand networks with private, custom Genesis ledgers running the current build of Algorand software. Rather than creating a node instance based on the released genesis.json, these networks have their own and need to be manually connected.

The basic idea is that we create one or more data directories and wallets to form this network, specify which node owns which wallets, and can start/stop the network as a unit. Each node is just like any other node running on TestNet or DevNet.`,
	Args: validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		//Fall back
		cmd.HelpFunc()(cmd, args)
	},
}

var networkCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a private named network from a template",
	Long:  `Creates a collection of folders under the specified root directory that make up the entire private network named 'private' (simplifying cleanup).`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		networkRootDir, err := filepath.Abs(networkRootDir)
		if err != nil {
			panic(err)
		}
		networkTemplateFile, err := filepath.Abs(networkTemplateFile)
		if err != nil {
			panic(err)
		}
		// Make sure target directory doesn't already exist
		exists := util.FileExists(networkRootDir)
		if exists {
			reportErrorf(infoNetworkAlreadyExists, networkRootDir)
		}

		binDir, err := util.ExeDir()
		if err != nil {
			panic(err)
		}

		dataDir := maybeSingleDataDir()
		var consensus config.ConsensusProtocols
		if dataDir != "" {
			// try to load the consensus from there. If there is none, we can just use the built in one.
			consensus, _ = config.PreloadConfigurableConsensusProtocols(dataDir)
		}

		network, err := netdeploy.CreateNetworkFromTemplate(networkName, networkRootDir, networkTemplateFile, binDir, !noImportKeys, nil, consensus)
		if err != nil {
			if noClean {
				reportInfof(" ** failed ** - Preserving network rootdir '%s'", networkRootDir)
			} else {
				os.RemoveAll(networkRootDir) // Don't leave partial network directory if create failed
			}
			reportErrorf(errorCreateNetwork, err)
		}

		reportInfof(infoNetworkCreated, network.Name(), networkRootDir)
	},
}

func getNetworkAndBinDir() (netdeploy.Network, string) {
	networkRootDir, err := filepath.Abs(networkRootDir)
	if err != nil {
		panic(err)
	}
	network, err := netdeploy.LoadNetwork(networkRootDir)
	if err != nil {
		reportErrorf(errorLoadingNetwork, err)
	}
	binDir, err := util.ExeDir()
	if err != nil {
		panic(err)
	}
	return network, binDir
}

var networkStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start a deployed private network",
	Long:  `Start a deployed private network by starting each individual node.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		network, binDir := getNetworkAndBinDir()
		if startNode == "" {
			err := network.Start(binDir, false)
			if err != nil {
				reportErrorf(errorStartingNetwork, err)
			}
			reportInfof(infoNetworkStarted, networkRootDir)
		} else {
			err := network.StartNode(binDir, startNode, false)
			if err != nil {
				reportErrorf(errorNodeFailedToStart, err)
			}
			reportInfof(infoNodeStart)
		}
	},
}

var networkRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart a deployed private network",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		network, binDir := getNetworkAndBinDir()
		network.Stop(binDir)
		err := network.Start(binDir, false)
		if err != nil {
			reportErrorf(errorStartingNetwork, err)
		}
		reportInfof(infoNetworkStarted, networkRootDir)
	},
}

var networkStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop a deployed private network",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		network, binDir := getNetworkAndBinDir()
		network.Stop(binDir)
		reportInfof(infoNetworkStopped, networkRootDir)
	},
}

var networkStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Prints status for all nodes in a deployed private network",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		network, binDir := getNetworkAndBinDir()

		statuses := network.NodesStatus(binDir)
		for dir, status := range statuses {
			if status.Error != nil {
				reportErrorf("\n[%s]\n ** Error getting status: %v **\n", dir, status.Error)
			} else {
				reportInfof("\n[%s]\n%s", dir, makeStatusString(status.Status))
			}
		}
		fmt.Println()
	},
}

var networkDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Stops and Deletes a deployed private network",
	Long:  `Stops and Deletes a deployed private network. NOTE: This does not prompt first - so be careful before you do this!`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		network, binDir := getNetworkAndBinDir()

		err := network.Delete(binDir)
		if err != nil {
			reportErrorf("Error stopping or deleting network: %v\n", err)
		}
		reportInfof(infoNetworkDeleted, networkRootDir)
	},
}
