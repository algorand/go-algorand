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

package main

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/cmd/util/datadir"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/gen"
	"github.com/algorand/go-algorand/netdeploy"
	"github.com/algorand/go-algorand/util"
)

var networkRootDir string
var networkName string
var networkTemplateFile string
var startNode string
var noImportKeys bool
var noClean bool
var devModeOverride bool
var startOnCreation bool
var pregenDir string

func init() {
	networkCmd.AddCommand(networkCreateCmd)
	networkCmd.PersistentFlags().StringVarP(&networkRootDir, "rootdir", "r", "", "Root directory for the private network directories")

	networkCreateCmd.Flags().StringVarP(&networkName, "network", "n", "", "Specify the name to use for the private network")
	networkCreateCmd.Flags().StringVarP(&networkTemplateFile, "template", "t", "", "Specify the path to the template file for the network")
	networkCreateCmd.Flags().BoolVarP(&noImportKeys, "noimportkeys", "K", false, "Do not import root keys when creating the network (by default will import)")
	networkCreateCmd.Flags().BoolVar(&noClean, "noclean", false, "Prevents auto-cleanup on error - for diagnosing problems")
	networkCreateCmd.Flags().BoolVar(&devModeOverride, "devMode", false, "Forces the configuration to enable DevMode, returns an error if the template is not compatible with DevMode.")
	networkCreateCmd.Flags().BoolVarP(&startOnCreation, "start", "s", false, "Automatically start the network after creating it.")
	networkCreateCmd.Flags().StringVarP(&pregenDir, "pregendir", "p", "", "Specify the path to the directory with pregenerated genesis.json, root and partkeys to import into the network directory. By default, the genesis.json and keys will be generated on start. This should only be used on private networks.")
	networkCreateCmd.MarkFlagRequired("rootdir")

	networkCmd.AddCommand(networkStartCmd)
	networkStartCmd.Flags().StringVarP(&startNode, "node", "n", "", "Specify the name of a specific node to start")
	networkStartCmd.MarkFlagRequired("rootdir")

	networkCmd.AddCommand(networkRestartCmd)
	networkRestartCmd.MarkFlagRequired("rootdir")

	networkCmd.AddCommand(networkStopCmd)
	networkStopCmd.MarkFlagRequired("rootdir")

	networkCmd.AddCommand(networkStatusCmd)
	networkStatusCmd.MarkFlagRequired("rootdir")

	networkCmd.AddCommand(networkDeleteCmd)
	networkDeleteCmd.MarkFlagRequired("rootdir")

	networkCmd.AddCommand(networkPregenCmd)
	networkPregenCmd.Flags().StringVarP(&networkTemplateFile, "template", "t", "", "Specify the path to the template file for the network")
	networkPregenCmd.Flags().StringVarP(&pregenDir, "pregendir", "p", "", "Specify the path to the directory to export genesis.json, root and partkey files. This should only be used on private networks.")
	networkPregenCmd.MarkFlagRequired("pregendir")
	// Hide rootdir flag as it is unused and will error if used with this command.
	networkPregenCmd.SetHelpFunc(func(command *cobra.Command, strings []string) {
		_ = command.Flags().MarkHidden("rootdir")
		command.Parent().HelpFunc()(command, strings)
	})
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

//go:embed defaultNetworkTemplate.json
var defaultNetworkTemplate string

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

		var templateReader io.Reader

		if networkTemplateFile == "" {
			templateReader = strings.NewReader(defaultNetworkTemplate)
		} else {
			networkTemplateFile, err = filepath.Abs(networkTemplateFile)
			if err != nil {
				panic(err)
			}
			file, osErr := os.Open(networkTemplateFile)
			if osErr != nil {
				reportErrorf(errorCreateNetwork, osErr)
			}

			defer file.Close()
			templateReader = file
		}

		// Make sure target directory does not exist or is empty
		if util.FileExists(networkRootDir) && !util.IsEmpty(networkRootDir) {
			reportErrorf(infoNetworkAlreadyExists, networkRootDir)
		}

		// If pregendir is specified, copy files over
		if pregenDir != "" {
			pregenDir, err = filepath.Abs(pregenDir)
			if err != nil {
				panic(err)
			}
			err = util.CopyFolder(pregenDir, networkRootDir)
			if err != nil {
				panic(err)
			}
		}

		binDir, err := util.ExeDir()
		if err != nil {
			panic(err)
		}

		dataDir := datadir.MaybeSingleDataDir()
		var consensus config.ConsensusProtocols
		if dataDir != "" {
			// try to load the consensus from there. If there is none, we can just use the built in one.
			consensus, _ = config.PreloadConfigurableConsensusProtocols(dataDir)
		}

		var overrides []netdeploy.TemplateOverride
		if devModeOverride {
			overrides = append(overrides, netdeploy.OverrideDevMode)
		}
		network, err := netdeploy.CreateNetworkFromTemplate(networkName, networkRootDir, templateReader, binDir, !noImportKeys, nil, consensus, overrides...)
		if err != nil {
			if noClean {
				reportInfof(" ** failed ** - Preserving network rootdir '%s'", networkRootDir)
			} else {
				os.RemoveAll(networkRootDir) // Don't leave partial network directory if create failed
			}
			reportErrorf(errorCreateNetwork, err)
		}

		reportInfof(infoNetworkCreated, network.Name(), networkRootDir)

		if startOnCreation {
			network, binDir := getNetworkAndBinDir()
			err := network.Start(binDir, false)
			if err != nil {
				reportErrorf(errorStartingNetwork, err)
			}
			reportInfof(infoNetworkStarted, networkRootDir)
		}
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

var networkPregenCmd = &cobra.Command{
	Use:   "pregen",
	Short: "Pregenerate private network",
	Long:  "Pregenerates the root and participation keys for a private network. The pregen directory can then be passed to the 'goal network create' to start the network more quickly.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		var err error
		if networkRootDir != "" {
			reportErrorf("This command does not take a network directory as an argument. Use --pregendir flag instead.")
		}

		pregenDir, err = filepath.Abs(pregenDir)
		if err != nil {
			panic(err)
		}

		var templateReader io.Reader

		if networkTemplateFile == "" {
			templateReader = strings.NewReader(defaultNetworkTemplate)
		} else {
			networkTemplateFile, err = filepath.Abs(networkTemplateFile)
			if err != nil {
				panic(err)
			}
			file, osErr := os.Open(networkTemplateFile)
			if osErr != nil {
				reportErrorf(errorCreateNetwork, osErr)
			}

			defer file.Close()
			templateReader = file
		}

		// Make sure target directory does not exist or is empty
		if util.FileExists(pregenDir) && !util.IsEmpty(pregenDir) {
			reportErrorf(infoNetworkAlreadyExists, pregenDir)
		}

		var template netdeploy.NetworkTemplate
		err = netdeploy.LoadTemplateFromReader(templateReader, &template)
		if err != nil {
			reportErrorf("Error in loading template: %v\n", err)
		}

		dataDir := datadir.MaybeSingleDataDir()
		var consensus config.ConsensusProtocols
		if dataDir != "" {
			// try to load the consensus from there. If there is none, we can just use the built in one.
			consensus, _ = config.PreloadConfigurableConsensusProtocols(dataDir)
		}
		if err = template.Validate(); err != nil {
			reportErrorf("Error in template validation: %v\n", err)
		}

		err = gen.GenerateGenesisFiles(template.Genesis, config.Consensus.Merge(consensus), pregenDir, os.Stdout)
		if err != nil {
			reportErrorf("Cannot write genesis files: %s", err)
		}
	},
}
