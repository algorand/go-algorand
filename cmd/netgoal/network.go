// Copyright (C) 2019-2020 Algorand, Inc.
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
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/netdeploy/remote"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/codecs"
)

var networkRootDir string
var networkRecipeFile string
var networkName string
var networkGenesisVersionModifier string
var miscStringStringTokens []string

var networkUseGenesisFiles bool
var networkIgnoreExistingDir bool

func init() {
	rootCmd.AddCommand(networkBuildCmd)

	rootCmd.PersistentFlags().StringVarP(&networkRootDir, "rootdir", "r", "", "Root directory for the private network directories")
	rootCmd.MarkPersistentFlagRequired("rootdir")
	networkBuildCmd.Flags().StringVarP(&networkName, "network", "n", "", "Specify the name to use for the network (overrides config file)")
	rootCmd.MarkPersistentFlagRequired("network")

	networkBuildCmd.Flags().StringVar(&networkRecipeFile, "recipe", "", "Specify the path of a Recipe file to use")
	networkBuildCmd.MarkFlagRequired("recipe")

	networkBuildCmd.Flags().BoolVarP(&networkUseGenesisFiles, "use-existing-files", "e", false, "Use existing genesis files.")
	networkBuildCmd.Flags().BoolVarP(&networkIgnoreExistingDir, "force", "f", false, "Force generation into existing directory.")
	networkBuildCmd.Flags().StringSliceVarP(&miscStringStringTokens, "val", "v", nil, "name=value, may be reapeated")

	rootCmd.PersistentFlags().StringVarP(&networkGenesisVersionModifier, "modifier", "m", "", "Override Genesis Version Modifier (eg 'v1')")
}

var networkBuildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build network deployment artifacts",
	Long:  `Build network deployment artifacts for modifying before deploying`,
	Run: func(cmd *cobra.Command, args []string) {
		// Similar to `goal network create`, we need to generate a genesis.json and wallets and store somewhere.
		// We have a lot more parameters to define, so we'll support a subset of parameters on cmdline but
		// support a config file with all parameters for complex configurations.

		err := runBuildNetwork()
		if err != nil {
			reportErrorf("error building network files: %v\n", err)
		}
	},
}

func runBuildNetwork() (err error) {
	networkRootDir, err := filepath.Abs(networkRootDir)
	if err != nil {
		return
	}
	// Make sure target directory doesn't already exist
	exists := util.FileExists(networkRootDir)
	if exists {
		if !networkIgnoreExistingDir {
			return fmt.Errorf(errDirectoryAlreadyExists, networkRootDir)
		}

		// If directory exists but we're not reusing its files, delete it.
		if !networkUseGenesisFiles {
			os.RemoveAll(networkRootDir)
		}
	}

	if networkRecipeFile, err = filepath.Abs(networkRecipeFile); err != nil {
		return
	}

	var r recipe
	if err = codecs.LoadObjectFromFile(networkRecipeFile, &r); err != nil {
		return fmt.Errorf("unable to parse recipe file '%s' : %v", networkRecipeFile, err)
	}

	templateBaseDir := filepath.Dir(networkRecipeFile)

	configFile := resolveFile(r.ConfigFile, templateBaseDir)

	buildConfig, err := remote.LoadBuildConfig(configFile)
	if err != nil {
		return fmt.Errorf("error loading Build Config file: %v", err)
	}
	for _, kev := range miscStringStringTokens {
		ab := strings.SplitN(kev, "=", 2)
		buildConfig.MiscStringString = append(buildConfig.MiscStringString, "{{"+ab[0]+"}}", ab[1])
	}

	networkTemplateFile := resolveFile(r.NetworkFile, templateBaseDir)
	networkTemplateFile, err = filepath.Abs(networkTemplateFile)
	if err != nil {
		return fmt.Errorf("error resolving network template file '%s' to full path: %v", networkTemplateFile, err)
	}

	netCfg, err := remote.InitDeployedNetworkConfig(networkTemplateFile, buildConfig)
	if err != nil {
		return fmt.Errorf("error loading Network Config file '%s': %v", networkTemplateFile, err)
	}

	genesisDataFile := resolveFile(r.GenesisFile, templateBaseDir)
	topologyFile := resolveFile(r.TopologyFile, templateBaseDir)
	net, err := netCfg.ResolveDeployedNetworkConfig(genesisDataFile, topologyFile)
	if err != nil {
		return fmt.Errorf("error resolving Network Config file: %v", err)
	}

	// If network name specified, use that
	if networkName != "" {
		buildConfig.NetworkName = networkName
		net.GenesisData.NetworkName = networkName
	}

	if networkGenesisVersionModifier != "" {
		net.GenesisData.VersionModifier = networkGenesisVersionModifier
	}

	net.SetUseExistingGenesisFiles(networkUseGenesisFiles)
	err = net.Validate(buildConfig, networkRootDir)
	if err != nil {
		return fmt.Errorf("error validating Network Config file: %v", err)
	}

	hostTemplatesFile := resolveFile(r.HostTemplatesFile, templateBaseDir)
	hostTemplates, err := remote.LoadHostTemplates(hostTemplatesFile)
	if err != nil {
		return fmt.Errorf("error loading HostTemplates file '%s': %v", hostTemplatesFile, err)
	}

	err = net.ValidateTopology(hostTemplates)
	if err != nil {
		return fmt.Errorf("error validating Topology: %v", err)
	}

	// OK, everything has been validated.  Time to generate.

	defer func() {
		if err != nil {
			os.RemoveAll(networkRootDir) // Don't leave partial network directory if create failed
		}
	}()

	err = net.BuildNetworkFromTemplate(buildConfig, networkRootDir)
	if err != nil {
		return fmt.Errorf(errorCreateNetwork, err)
	}

	// Write the processed template file (without genesisdata / topology instances)
	netCfg.SaveToDisk(networkRootDir)

	err = net.GenerateCloudTemplate(hostTemplates, networkRootDir)
	if err != nil {
		return fmt.Errorf("error generating cloud template file: %v", err)
	}

	reportInfof(infoNetworkCreated, networkName, networkRootDir)

	return nil
}

func resolveFile(filename string, baseDir string) string {
	if filepath.IsAbs(filename) {
		return filename
	}

	// Assume path is relative to the directory of the template file
	return filepath.Join(baseDir, filename)
}
