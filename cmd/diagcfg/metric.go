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
)

var (
	dataDir string
)

func init() {
	metricCmd.AddCommand(metricStatusCmd)
	metricCmd.AddCommand(metricEnableCmd)
	metricCmd.AddCommand(metricDisableCmd)

	// override the data directory, if provided in the command.
	metricCmd.PersistentFlags().StringVarP(&dataDir, "dataDir", "d", os.ExpandEnv("$ALGORAND_DATA"), "Data directory")

}

var metricCmd = &cobra.Command{
	Use:   "metric -d dataDir",
	Short: "Control and manage Algorand metrics",
	Long:  `Enable/disable and configure Algorand remote logging`,
	Run:   metricStatusCmd.Run,
}

var metricStatusCmd = &cobra.Command{
	Use:   "status -d dataDir",
	Short: "Print the node's metric status",
	Long:  `Print the node's metric status`,
	Run: func(cmd *cobra.Command, args []string) {
		actualConfigPath, err := getConfigFilePath()
		if err != nil {
			fmt.Printf(metricNoConfig, fmt.Sprintf("%v", err))
			return
		}
		localConfig, err := config.LoadConfigFromDisk(actualConfigPath)
		if err != nil {
			fmt.Printf(metricConfigReadingFailed, fmt.Sprintf("%v", err))
			return
		}
		if localConfig.EnableMetricReporting {
			fmt.Printf(metricReportingStatus, "enabled")
		} else {
			fmt.Printf(metricReportingStatus, "disabled")
		}
	},
}

var metricEnableCmd = &cobra.Command{
	Use:   "enable -d dataDir",
	Short: "Enable metric collection on node",
	Long:  `Enable metric collection on node`,
	Run: func(cmd *cobra.Command, args []string) {
		metricEnableDisable(true)
	},
}

var metricDisableCmd = &cobra.Command{
	Use:   "disable -d dataDir",
	Short: "Disable metric collection on node",
	Long:  `Disable metric collection on node`,
	Run: func(cmd *cobra.Command, args []string) {
		metricEnableDisable(false)
	},
}

func metricEnableDisable(enable bool) {
	actualConfigPath, err := getConfigFilePath()
	if err != nil {
		fmt.Printf(metricNoConfig, fmt.Sprintf("%v", err))
		return
	}
	localConfig, err := config.LoadConfigFromDisk(actualConfigPath)
	if err != nil {
		fmt.Printf(metricConfigReadingFailed, fmt.Sprintf("%v", err))
		return
	}
	localConfig.EnableMetricReporting = enable
	err = localConfig.SaveToDisk(actualConfigPath)
	if err != nil {
		fmt.Printf(metricSaveConfigFailed, fmt.Sprintf("%v", err))
	}
	return
}

func getConfigFilePath() (string, error) {
	maybeUpdateDataDirFromEnv()
	configFilePath := dataDir
	if configFilePath == "" {
		return "", fmt.Errorf("%s", metricDataDirectoryEmpty)
	}

	// check if directory exists.
	if configDirFile, err := os.Open(configFilePath); err == nil {
		configDirFile.Close()
	} else {
		return "", err
	}

	// check if actual file exists.
	if configFile, err := os.Open(filepath.Join(configFilePath, config.ConfigFilename)); err == nil {
		configFile.Close()
	} else {
		return "", err
	}
	return configFilePath, nil
}
