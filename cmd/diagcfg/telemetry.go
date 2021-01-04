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
	"github.com/algorand/go-algorand/logging"
)

var (
	nodeName string
	uri      string
	//dataDir  string // declared in ./metric.go
)

func init() {
	telemetryCmd.AddCommand(telemetryStatusCmd)
	telemetryCmd.AddCommand(telemetryEnableCmd)
	telemetryCmd.AddCommand(telemetryDisableCmd)
	telemetryCmd.AddCommand(telemetryNameCmd)
	telemetryCmd.AddCommand(telemetryEndpointCmd)

	telemetryCmd.PersistentFlags().StringVarP(&dataDir, "datadir", "d", "", "Data directory for the node")
	// Enable Logging : node name
	telemetryNameCmd.Flags().StringVarP(&nodeName, "name", "n", "", "Friendly-name to use for node")
	telemetryEndpointCmd.Flags().StringVarP(&uri, "endpoint", "e", "", "Endpoint's URI")
}

// If we didn't get a value from -d, try $ALGORAND_DATA
func maybeUpdateDataDirFromEnv() {
	if dataDir == "" {
		dataDir = os.Getenv("ALGORAND_DATA")
	}
}

func readTelemetryConfigOrExit() logging.TelemetryConfig {
	maybeUpdateDataDirFromEnv()
	cfg, err := logging.ReadTelemetryConfigOrDefault(&dataDir, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, telemetryConfigReadError, err)
		os.Exit(1)
	}
	return cfg
}

func saveTelemetryConfig(cfg logging.TelemetryConfig) {
	globalPath, err := config.GetConfigFilePath(logging.TelemetryConfigFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	if dataDir != "" {
		// Save to dataDir and only update global config {Name,GUID}
		ddPath := filepath.Join(dataDir, logging.TelemetryConfigFilename)
		err := cfg.Save(ddPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, pathErrFormat, ddPath, err)
			os.Exit(1)
		}
		gcfg, err := logging.LoadTelemetryConfig(globalPath)
		if err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, pathErrFormat, globalPath, err)
			os.Exit(1)
		}
		gcfg.Name = cfg.Name
		gcfg.GUID = cfg.GUID
		err = gcfg.Save(globalPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, pathErrFormat, globalPath, err)
			os.Exit(1)
		}
	} else {
		// write to global config
		err = cfg.Save(globalPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, pathErrFormat, globalPath, err)
			os.Exit(1)
		}
	}
}

var telemetryCmd = &cobra.Command{
	Use:   "telemetry",
	Short: "Control and manage Algorand logging",
	Long:  `Enable/disable and configure Algorand remote logging`,
	Run:   telemetryStatusCmd.Run,
}

var telemetryStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Print the node's telemetry status",
	Long:  `Print the node's telemetry status`,
	Run: func(cmd *cobra.Command, args []string) {
		maybeUpdateDataDirFromEnv()
		cfg, err := logging.ReadTelemetryConfigOrDefault(&dataDir, "")

		// If error loading config, can't disable / no need to disable
		if err != nil {
			fmt.Println(err)
			fmt.Println(loggingNotConfigured)
		} else if cfg.Enable == false {
			fmt.Println(loggingNotEnabled)
		} else {
			fmt.Printf(loggingEnabled, cfg.Name, cfg.GUID)
		}
	},
}

var telemetryEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable Algorand remote logging",
	Long:  `Enable Algorand remote logging`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := readTelemetryConfigOrExit()

		cfg.Enable = true
		saveTelemetryConfig(cfg)
		fmt.Printf("Telemetry logging enabled: Name = %s, Guid = %s\n", cfg.Name, cfg.GUID)
	},
}

var telemetryDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable Algorand remote logging",
	Long:  `Disable Algorand remote logging`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := readTelemetryConfigOrExit()

		cfg.Enable = false
		saveTelemetryConfig(cfg)
		fmt.Printf("Telemetry logging disabled: Name = %s, Guid = %s\n", cfg.Name, cfg.GUID)
	},
}

var telemetryNameCmd = &cobra.Command{
	Use:   "name -n nodeName",
	Short: "Enable Algorand remote logging",
	Long:  `Enable Algorand remote logging with specified node name`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := readTelemetryConfigOrExit()
		cfg.Enable = true
		if len(nodeName) > 0 {
			cfg.Name = nodeName
		}
		saveTelemetryConfig(cfg)
		fmt.Printf("Telemetry logging: Name = %s, Guid = %s\n", cfg.Name, cfg.GUID)
	},
}

var telemetryEndpointCmd = &cobra.Command{
	Use:   "endpoint -e <url>",
	Short: "Sets the \"URI\" property",
	Long:  `Sets the "URI" property in the telemetry configuration`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := readTelemetryConfigOrExit()
		cfg.URI = uri
		saveTelemetryConfig(cfg)
		fmt.Printf("Telemetry logging: Name = %s, Guid = %s, URI = %s\n", cfg.Name, cfg.GUID, cfg.URI)
	},
}
