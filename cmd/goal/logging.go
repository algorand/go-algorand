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
	"time"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
)

var (
	nodeName   string
	logChannel string
)

func init() {
	loggingCmd.AddCommand(enableCmd)
	loggingCmd.AddCommand(disableCmd)
	loggingCmd.AddCommand(loggingSendCmd)

	// Enable Logging : node name
	enableCmd.Flags().StringVarP(&nodeName, "name", "n", "", "Friendly-name to use for node")

	loggingSendCmd.Flags().StringVarP(&logChannel, "channel", "c", "", "Release channel for log file source")
}

var loggingCmd = &cobra.Command{
	Use:   "logging",
	Short: "Control and manage Algorand logging",
	Long:  `Enable/disable and configure Algorand remote logging.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintf(os.Stderr, "Warning: `goal logging` deprecated, use `diagcfg telemetry status`\n")
		dataDir := ensureSingleDataDir()
		cfg, err := logging.EnsureTelemetryConfig(&dataDir, "")

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

var enableCmd = &cobra.Command{
	Use:   "enable -n nodeName",
	Short: "Enable Algorand remote logging",
	Long:  `This will turn on remote logging. The "friendly name" for the node, used by logging, will be determined by -n nodename.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintf(os.Stderr, "Warning: `goal logging enable` deprecated, use `diagcfg telemetry enable`\n")
		dataDir := ensureSingleDataDir()
		cfg, err := logging.EnsureTelemetryConfig(&dataDir, "")
		if err != nil {
			fmt.Println(err)
			return
		}
		cfg.Enable = true
		if len(nodeName) > 0 {
			cfg.Name = nodeName
		}
		cfg.Save(cfg.FilePath)
		fmt.Printf("Logging enabled: Name = %s, Guid = %s\n", cfg.Name, cfg.GUID)
	},
}

var disableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable Algorand remote logging",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintf(os.Stderr, "Warning: `goal logging disable` deprecated, use `diagcfg telemetry disable`\n")
		dataDir := ensureSingleDataDir()
		cfg, err := logging.EnsureTelemetryConfig(&dataDir, "")

		// If error loading config, can't disable / no need to disable
		if err != nil {
			return
		}

		cfg.Enable = false
		cfg.Save(cfg.FilePath)
	},
}

var loggingSendCmd = &cobra.Command{
	Use:   "send",
	Short: "Upload logs and debugging information for analysis",
	Long:  `Upload logs and debugging information to Algorand for analysis. Ledger and wallet data are not included.`,
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		timestamp := time.Now().UTC().Format("20060102150405")

		if logChannel == "" {
			logChannel = config.GetCurrentVersion().Channel
		}

		targetFolder := filepath.Join("channel", logChannel)

		modifier := ""
		counter := uint(1)
		onDataDirs(func(dataDir string) {
			cfg, err := logging.EnsureTelemetryConfig(&dataDir, "")
			if err != nil {
				fmt.Println(err)
				return
			}
			basename := cfg.Name
			if len(basename) > 0 {
				basename = basename + "-"
			}
			dirname := filepath.Base(dataDir)
			name := basename + cfg.GUID + "_" + dirname + "-" + timestamp + modifier + ".tar.gz"

			for err := range logging.CollectAndUploadData(dataDir, name, targetFolder) {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}
			modifier = fmt.Sprintf("-%d", counter)
			counter++
		})
	},
}
