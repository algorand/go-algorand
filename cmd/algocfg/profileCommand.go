// Copyright (C) 2019-2023 Algorand, Inc.
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
	"bufio"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"strings"

	"github.com/algorand/go-algorand/cmd/util/datadir"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/util/codecs"
)

var (
	profileNames = []string{"relay", "default"}
)

func init() {
	rootCmd.AddCommand(profileCmd)
	profileCmd.AddCommand(setProfileCmd)
	profileCmd.AddCommand(listProfileCmd)
}

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manipulate config profiles",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.HelpFunc()(cmd, args)
	},
}

var listProfileCmd = &cobra.Command{
	Use:   "list",
	Short: "List config profiles",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		reportInfof("%v", strings.Join(profileNames, " "))
	},
}

var setProfileCmd = &cobra.Command{
	Use:   "set",
	Short: "Set preconfigured config defaults",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		datadir.OnDataDirs(func(dataDir string) {
			cfg, err := getConfigForArg(args[0])
			if err != nil {
				reportErrorf("%v", err)
			}
			file := filepath.Join(dataDir, config.ConfigFilename)
			if _, err := os.Stat(file); err == nil {
				fmt.Printf("A config.json file already exists for this data directory. Would you like to overwrite it? (Y/n)")
				reader := bufio.NewReader(os.Stdin)
				resp, err := reader.ReadString('\n')
				resp = strings.TrimSpace(resp)
				if err != nil {
					reportErrorf("Failed to read response: %v", err)
				}
				if strings.ToLower(resp) != "y" {
					reportInfof("Exiting without overwriting existing config.")
					return
				}
			}
			err = codecs.SaveNonDefaultValuesToFile(file, cfg, config.GetDefaultLocal(), nil, true)
			if err != nil {
				reportErrorf("Error saving updated config file '%s' - %s", file, err)
			}
		})
	},
}

func getConfigForArg(configType string) (config.Local, error) {
	cfg := config.GetDefaultLocal()
	switch configType {
	case "relay":
		cfg.Archival = true
		cfg.EnableLedgerService = true
		cfg.EnableBlockService = true
		cfg.NetAddress = "4160"
		return cfg, nil
	case "default":
		return config.GetDefaultLocal(), nil
	default:
		return config.Local{}, fmt.Errorf("invalid profile type %v", configType)
	}
}
