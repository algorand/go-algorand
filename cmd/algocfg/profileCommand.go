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
	"fmt"
	"github.com/spf13/cobra"
	"path/filepath"
	"strings"

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
		onDataDirs(func(dataDir string) {
			cfg, err := getConfigForArg(args[0])
			if err != nil {
				reportErrorf("%v", err)
			}
			file := filepath.Join(dataDir, config.ConfigFilename)
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
		cfg.EnableBlockService = false
		cfg.NetAddress = "4160"
		return cfg, nil
	case "default":
		return config.GetDefaultLocal(), nil
	default:
		return config.Local{}, fmt.Errorf("invalid profile type %v", configType)
	}
}
