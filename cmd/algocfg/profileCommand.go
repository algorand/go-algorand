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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/cmd/util/datadir"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/util/codecs"
)

// configUpdater updates the provided config for non-defaults in a given profile
type configUpdater struct {
	updateFunc  func(cfg config.Local) config.Local
	description string
}

var (
	development = configUpdater{
		description: "Build on Algorand.",
		updateFunc: func(cfg config.Local) config.Local {
			cfg.EnableExperimentalAPI = true
			cfg.EnableDeveloperAPI = true
			cfg.MaxAcctLookback = 256
			cfg.EnableTxnEvalTracer = true
			cfg.DisableAPIAuth = true
			return cfg
		},
	}

	conduit = configUpdater{
		description: "Provide data for the Conduit tool.",
		updateFunc: func(cfg config.Local) config.Local {
			cfg.EnableFollowMode = true
			cfg.MaxAcctLookback = 64
			cfg.CatchupParallelBlocks = 64
			return cfg
		},
	}

	participation = configUpdater{
		description: "Participate in consensus or simply ensure chain health by validating blocks.",
		updateFunc: func(cfg config.Local) config.Local {
			return cfg
		},
	}

	wsRelay = configUpdater{
		description: "Relay consensus messages across the ws network and support recent catchup.",
		updateFunc: func(cfg config.Local) config.Local {
			cfg.MaxBlockHistoryLookback = 22000 // Enough to support 2 catchpoints with some wiggle room for nodes to catch up from the older one
			cfg.CatchpointFileHistoryLength = 3
			cfg.CatchpointTracking = 2
			cfg.EnableLedgerService = true
			cfg.EnableBlockService = true
			cfg.NetAddress = ":4160"
			return cfg
		},
	}

	archival = configUpdater{
		description: "Store the full chain history and support full catchup.",
		updateFunc: func(cfg config.Local) config.Local {
			cfg.Archival = true
			cfg.EnableLedgerService = true
			cfg.EnableBlockService = true
			cfg.NetAddress = ":4160"
			cfg.EnableGossipService = false
			return cfg
		},
	}

	hybridRelay = configUpdater{
		description: "Relay consensus messages across both ws and p2p networks, also support recent catchup.",
		updateFunc: func(cfg config.Local) config.Local {
			// WS relay config defaults
			cfg.MaxBlockHistoryLookback = 22000 // Enough to support 2 catchpoints with some wiggle room for nodes to catch up from the older one
			cfg.CatchpointFileHistoryLength = 3
			cfg.CatchpointTracking = 2
			cfg.EnableLedgerService = true
			cfg.EnableBlockService = true
			cfg.NetAddress = ":4160"
			// This should be set to the public address of the node if public access is desired
			cfg.PublicAddress = config.PlaceholderPublicAddress

			// P2P config defaults
			cfg.EnableP2PHybridMode = true
			cfg.P2PHybridNetAddress = ":4190"
			cfg.EnableDHTProviders = true
			return cfg
		},
	}

	hybridArchival = configUpdater{
		description: "Store the full chain history, support full catchup, P2P enabled, discoverable via DHT.",
		updateFunc: func(cfg config.Local) config.Local {
			cfg.Archival = true
			cfg.EnableLedgerService = true
			cfg.EnableBlockService = true
			cfg.NetAddress = ":4160"
			cfg.EnableGossipService = false
			// This should be set to the public address of the node
			cfg.PublicAddress = config.PlaceholderPublicAddress

			// P2P config defaults
			cfg.EnableP2PHybridMode = true
			cfg.P2PHybridNetAddress = ":4190"
			cfg.EnableDHTProviders = true
			return cfg
		},
	}

	hybridClient = configUpdater{
		description: "Participate in consensus or simply ensure chain health by validating blocks and supporting P2P traffic propagation.",
		updateFunc: func(cfg config.Local) config.Local {

			// P2P config defaults
			cfg.EnableP2PHybridMode = true
			cfg.EnableDHTProviders = true
			return cfg
		},
	}

	// profileNames are the supported pre-configurations of config values
	profileNames = map[string]configUpdater{
		"participation":  participation,
		"conduit":        conduit,
		"wsRelay":        wsRelay,
		"archival":       archival,
		"development":    development,
		"hybridRelay":    hybridRelay,
		"hybridArchival": hybridArchival,
		"hybridClient":   hybridClient,
	}

	forceUpdate bool
)

func init() {
	rootCmd.AddCommand(profileCmd)
	profileCmd.AddCommand(setProfileCmd)
	setProfileCmd.Flags().BoolVarP(&forceUpdate, "yes", "y", false, "Force updates to be written")
	profileCmd.AddCommand(printProfileCmd)
	profileCmd.AddCommand(listProfileCmd)
}

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Generate config.json file from a profile.",
	Long: `Initialize algod config.json files based on a usage profile.

The config file generated by these profiles can be used as a starting point
for a nodes configuration. The defaults for a given profile should be treated
as supplemental to the documentation, you should review the documentation to
understand what the settings are doing.

For more details about configuration settings refer to the developer portal:
https://developer.algorand.org/docs/run-a-node/reference/config/

Profiles are subject to change or removal.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.HelpFunc()(cmd, args)
	},
}

var listProfileCmd = &cobra.Command{
	Use:   "list",
	Short: "A list of valid config profiles and a short description.",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		longest := 0
		for key := range profileNames {
			if len(key) > longest {
				longest = len(key)
			}
		}

		for key, value := range profileNames {
			reportInfof("%-*s  %s", longest, key, value.description)
		}
	},
}

var printProfileCmd = &cobra.Command{
	Use:   "print",
	Short: "Print config.json to stdout.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := getConfigForArg(args[0])
		if err != nil {
			reportErrorf("%v", err)
		}
		err = codecs.WriteNonDefaultValues(os.Stdout, cfg, config.GetDefaultLocal(), nil)
		if err != nil {
			reportErrorf("Error writing config file to stdout: %s", err)
		}
		fmt.Fprintf(os.Stdout, "\n")
	},
}

var setProfileCmd = &cobra.Command{
	Use:   "set",
	Short: "Set config.json file from a profile.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		datadir.OnDataDirs(func(dataDir string) {
			cfg, err := getConfigForArg(args[0])
			if err != nil {
				reportErrorf("%v", err)
			}
			file := filepath.Join(dataDir, config.ConfigFilename)
			if _, statErr := os.Stat(file); !forceUpdate && statErr == nil {
				fmt.Printf("A config.json file already exists at %s\nWould you like to overwrite it? (Y/n)", file)
				reader := bufio.NewReader(os.Stdin)
				resp, readErr := reader.ReadString('\n')
				resp = strings.TrimSpace(resp)
				if readErr != nil {
					reportErrorf("Failed to read response: %v", readErr)
				}
				if strings.ToLower(resp) == "n" {
					reportInfof("Exiting without overwriting existing config.")
					return
				}
			}
			err = codecs.SaveNonDefaultValuesToFile(file, cfg, config.GetDefaultLocal(), nil)
			if err != nil {
				reportErrorf("Error saving updated config file '%s' - %s", file, err)
			}
		})
	},
}

// getConfigForArg returns a Local config w/ options updated acorrding to the profil specified by configType
func getConfigForArg(configType string) (config.Local, error) {
	cfg := config.GetDefaultLocal()
	if updater, ok := profileNames[configType]; ok {
		return updater.updateFunc(cfg), nil
	}

	var names []string
	for name := range profileNames {
		names = append(names, name)
	}
	return config.Local{}, fmt.Errorf("unknown profile provided: '%s' is not in list of valid profiles: %s", configType, strings.Join(names, ", "))
}
