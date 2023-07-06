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
	"os"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"

	"github.com/spf13/cobra"
)

var networkInterface string
var debuggerPort uint64
var simulationResultFileName string

// maybe pass in sourcemap together with appID in format
// sourcemap.....,100,101,102
// such that the sourcemap will not mismatch with appID
var sourcemapFileNamesAndAppIDs []string

// SourcemapWithAppID is the struct containing the sourcemap and appIDs
// retrieved from the commandline argument
type SourcemapWithAppID struct {
	sourcemap logic.SourceMap
	appIDs    []basics.AppIndex
}

var AppIDtoSourcemap map[basics.AppIndex]*logic.SourceMap

func init() {
	rootCmd.PersistentFlags().StringVar(
		&networkInterface, "listen", "127.0.0.1", "Network interface to listen to")
	rootCmd.PersistentFlags().Uint64Var(
		&debuggerPort, "port", 22015, "Debugger port to listen to")
	rootCmd.PersistentFlags().StringVar(
		&simulationResultFileName, "simulation-trace-file", "",
		"Simulate trace file to start debug session")
	rootCmd.PersistentFlags().StringArrayVar(
		&sourcemapFileNamesAndAppIDs, "sourcemap-file", nil,
		"Sourcemap file name together with appIDs with this sourcemap")
}

var rootCmd = &cobra.Command{
	Use:   "tealdap",
	Short: "Algorand TEAL Debugger (supporting Debug Adapter Protocol)",
	Long:  `Debug a ...`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.HelpFunc()(cmd, args)
	},
}

// TODO should consider a few inputs
// - sourcemap (together with source?)
// - app-id(s) tied to the source map
// - simulation result?

func main() {
	fmt.Println("start debugging")
	// TODO haven't start server yet, was thinking of testing:
	// how to bring up the server for testing, and bring down after the test

	// I suppose once we run `launch`, namely dap.LaunchResponse,
	// the server just run all the way to end (if we let through all the stop points).
	os.Exit(0)
}
