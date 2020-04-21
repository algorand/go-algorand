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

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "tealdbg",
	Short: "Algorand TEAL Debugger",
	Long: `Debug a local or remote TEAL code in controlled environment
with Web or Chrome DevTools frontends`,
	Run: func(cmd *cobra.Command, args []string) {
		//If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug a local TEAL program",
	Long:  `Debug a local TEAL program in controlled environment`,
	Run: func(cmd *cobra.Command, args []string) {
		debugLocal(args)
		// //If no arguments passed, we should fallback to help
		// cmd.HelpFunc()(cmd, args)
	},
}

var remoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Debug remote TEAL program",
	Long:  `Start the server and wait upcoming debug connections from remote TEAL evaluator`,
	Run: func(cmd *cobra.Command, args []string) {
		debugRemote()
	},
}

var frontend frontendValue

type frontendValue struct {
	value string
}

func (f *frontendValue) String() string {
	return f.value
}

func (f *frontendValue) Type() string {
	return "string"
}

func (f *frontendValue) Set(other string) error {
	allowed := map[string]bool{
		"web": true,
		"cdt": true,
	}
	if !allowed[other] {
		return fmt.Errorf("value %s not allowed", other)
	}

	f.value = other

	return nil
}

func (f *frontendValue) MakeAdapter(router *mux.Router, appAddress string) (da DebugAdapter) {
	switch f.value {
	case "web":
		wa := &WebPageAdapter{}
		wa.Setup(router)
		return wa
	case "cdt":
		fallthrough
	default:
		cdt := &CDTAdapter{}
		cdt.Setup(&CDTSetupParams{router, appAddress})
		return cdt
	}
}

func init() {
	// rootCmd.PersistentFlags().StringVarP(&frontend, "frontend", "f", "cdt", "Frontend to use: web, cdt")
	rootCmd.PersistentFlags().VarP(&frontend, "frontend", "f", "Frontend to use: web, cdt")
	rootCmd.AddCommand(debugCmd)
	rootCmd.AddCommand(remoteCmd)
}

func debugRemote() {
	ds := makeDebugServer(&frontend)
	ds.enableRemoteHook()

	ds.startDebugging()
}

func debugLocal(args []string) {
	ds := makeDebugServer(&frontend)

	ds.startDebugging()
}
