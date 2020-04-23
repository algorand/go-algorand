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
	"io/ioutil"
	"log"
	"os"
	"strings"

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
	Use:   "debug program.tok [program.teal ...]",
	Short: "Debug a local TEAL program(s)",
	Long:  `Debug a local TEAL program(s) in controlled environment`,
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

// cobraStringValue is a cobra's string flag with restricted values
type cobraStringValue struct {
	value   string
	allowed []string
}

func makeCobraStringValue(value string, others []string) *cobraStringValue {
	c := new(cobraStringValue)
	c.value = value
	c.allowed = make([]string, 0, len(others)+1)
	c.allowed = append(c.allowed, value)
	for _, s := range others {
		c.allowed = append(c.allowed, s)
	}
	return c
}

func (c *cobraStringValue) String() string { return c.value }
func (c *cobraStringValue) Type() string   { return "string" }

func (c *cobraStringValue) Set(other string) error {
	for _, s := range c.allowed {
		if other == s {
			c.value = other
			return nil
		}
	}
	return fmt.Errorf("value %s not allowed", other)
}

func (c *cobraStringValue) AllowedString() string {
	return strings.Join(c.allowed, ", ")
}

type frontendValue struct {
	*cobraStringValue
}

func (f *frontendValue) Make(router *mux.Router, appAddress string) (da DebugAdapter) {
	switch f.value {
	case "web":
		wa := MakeWebPageAdapter(router)
		return wa
	case "cdt":
		fallthrough
	default:
		cdt := MakeCDTAdapter(&CDTSetupParams{router, appAddress})
		return cdt
	}
}

type runModeValue struct {
	*cobraStringValue
}

var frontend frontendValue = frontendValue{makeCobraStringValue("cdt", []string{"web"})}
var proto string
var txnFile string
var groupIndex int
var balanceFile string
var roundNumber int
var runMode runModeValue = runModeValue{makeCobraStringValue("signature", []string{"application"})}

func init() {
	rootCmd.PersistentFlags().VarP(&frontend, "frontend", "f", "Frontend to use: "+frontend.AllowedString())

	debugCmd.Flags().StringVarP(&proto, "proto", "p", "", "Consensus protocol version for TEAL")
	debugCmd.Flags().StringVarP(&txnFile, "txn", "t", "", "Transaction(s) to evaluate TEAL on in form of json or msgpack file")
	debugCmd.Flags().IntVarP(&groupIndex, "group-index", "g", 0, "Transaction index in a txn group")
	debugCmd.Flags().StringVarP(&balanceFile, "balance", "b", "", "Balance records to evaluate stateful TEAL on in form of json or msgpack file")
	debugCmd.Flags().IntVarP(&roundNumber, "round", "r", 1095518031, "Ledger round number to evaluate stateful TEAL on")
	debugCmd.Flags().VarP(&runMode, "mode", "m", "TEAL evaluation mode: "+runMode.AllowedString())

	rootCmd.AddCommand(debugCmd)
	rootCmd.AddCommand(remoteCmd)
}

func debugRemote() {
	dp := DebugParams{Remote: true}
	ds := makeDebugServer(&frontend, &dp)

	ds.startRemote()
}

func debugLocal(args []string) {
	// simple pre-invalidation
	if len(args) == 0 {
		log.Fatalln("No program to debug")
	}
	if roundNumber < 0 {
		log.Fatalln("Invalid round")
	}

	programBlobs := make([][]byte, len(args))
	for i, file := range args {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			log.Fatalf("Error program reading %s: %s", file, err)
		}
		programBlobs[i] = data
	}

	var err error
	var txnBlob []byte
	if len(txnFile) > 0 {
		txnBlob, err = ioutil.ReadFile(txnFile)
		if err != nil {
			log.Fatalf("Error txn reading %s: %s", balanceFile, err)
		}
	}

	var balanceBlob []byte
	if len(balanceFile) > 0 {
		balanceBlob, err = ioutil.ReadFile(balanceFile)
		if err != nil {
			log.Fatalf("Error balance reading %s: %s", balanceFile, err)
		}
	}

	dp := DebugParams{
		ProgramBlobs: programBlobs,
		Proto:        proto,
		TxnBlob:      txnBlob,
		GroupIndex:   groupIndex,
		BalanceBlob:  balanceBlob,
		Round:        roundNumber,
		RunMode:      runMode.String(),
	}

	ds := makeDebugServer(&frontend, &dp)

	err = ds.startDebug()
	if err != nil {
		log.Fatalf("Debugging error: %s", err.Error())
	}
}
