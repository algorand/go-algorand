// Copyright (C) 2019 Algorand, Inc.
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
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/shared/pingpong"
)

var dataDir string
var srcAddress string
var numAccounts uint32
var minAccountFunds uint64
var maxAmount uint64
var maxFee int64
var minFee uint64
var randomFee, noRandomFee bool
var randomAmount, noRandomAmount bool
var randomDst bool
var delayBetween string
var runTime string
var restTime string
var refreshTime string
var saveConfig bool
var useDefault bool
var quietish bool
var randomNote bool

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.PersistentFlags().StringVarP(&dataDir, "datadir", "d", "", "Data directory for the node")

	runCmd.Flags().StringVarP(&srcAddress, "src", "s", "", "Account address to use as funding source for new accounts)")
	runCmd.Flags().Uint32VarP(&numAccounts, "numaccounts", "n", 0, "The number of accounts to include in the transfers")
	runCmd.Flags().Uint64VarP(&maxAmount, "ma", "a", 0, "The (max) amount to be transferred")
	runCmd.Flags().Uint64VarP(&minAccountFunds, "minaccount", "", 0, "The minimum amount to fund a test account with")
	runCmd.Flags().Int64VarP(&maxFee, "mf", "f", -1, "The MAX fee to be used for transactions, a value of '0' tells the server to use a suggested fee.")
	runCmd.Flags().Uint64VarP(&minFee, "minf", "m", 1000, "The MIN fee to be used for randomFee transactions")
	runCmd.Flags().BoolVar(&randomAmount, "ra", false, "Set to enable random amounts (up to maxamount)")
	runCmd.Flags().BoolVar(&noRandomAmount, "nra", false, "Set to disable random amounts")
	runCmd.Flags().BoolVar(&randomFee, "rf", false, "Set to enable random fees (between minf and mf)")
	runCmd.Flags().BoolVar(&noRandomFee, "nrf", false, "Set to disable random fees")
	runCmd.Flags().BoolVar(&randomDst, "rd", false, "Send money to randomly-generated addresses")
	runCmd.Flags().StringVar(&delayBetween, "delay", "", "Delay (ms) between every transaction (0 means none)")
	runCmd.Flags().StringVar(&runTime, "run", "", "Duration of time (seconds) to run transfers before resting (0 means non-stop)")
	runCmd.Flags().StringVar(&restTime, "rest", "", "Duration of time (seconds) to rest between transfer periods (0 means no rest)")
	runCmd.Flags().StringVar(&refreshTime, "refresh", "", "Duration of time (seconds) between refilling accounts with money (0 means no refresh)")
	runCmd.Flags().BoolVar(&saveConfig, "save", false, "Save the effective configuration to disk")
	runCmd.Flags().BoolVar(&useDefault, "reset", false, "Reset to the default configuration (not read from disk)")
	runCmd.Flags().BoolVar(&quietish, "quiet", false, "quietish stdout logging")
	runCmd.Flags().BoolVar(&randomNote, "randomnote", false, "generates a random byte array between 0-1024 bytes long")
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start running the ping-pong activity",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		// Make a cache dir for wallet handle tokens
		cacheDir, err := ioutil.TempDir("", "pingpong")
		if err != nil {
			reportErrorf("Cannot make temp dir: %v\n", err)
		}

		// Get libgoal Client
		ac, err := libgoal.MakeClient(dataDir, cacheDir, libgoal.FullClient)
		if err != nil {
			panic(err)
		}

		// Prepare configuration
		var cfg pingpong.PpConfig
		cfgPath := filepath.Join(ac.DataDir(), pingpong.ConfigFilename)
		if useDefault {
			cfg = pingpong.DefaultConfig
		} else {
			cfg, err = pingpong.LoadConfigFromFile(cfgPath)
			if err != nil && !os.IsNotExist(err) {
				reportErrorf("Error loading configuration from '%s': %v\n", cfgPath, err)
			}
		}

		if srcAddress != "" {
			cfg.SrcAccount = srcAddress
		}
		if numAccounts > 0 {
			cfg.NumPartAccounts = numAccounts
		}
		if maxAmount > 0 {
			cfg.MaxAmt = maxAmount
		}
		if maxFee >= 0 {
			cfg.MaxFee = uint64(maxFee)
		}
		if minFee > 0 {
			cfg.MinFee = minFee
		}
		if minAccountFunds > 0 {
			cfg.MinAccountFunds = minAccountFunds
		}
		if randomFee {
			if cfg.MinFee > cfg.MaxFee {
				reportErrorf("Cannot use randomFee with --minf > --mf.\n")
			}
			cfg.RandomizeFee = true
		}
		if noRandomFee {
			if randomFee {
				reportErrorf("Error --rf and --nrf can't both be specified\n")
			}
			cfg.RandomizeFee = false
		}
		if randomAmount {
			cfg.RandomizeAmt = true
		}
		if noRandomAmount {
			if randomAmount {
				reportErrorf("Error --ra and --nra can't both be specified\n")
			}
			cfg.RandomizeAmt = false
		}
		cfg.RandomizeDst = randomDst
		cfg.Quiet = quietish
		if delayBetween != "" {
			val, err := strconv.ParseUint(delayBetween, 10, 32)
			if err != nil {
				reportErrorf("Invalid value specified for --delay: %v\n", err)
			}
			cfg.DelayBetweenTxn = time.Duration(uint32(val)) * time.Millisecond
		}
		if runTime != "" {
			val, err := strconv.ParseUint(runTime, 10, 32)
			if err != nil {
				reportErrorf("Invalid value specified for --run: %v\n", err)
			}
			cfg.RunTime = time.Duration(uint32(val)) * time.Second
		}
		if restTime != "" {
			val, err := strconv.ParseUint(restTime, 10, 32)
			if err != nil {
				reportErrorf("Invalid value specified for --rest: %v\n", err)
			}
			cfg.RestTime = time.Duration(uint32(val)) * time.Second
		}
		if refreshTime != "" {
			val, err := strconv.ParseUint(refreshTime, 10, 32)
			if err != nil {
				reportErrorf("Invalid value specified for --refresh: %v\n", err)
			}
			cfg.RefreshTime = time.Duration(uint32(val)) * time.Second
		}
		if randomNote {
			cfg.RandomNote = true
		}

		reportInfof("Preparing to initialize PingPong with config:\n")
		cfg.Dump(os.Stdout)

		// Initialize accounts if necessary
		accounts, cfg, err := pingpong.PrepareAccounts(ac, cfg)
		if err != nil {
			reportErrorf("Error preparing accounts for transfers: %v\n", err)
		}

		if saveConfig {
			cfg.Save(cfgPath)
		}

		reportInfof("Preparing to run PingPong with config:\n")
		cfg.Dump(os.Stdout)

		// Kick off the real processing
		pingpong.RunPingPong(context.Background(), ac, accounts, cfg)
	},
}

func reportErrorf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
	os.Exit(1)
}

func reportInfof(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}
