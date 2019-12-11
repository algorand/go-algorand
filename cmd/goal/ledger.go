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
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

var (
	rawFilename string
)

func init() {
	ledgerCmd.AddCommand(supplyCmd)
	ledgerCmd.AddCommand(rawBlockCmd)

	rawBlockCmd.Flags().StringVarP(&rawFilename, "out", "o", stdoutFilenameValue, "The filename to dump the raw block to (if not set, use stdout)")
}

var ledgerCmd = &cobra.Command{
	Use:   "ledger",
	Short: "Access ledger-related details",
	Long:  "Access ledger-related details",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		// If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

var supplyCmd = &cobra.Command{
	Use:   "supply",
	Short: "Show ledger token supply",
	Long:  "Show ledger token supply. All units are in microAlgos.",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, _ []string) {
		dataDir := ensureSingleDataDir()
		response, err := ensureAlgodClient(dataDir).LedgerSupply()
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		fmt.Printf("Round: %v\nTotal Money: %v microAlgos\nOnline Money: %v microAlgos\n", response.Round, response.TotalMoney, response.OnlineMoney)
	},
}

var rawBlockCmd = &cobra.Command{
	Use:   "rawblock",
	Short: "Dump the raw, encoded msgpack block to a file or stdout",
	Long:  "Dump the raw, encoded msgpack block to a file or stdout",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		round, err := strconv.ParseUint(args[0], 10, 64)
		if err != nil {
			reportErrorf(errParsingRoundNumber, err)
		}

		dataDir := ensureSingleDataDir()
		client := ensureAlgodClient(dataDir)
		response, err := client.RawBlock(round)
		if err != nil {
			reportErrorf(errorRequestFail, err)
		}

		// If rawFilename flag was not set, the default value '-' will write to stdout
		err = writeFile(rawFilename, response, 0600)
		if err != nil {
			reportErrorf(fileWriteError, rawFilename, err)
		}
	},
}
