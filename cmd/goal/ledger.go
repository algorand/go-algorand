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
	"bytes"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/protocol/transcode"
)

var (
	blockFilename  string
	rawBlock       bool
	base32Encoding bool
	strictJSON     bool
)

func init() {
	ledgerCmd.AddCommand(supplyCmd)
	ledgerCmd.AddCommand(blockCmd)

	blockCmd.Flags().StringVarP(&blockFilename, "out", "o", stdoutFilenameValue, "The filename to dump the block to (if not set, use stdout)")
	blockCmd.Flags().BoolVarP(&rawBlock, "raw", "r", false, "Format block as msgpack")
	blockCmd.Flags().BoolVar(&base32Encoding, "b32", false, "Encode binary blobs using base32 instead of base64")
	blockCmd.Flags().BoolVar(&strictJSON, "strict", false, "Strict JSON decode: turn all keys into strings")
}

var ledgerCmd = &cobra.Command{
	Use:   "ledger",
	Short: "Access ledger-related details",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		// If no arguments passed, we should fallback to help
		cmd.HelpFunc()(cmd, args)
	},
}

var supplyCmd = &cobra.Command{
	Use:   "supply",
	Short: "Show ledger token supply",
	Long:  `Show ledger token supply. All units are in microAlgos. The "Total Money" is all algos held by online+offline accounts (excludes non-participating accounts). The "Online Money" is the amount held solely by online accounts.`,
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

var blockCmd = &cobra.Command{
	Use:   "block [round number]",
	Short: "Dump a block to a file or stdout",
	Long:  "Dump a block to a file or stdout. Default behavior is to attempt to decode the raw bytes returned from algod to JSON.",
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

		// Unless the user asked for the raw block,
		// print the block encoded as JSON
		if !rawBlock {
			in := bytes.NewBuffer(response)
			out := bytes.NewBuffer(nil)
			err = transcode.Transcode(true, base32Encoding, strictJSON, in, out)
			if err != nil {
				reportErrorf(errEncodingBlockAsJSON, err)
			}
			response = out.Bytes()
		} else {
			if base32Encoding || strictJSON {
				reportErrorf(errBadBlockArgs)
			}
		}

		// If blockFilename flag was not set, the default value '-' will write to stdout
		err = writeFile(blockFilename, response, 0600)
		if err != nil {
			reportErrorf(fileWriteError, blockFilename, err)
		}
	},
}
