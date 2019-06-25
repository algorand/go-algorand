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

	"github.com/spf13/cobra"
)

func init() {
	ledgerCmd.AddCommand(supplyCmd)
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
