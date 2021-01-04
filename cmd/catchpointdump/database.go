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
	"os"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/ledger"
)

var ledgerTrackerFilename string

func init() {
	databaseCmd.Flags().StringVarP(&ledgerTrackerFilename, "tracker", "t", "", "Specify the ledger tracker file name ( i.e. ./ledger.tracker.sqlite )")
	databaseCmd.Flags().StringVarP(&outFileName, "output", "o", "", "Specify an outfile for the dump ( i.e. ledger.dump.txt )")
}

var databaseCmd = &cobra.Command{
	Use:   "database",
	Short: "Dump the given ledger tracker database",
	Long:  "Dump the given ledger tracker database",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		if ledgerTrackerFilename == "" {
			cmd.HelpFunc()(cmd, args)
			return
		}
		outFile := os.Stdout
		var err error
		if outFileName != "" {
			outFile, err = os.OpenFile(outFileName, os.O_RDWR|os.O_CREATE, 0755)
			if err != nil {
				reportErrorf("Unable to create file '%s' : %v", outFileName, err)
			}
			defer outFile.Close()
		}
		err = printAccountsDatabase(ledgerTrackerFilename, ledger.CatchpointFileHeader{}, outFile)
		if err != nil {
			reportErrorf("Unable to print account database : %v", err)
		}
	},
}
