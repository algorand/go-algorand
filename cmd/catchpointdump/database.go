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
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/util/db"
)

var ledgerTrackerFilename string

func init() {
	databaseCmd.Flags().StringVarP(&ledgerTrackerFilename, "tracker", "t", "", "Specify the ledger tracker file name ( i.e. ./ledger.tracker.sqlite )")
	databaseCmd.Flags().StringVarP(&outFileName, "output", "o", "", "Specify an outfile for the dump ( i.e. ledger.dump.txt )")
	databaseCmd.AddCommand(checkCmd)

	checkCmd.Flags().StringVarP(&ledgerTrackerFilename, "tracker", "t", "", "Specify the ledger tracker file name ( i.e. ./ledger.tracker.sqlite )")
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

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Performs a consistency checking on the accounts merkle trie",
	Long:  "Performs a consistency checking on the accounts merkle trie",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		if ledgerTrackerFilename == "" {
			cmd.HelpFunc()(cmd, args)
			return
		}

		outFile := os.Stdout
		fmt.Fprintf(outFile, "Checking tracker database at %s.\n", ledgerTrackerFilename)
		err := checkDatabase(ledgerTrackerFilename, outFile)
		if err != nil {
			reportErrorf("Error checking database : %v", err)
		}
	},
}

func checkDatabase(databaseName string, outFile *os.File) error {
	dbAccessor, err := db.MakeAccessor(databaseName, true, false)
	if err != nil || dbAccessor.Handle == nil {
		return err
	}
	defer func() {
		dbAccessor.Close()
	}()

	var stats merkletrie.Stats
	err = dbAccessor.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		committer, err := ledger.MakeMerkleCommitter(tx, false)
		if err != nil {
			return err
		}
		trie, err := merkletrie.MakeTrie(committer, ledger.TrieMemoryConfig)
		if err != nil {
			return err
		}
		stats, err = trie.GetStats()
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(outFile, "Merkle trie statistics:\n")
	fmt.Fprintf(outFile, " Nodes count: %d\n", stats.NodesCount)
	fmt.Fprintf(outFile, " Leaf count:  %d\n", stats.LeafCount)
	fmt.Fprintf(outFile, " Depth:       %d\n", stats.Depth)
	fmt.Fprintf(outFile, " Size:        %d\n", stats.Size)
	return nil
}
