// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/sqlitedriver"
	"github.com/algorand/go-algorand/util/db"
)

var ledgerTrackerFilename string
var ledgerTrackerStaging bool

func init() {
	databaseCmd.Flags().StringVarP(&ledgerTrackerFilename, "tracker", "t", "", "Specify the ledger tracker file name ( i.e. ./ledger.tracker.sqlite )")
	databaseCmd.Flags().StringVarP(&outFileName, "output", "o", "", "Specify an outfile for the dump ( i.e. ledger.dump.txt )")
	databaseCmd.Flags().BoolVarP(&ledgerTrackerStaging, "staging", "s", false, "Specify whether to look in the catchpoint staging or regular tables. (default false)")
	databaseCmd.AddCommand(checkCmd)

	checkCmd.Flags().StringVarP(&ledgerTrackerFilename, "tracker", "t", "", "Specify the ledger tracker file name ( i.e. ./ledger.tracker.sqlite )")
	checkCmd.Flags().BoolVarP(&ledgerTrackerStaging, "staging", "s", false, "Specify whether to look in the catchpoint staging or regular tables. (default false)")
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
			outFile, err = os.OpenFile(outFileName, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0755)
			if err != nil {
				reportErrorf("Unable to create file '%s' : %v", outFileName, err)
			}
			defer outFile.Close()
		}

		var version uint64
		version, err = getVersion(ledgerTrackerFilename, ledgerTrackerStaging)
		if err != nil {
			reportErrorf("Unable to read version : %v", err)
		}
		printDbVersion(ledgerTrackerStaging, version, outFile)
		err = printAccountsDatabase(ledgerTrackerFilename, ledgerTrackerStaging, ledger.CatchpointFileHeader{}, outFile, nil)
		if err != nil {
			reportErrorf("Unable to print account database : %v", err)
		}
		err = printKeyValueStore(ledgerTrackerFilename, ledgerTrackerStaging, outFile)
		if err != nil {
			reportErrorf("Unable to print key value store : %v", err)
		}
		// state proof verification can be found on tracker db version >= 10 or
		// catchpoint file version >= 7 (i.e staging tables)
		if !ledgerTrackerStaging && version < 10 || ledgerTrackerStaging && version < ledger.CatchpointFileVersionV7 {
			return
		}
		err = printStateProofVerificationContext(ledgerTrackerFilename, ledgerTrackerStaging, outFile)
		if err != nil {
			reportErrorf("Unable to print state proof verification database : %v", err)
		}
		err = printOnlineAccounts(ledgerTrackerFilename, ledgerTrackerStaging, outFile)
		if err != nil {
			reportErrorf("Unable to print online accounts : %v", err)
		}
		err = printOnlineRoundParams(ledgerTrackerFilename, ledgerTrackerStaging, outFile)
		if err != nil {
			reportErrorf("Unable to print online round params : %v", err)
		}
	},
}

func printDbVersion(staging bool, version uint64, outFile *os.File) {
	fileWriter := bufio.NewWriterSize(outFile, 1024*1024)
	defer fileWriter.Flush()

	if staging {
		fmt.Fprintf(outFile, "Catchpoint version: %d \n", version)
	} else {
		fmt.Fprintf(outFile, "Ledger db version: %d \n", version)
	}
}

func getVersion(filename string, staging bool) (uint64, error) {
	dbAccessor, err := db.MakeAccessor(filename, true, false)
	if err != nil || dbAccessor.Handle == nil {
		return 0, err
	}
	defer dbAccessor.Close()
	version, err := db.AtomicResult(&dbAccessor, func(ctx context.Context, tx *sql.Tx) (uint64, error) {
		if staging {
			// writing the version of the catchpoint file start only on ver >= CatchpointFileVersionV7.
			// in case the catchpoint version does not exists ReadCatchpointStateUint64 returns 0
			cw := sqlitedriver.NewCatchpointSQLReaderWriter(tx)
			return cw.ReadCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupVersion)
		}

		versionAsInt32, versionErr := db.GetUserVersion(ctx, tx)
		return uint64(versionAsInt32), versionErr
	})
	if err != nil {
		return 0, err
	}

	return version, nil
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
	if dbAccessor.Handle == nil {
		return fmt.Errorf("database handle is nil when opening database %s", databaseName)
	}
	defer func() {
		dbAccessor.Close()
	}()

	type trieInfo struct {
		root  crypto.Digest
		stats merkletrie.Stats
	}
	info, err := db.AtomicResult(&dbAccessor, func(ctx context.Context, tx *sql.Tx) (info trieInfo, err error) {
		committer, err := sqlitedriver.MakeMerkleCommitter(tx, ledgerTrackerStaging)
		if err != nil {
			return info, err
		}
		trie, err := merkletrie.MakeTrie(committer, trackerdb.TrieMemoryConfig)
		if err != nil {
			return info, err
		}
		info.root, err = trie.RootHash()
		if err != nil {
			return info, err
		}
		info.stats, err = trie.GetStats()
		return info, err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(outFile, " Root: %s\n", info.root)
	stats := info.stats

	fmt.Fprintf(outFile, "Merkle trie statistics:\n")
	fmt.Fprintf(outFile, " Nodes count: %d\n", stats.NodesCount)
	fmt.Fprintf(outFile, " Leaf count:  %d\n", stats.LeafCount)
	fmt.Fprintf(outFile, " Depth:       %d\n", stats.Depth)
	fmt.Fprintf(outFile, " Size:        %d\n", stats.Size)
	return nil
}
