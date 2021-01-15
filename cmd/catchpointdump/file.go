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
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

var tarFile string
var outFileName string

func init() {
	fileCmd.Flags().StringVarP(&tarFile, "tar", "t", "", "Specify the tar file to process")
	fileCmd.Flags().StringVarP(&outFileName, "output", "o", "", "Specify an outfile for the dump ( i.e. tracker.dump.txt )")
}

var fileCmd = &cobra.Command{
	Use:   "file",
	Short: "Specify a file to dump",
	Long:  "Specify a file to dump",
	Args:  validateNoPosArgsFn,
	Run: func(cmd *cobra.Command, args []string) {
		if tarFile == "" {
			cmd.HelpFunc()(cmd, args)
			return
		}
		tarFileBytes, err := ioutil.ReadFile(tarFile)
		if err != nil || len(tarFileBytes) == 0 {
			reportErrorf("Unable to read '%s' : %v", tarFile, err)
		}
		genesisInitState := ledger.InitState{}
		cfg := config.GetDefaultLocal()
		l, err := ledger.OpenLedger(logging.Base(), "./ledger", false, genesisInitState, cfg)
		if err != nil {
			reportErrorf("Unable to open ledger : %v", err)
		}

		defer os.Remove("./ledger.block.sqlite")
		defer os.Remove("./ledger.block.sqlite-shm")
		defer os.Remove("./ledger.block.sqlite-wal")
		defer os.Remove("./ledger.tracker.sqlite")
		defer os.Remove("./ledger.tracker.sqlite-shm")
		defer os.Remove("./ledger.tracker.sqlite-wal")
		defer l.Close()

		catchupAccessor := ledger.MakeCatchpointCatchupAccessor(l, logging.Base())
		err = catchupAccessor.ResetStagingBalances(context.Background(), true)
		if err != nil {
			reportErrorf("Unable to initialize catchup database : %v", err)
		}
		var fileHeader ledger.CatchpointFileHeader
		fileHeader, err = loadCatchpointIntoDatabase(context.Background(), catchupAccessor, tarFileBytes)
		if err != nil {
			reportErrorf("Unable to load catchpoint file into in-memory database : %v", err)
		}

		outFile := os.Stdout
		if outFileName != "" {
			outFile, err = os.OpenFile(outFileName, os.O_RDWR|os.O_CREATE, 0755)
			if err != nil {
				reportErrorf("Unable to create file '%s' : %v", outFileName, err)
			}
			defer outFile.Close()
		}

		err = printAccountsDatabase("./ledger.tracker.sqlite", fileHeader, outFile)
		if err != nil {
			reportErrorf("Unable to print account database : %v", err)
		}
	},
}

func printLoadCatchpointProgressLine(progress int, barLength int, dld int64) {
	if barLength == 0 {
		fmt.Printf(escapeCursorUp + escapeDeleteLine + "[ Done ] Loaded\n")
		return
	}

	outString := "[" + strings.Repeat(escapeSquare, progress) + strings.Repeat(escapeDot, barLength-progress) + "] Loading..."
	fmt.Printf(escapeCursorUp+escapeDeleteLine+outString+" %s\n", formatSize(dld))
}

func loadCatchpointIntoDatabase(ctx context.Context, catchupAccessor ledger.CatchpointCatchupAccessor, fileBytes []byte) (fileHeader ledger.CatchpointFileHeader, err error) {
	fmt.Printf("\n")
	printLoadCatchpointProgressLine(0, 50, 0)
	lastProgressUpdate := time.Now()
	progress := uint64(0)
	defer printLoadCatchpointProgressLine(0, 0, 0)

	reader := bytes.NewReader(fileBytes)
	tarReader := tar.NewReader(reader)
	var downloadProgress ledger.CatchpointCatchupAccessorProgress
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				return fileHeader, nil
			}
			return fileHeader, err
		}
		balancesBlockBytes := make([]byte, header.Size)
		readComplete := int64(0)

		for readComplete < header.Size {
			bytesRead, err := tarReader.Read(balancesBlockBytes[readComplete:])
			readComplete += int64(bytesRead)
			progress += uint64(bytesRead)
			if err != nil {
				if err == io.EOF {
					if readComplete == header.Size {
						break
					}
					err = fmt.Errorf("getPeerLedger received io.EOF while reading from tar file stream prior of reaching chunk size %d / %d", readComplete, header.Size)
				}
				return fileHeader, err
			}
		}
		err = catchupAccessor.ProgressStagingBalances(ctx, header.Name, balancesBlockBytes, &downloadProgress)
		if err != nil {
			return fileHeader, err
		}
		if header.Name == "content.msgpack" {
			// we already know it's valid, since we validated that above.
			protocol.Decode(balancesBlockBytes, &fileHeader)
		}
		if time.Now().Sub(lastProgressUpdate) > 50*time.Millisecond && len(fileBytes) > 0 {
			lastProgressUpdate = time.Now()
			printLoadCatchpointProgressLine(int(float64(progress)*50.0/float64(len(fileBytes))), 50, int64(progress))
		}
	}
}

func printDumpingCatchpointProgressLine(progress int, barLength int, dld int64) {
	if barLength == 0 {
		fmt.Printf(escapeCursorUp + escapeDeleteLine + "[ Done ] Dumped\n")
		return
	}

	outString := "[" + strings.Repeat(escapeSquare, progress) + strings.Repeat(escapeDot, barLength-progress) + "] Dumping..."
	if dld > 0 {
		outString = fmt.Sprintf(outString+" %d", dld)
	}
	fmt.Printf(escapeCursorUp + escapeDeleteLine + outString + "\n")
}

func printAccountsDatabase(databaseName string, fileHeader ledger.CatchpointFileHeader, outFile *os.File) error {
	lastProgressUpdate := time.Now()
	progress := uint64(0)
	defer printDumpingCatchpointProgressLine(0, 0, 0)

	fileWriter := bufio.NewWriterSize(outFile, 1024*1024)
	defer fileWriter.Flush()

	dbAccessor, err := db.MakeAccessor(databaseName, true, false)
	if err != nil || dbAccessor.Handle == nil {
		return err
	}
	if fileHeader.Version != 0 {
		fmt.Fprintf(fileWriter, "Version: %d\nBalances Round: %d\nBlock Round: %d\nBlock Header Digest: %s\nCatchpoint: %s\nTotal Accounts: %d\nTotal Chunks: %d\n",
			fileHeader.Version,
			fileHeader.BalancesRound,
			fileHeader.BlocksRound,
			fileHeader.BlockHeaderDigest.String(),
			fileHeader.Catchpoint,
			fileHeader.TotalAccounts,
			fileHeader.TotalChunks)

		totals := fileHeader.Totals
		fmt.Fprintf(fileWriter, "AccountTotals - Online Money: %d\nAccountTotals - Online RewardUnits : %d\nAccountTotals - Offline Money: %d\nAccountTotals - Offline RewardUnits : %d\nAccountTotals - Not Participating Money: %d\nAccountTotals - Not Participating Money RewardUnits: %d\nAccountTotals - Rewards Level: %d\n",
			totals.Online.Money.Raw, totals.Online.RewardUnits,
			totals.Offline.Money.Raw, totals.Offline.RewardUnits,
			totals.NotParticipating.Money.Raw, totals.NotParticipating.RewardUnits,
			totals.RewardsLevel)
	}
	return dbAccessor.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		fmt.Printf("\n")
		printDumpingCatchpointProgressLine(0, 50, 0)

		if fileHeader.Version == 0 {
			var totals ledgercore.AccountTotals
			id := ""
			row := tx.QueryRow("SELECT online, onlinerewardunits, offline, offlinerewardunits, notparticipating, notparticipatingrewardunits, rewardslevel FROM accounttotals WHERE id=?", id)
			err = row.Scan(&totals.Online.Money.Raw, &totals.Online.RewardUnits,
				&totals.Offline.Money.Raw, &totals.Offline.RewardUnits,
				&totals.NotParticipating.Money.Raw, &totals.NotParticipating.RewardUnits,
				&totals.RewardsLevel)
			if err != nil {
				return err
			}
			fmt.Fprintf(fileWriter, "AccountTotals - Online Money: %d\nAccountTotals - Online RewardUnits : %d\nAccountTotals - Offline Money: %d\nAccountTotals - Offline RewardUnits : %d\nAccountTotals - Not Participating Money: %d\nAccountTotals - Not Participating Money RewardUnits: %d\nAccountTotals - Rewards Level: %d\n",
				totals.Online.Money.Raw, totals.Online.RewardUnits,
				totals.Offline.Money.Raw, totals.Offline.RewardUnits,
				totals.NotParticipating.Money.Raw, totals.NotParticipating.RewardUnits,
				totals.RewardsLevel)
		}

		balancesTable := "accountbase"
		if fileHeader.Version != 0 {
			balancesTable = "catchpointbalances"
		}

		var rowsCount int64
		err = tx.QueryRow(fmt.Sprintf("SELECT count(*) from %s", balancesTable)).Scan(&rowsCount)
		if err != nil {
			return
		}

		rows, err := tx.Query(fmt.Sprintf("SELECT address, data FROM %s order by address", balancesTable))
		if err != nil {
			return
		}
		defer rows.Close()

		for rows.Next() {
			var addrbuf []byte
			var buf []byte
			err = rows.Scan(&addrbuf, &buf)
			if err != nil {
				return
			}

			var data basics.AccountData
			err = protocol.Decode(buf, &data)
			if err != nil {
				return
			}

			var addr basics.Address
			if len(addrbuf) != len(addr) {
				err = fmt.Errorf("Account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
				return
			}
			copy(addr[:], addrbuf)
			jsonData, err := json.Marshal(data)
			if err != nil {
				return err
			}

			fmt.Fprintf(fileWriter, "%v : %s\n", addr, string(jsonData))

			if time.Now().Sub(lastProgressUpdate) > 50*time.Millisecond && rowsCount > 0 {
				lastProgressUpdate = time.Now()
				printDumpingCatchpointProgressLine(int(float64(progress)*50.0/float64(rowsCount)), 50, int64(progress))
			}
			progress++
		}

		err = rows.Err()
		// increase the deadline warning to disable the warning message.
		db.ResetTransactionWarnDeadline(ctx, tx, time.Now().Add(5*time.Second))
		return nil
	})
}
