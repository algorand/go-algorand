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
	"archive/tar"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

var tarFile string

func init() {
	fileCmd.Flags().StringVarP(&tarFile, "tar", "t", "", "Specify the tar file to process")
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
		reportInfof("Processing %s..", tarFile)
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
		catchupAccessor := ledger.MakeCatchpointCatchupAccessor(l, logging.Base())
		err = catchupAccessor.ResetStagingBalances(context.Background(), true)
		if err != nil {
			reportErrorf("Unable to initialize catchup database : %v", err)
		}
		err = loadCatchpointIntoDatabase(context.Background(), catchupAccessor, tarFileBytes)
		if err != nil {
			reportErrorf("Unable to load catchpoint file into in-memory database : %v", err)
		}
		err = printAccountsDatabase("./ledger.tracker.sqlite")
		if err != nil {
			reportErrorf("Unable to print account database : %v", err)
		}
	},
}

func loadCatchpointIntoDatabase(ctx context.Context, catchupAccessor ledger.CatchpointCatchupAccessor, fileBytes []byte) error {
	reader := bytes.NewReader(fileBytes)
	tarReader := tar.NewReader(reader)
	var downloadProgress ledger.CatchpointCatchupAccessorProgress
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		balancesBlockBytes := make([]byte, header.Size)
		readComplete := int64(0)

		for readComplete < header.Size {
			bytesRead, err := tarReader.Read(balancesBlockBytes[readComplete:])
			readComplete += int64(bytesRead)
			if err != nil {
				if err == io.EOF {
					if readComplete == header.Size {
						break
					}
					err = fmt.Errorf("getPeerLedger received io.EOF while reading from tar file stream prior of reaching chunk size %d / %d", readComplete, header.Size)
				}
				return err
			}
		}
		err = catchupAccessor.ProgressStagingBalances(ctx, header.Name, balancesBlockBytes, &downloadProgress)
		if err != nil {
			return err
		}
	}
}

func printAccountsDatabase(databaseName string) error {
	dbAccessor, err := db.MakeAccessor(databaseName, true, false)
	if err != nil || dbAccessor.Handle == nil {
		return err
	}
	return dbAccessor.Atomic(func(tx *sql.Tx) (err error) {
		var totals ledger.AccountTotals
		row := tx.QueryRow("SELECT online, onlinerewardunits, offline, offlinerewardunits, notparticipating, notparticipatingrewardunits, rewardslevel FROM accounttotals WHERE id=?", "catchpointStaging")
		err = row.Scan(&totals.Online.Money.Raw, &totals.Online.RewardUnits,
			&totals.Offline.Money.Raw, &totals.Offline.RewardUnits,
			&totals.NotParticipating.Money.Raw, &totals.NotParticipating.RewardUnits,
			&totals.RewardsLevel)
		if err != nil {
			return err
		}
		fmt.Printf("AccountTotals - Online Money: %d\nAccountTotals - Online RewardUnits : %d\nAccountTotals - Offline Money: %d\nAccountTotals - Offline RewardUnits : %d\nAccountTotals - Not Participating Money: %d\nAccountTotals - Not Participating Money RewardUnits: %d\nAccountTotals - Rewards Level: %d\n", &totals.Online.Money.Raw, &totals.Online.RewardUnits,
			&totals.Offline.Money.Raw, &totals.Offline.RewardUnits,
			&totals.NotParticipating.Money.Raw, &totals.NotParticipating.RewardUnits,
			&totals.RewardsLevel)

		rows, err := tx.Query("SELECT address, data FROM catchpointbalances order by address")
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

			fmt.Printf("%v : %s\n", addr, string(jsonData))
		}

		err = rows.Err()
		return nil
	})
}
