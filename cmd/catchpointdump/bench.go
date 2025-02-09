// Copyright (C) 2019-2024 Algorand, Inc.
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
	"os"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	tools "github.com/algorand/go-algorand/tools/network"
)

var reportJsonPath string

func init() {
	benchCmd.Flags().StringVarP(&networkName, "net", "n", "", "Specify the network name ( i.e. mainnet.algorand.network )")
	benchCmd.Flags().IntVarP(&round, "round", "r", 0, "Specify the round number ( i.e. 7700000 )")
	benchCmd.Flags().StringVarP(&relayAddress, "relay", "p", "", "Relay address to use ( i.e. r-ru.algorand-mainnet.network:4160 )")
	benchCmd.Flags().StringVarP(&catchpointFile, "tar", "t", "", "Specify the catchpoint file (either .tar or .tar.gz) to process")
	benchCmd.Flags().StringVarP(&reportJsonPath, "report", "j", "", "Specify the file to save the Json formatted report to")
}

var benchCmd = &cobra.Command{
	Use:   "bench",
	Short: "Benchmark a catchpoint restore",
	Long:  "Benchmark a catchpoint restore",
	Args:  validateNoPosArgsFn,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		// Either source the file locally or require a network name to download
		if catchpointFile == "" && networkName == "" {
			return fmt.Errorf("provide either catchpoint file or network name")
		}
		loadOnly = true
		benchmark := makeBenchmarkReport()

		if catchpointFile == "" {
			if round == 0 {
				return fmt.Errorf("round not set")
			}
			stage := benchmark.startStage("network")
			catchpointFile, err = downloadCatchpointFromAnyRelay(networkName, round, relayAddress)
			if err != nil {
				return fmt.Errorf("failed to download catchpoint : %v", err)
			}
			stage.completeStage()
		}
		stats, err := os.Stat(catchpointFile)
		if err != nil {
			return fmt.Errorf("unable to stat '%s' : %v", catchpointFile, err)
		}

		catchpointSize := stats.Size()
		if catchpointSize == 0 {
			return fmt.Errorf("empty file '%s' : %v", catchpointFile, err)
		}

		genesisInitState := ledgercore.InitState{
			Block: bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{
				UpgradeState: bookkeeping.UpgradeState{
					CurrentProtocol: protocol.ConsensusCurrentVersion,
				},
			}},
		}
		cfg := config.GetDefaultLocal()
		l, err := ledger.OpenLedger(logging.Base(), "./ledger", false, genesisInitState, cfg)
		if err != nil {
			return fmt.Errorf("unable to open ledger : %v", err)
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
			return fmt.Errorf("unable to initialize catchup database : %v", err)
		}

		reader, err := os.Open(catchpointFile)
		if err != nil {
			return fmt.Errorf("unable to read '%s' : %v", catchpointFile, err)
		}
		defer reader.Close()

		printDigests = false
		stage := benchmark.startStage("database")

		_, err = loadCatchpointIntoDatabase(context.Background(), catchupAccessor, reader, catchpointSize)
		if err != nil {
			return fmt.Errorf("unable to load catchpoint file into in-memory database : %v", err)
		}
		stage.completeStage()

		stage = benchmark.startStage("digest")

		err = buildMerkleTrie(context.Background(), catchupAccessor)
		if err != nil {
			return fmt.Errorf("unable to build Merkle tree : %v", err)
		}
		stage.completeStage()

		benchmark.printReport()
		if reportJsonPath != "" {
			if err := benchmark.saveReport(reportJsonPath); err != nil {
				fmt.Printf("error writing report to %s: %v\n", reportJsonPath, err)
			}
		}

		return err
	},
}

func downloadCatchpointFromAnyRelay(network string, round int, relayAddress string) (string, error) {
	var addrs []string
	if relayAddress != "" {
		addrs = []string{relayAddress}
	} else {
		//append relays
		dnsaddrs, err := tools.ReadFromSRV(context.Background(), "algobootstrap", "tcp", networkName, "", false)
		if err != nil || len(dnsaddrs) == 0 {
			return "", fmt.Errorf("unable to bootstrap records for '%s' : %v", networkName, err)
		}
		addrs = append(addrs, dnsaddrs...)
		// append archivers
		dnsaddrs, err = tools.ReadFromSRV(context.Background(), "archive", "tcp", networkName, "", false)
		if err == nil && len(dnsaddrs) > 0 {
			addrs = append(addrs, dnsaddrs...)
		}
	}

	for _, addr := range addrs {
		tarName, err := downloadCatchpoint(addr, round)
		if err != nil {
			reportInfof("failed to download catchpoint from '%s' : %v", addr, err)
			continue
		}
		return tarName, nil
	}
	return "", fmt.Errorf("catchpoint for round %d on network %s could not be downloaded from any relay", round, network)
}

func buildMerkleTrie(ctx context.Context, catchupAccessor ledger.CatchpointCatchupAccessor) (err error) {
	fmt.Printf("\n Building Merkle Trie, this might take a few minutes...\n")
	err = catchupAccessor.BuildMerkleTrie(ctx, func(uint64, uint64) {})
	if err != nil {
		return err
	}

	var balanceHash, spverHash crypto.Digest
	balanceHash, spverHash, _, err = catchupAccessor.GetVerifyData(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("done. \naccounts digest=%s, spver digest=%s\n\n", balanceHash, spverHash)
	return nil
}
