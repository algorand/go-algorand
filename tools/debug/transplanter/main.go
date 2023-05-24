// Copyright (C) 2019-2023 Algorand, Inc.
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
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/pools"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
)

var dataDir = flag.String("d", "", "Data directory to track to get files from")
var roundStart = flag.Int("r", 0, "Target round number to catch up to")
var txnDir = flag.String("t", "", "Transaction directory to read files from")
var force = flag.Bool("y", false, "Suppress confirmation")
var blockSize = flag.Int("b", 1000, "Number of transaction groups per block")

var help = flag.Bool("help", false, "Show help")
var helpShort = flag.Bool("h", false, "Show help")

func usage() {
	fmt.Fprintln(os.Stderr, "Utility to transplant transaction into real ledger")
	flag.Usage()
}

func decodeTxGroup(data []byte) ([]transactions.SignedTxn, error) {
	unverifiedTxGroup := make([]transactions.SignedTxn, 1)
	dec := protocol.NewMsgpDecoderBytes(data)
	ntx := 0

	for {
		if len(unverifiedTxGroup) == ntx {
			n := make([]transactions.SignedTxn, len(unverifiedTxGroup)*2)
			copy(n, unverifiedTxGroup)
			unverifiedTxGroup = n
		}
		err := dec.Decode(&unverifiedTxGroup[ntx])
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("received a non-decodable txn: %v", err)
		}
		ntx++
		if ntx >= config.MaxTxGroupSize {
			// max ever possible group size reached, done reading input.
			if dec.Remaining() > 0 {
				// if something else left in the buffer - this is an error, drop
				return nil, fmt.Errorf("received large txn group: %v", err)
			}
		}
	}
	return unverifiedTxGroup, nil
}

func getConfig() (config.Local, string, error) {
	absolutePath, err := filepath.Abs(*dataDir)
	if err != nil {
		return config.Local{}, "", fmt.Errorf("can't convert data directory's path to absolute, %v", *dataDir)
	}
	cfg, err := config.LoadConfigFromDisk(absolutePath)
	if err != nil {
		return config.Local{}, "", fmt.Errorf("load config: %v", err)
	}
	return cfg, absolutePath, nil
}

func prepareGenesis() (ledgercore.InitState, bookkeeping.Genesis, string, error) {
	genesisPath := filepath.Join(*dataDir, config.GenesisJSONFile)

	// Load genesis
	genesisText, err := os.ReadFile(genesisPath)
	if err != nil {
		return ledgercore.InitState{}, bookkeeping.Genesis{}, "", fmt.Errorf("read genesis file %s: %v", genesisPath, err)
	}

	var genesis bookkeeping.Genesis
	err = protocol.DecodeJSON(genesisText, &genesis)
	if err != nil {
		return ledgercore.InitState{}, bookkeeping.Genesis{}, "", fmt.Errorf("parse genesis file %s: %v", genesisPath, err)
	}

	genesisDir := filepath.Join(*dataDir, genesis.ID())
	ledgerPathnamePrefix := filepath.Join(genesisDir, config.LedgerFilenamePrefix)

	genalloc, err := genesis.Balances()
	if err != nil {
		return ledgercore.InitState{}, bookkeeping.Genesis{}, "", fmt.Errorf("load genesis allocation: %v", err)
	}
	genBlock, err := bookkeeping.MakeGenesisBlock(genesis.Proto, genalloc, genesis.ID(), genesis.Hash())
	if err != nil {
		return ledgercore.InitState{}, bookkeeping.Genesis{}, "", fmt.Errorf("make genesis block: %v", err)
	}
	genesisInitState := ledgercore.InitState{
		Block:       genBlock,
		Accounts:    genalloc.Balances,
		GenesisHash: genesis.Hash(),
	}
	return genesisInitState, genesis, ledgerPathnamePrefix, nil
}

func main() {
	flag.Parse()

	if *help || *helpShort || len(*dataDir) == 0 || *roundStart == 0 {
		usage()
		os.Exit(1)
	}

	if !*force {
		fmt.Println("Running this command could damage your node installation, proceed anyway (N/y)?")
		reader := bufio.NewReader(os.Stdin)
		resp, err := reader.ReadString('\n')
		resp = strings.TrimSpace(resp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read confirmation: %v\n", err)
			os.Exit(1)
		}
		if strings.ToLower(resp) != "y" {
			fmt.Fprintln(os.Stderr, "Exiting...")
			os.Exit(1)
		}
	}

	genesisInitState, genesis, ledgerPathnamePrefix, err := prepareGenesis()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Loading genesis error: %v", err)
		os.Exit(1)
	}

	cfg, rootPath, err := getConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Loading config error: %v", err)
		os.Exit(1)
	}

	log := logging.Base()

	l, err := ledger.OpenLedger(log, ledgerPathnamePrefix, false, genesisInitState, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open ledger config: %v", err)
		os.Exit(1)
	}

	var followerNode *node.AlgorandFollowerNode
	latest := l.Latest()
	if latest < basics.Round(*roundStart) {
		l.Close()

		fmt.Printf("Catching up from %d to %d\n", latest, *roundStart)

		followerNode, err = node.MakeFollower(log, rootPath, cfg, []string{}, genesis)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot init follower node: %v", err)
			os.Exit(1)
		}
		syncRound := uint64(*roundStart) - cfg.MaxAcctLookback + 1
		followerNode.SetSyncRound(syncRound)

		followerNode.Start()

		for followerNode.Ledger().Latest() < basics.Round(*roundStart) {
			fmt.Printf("At round %d, waiting for %d\n", followerNode.Ledger().Latest(), *roundStart)
			time.Sleep(5 * time.Second)
		}
		followerNode.Stop()

		fmt.Printf("Caught up to %d\n", *roundStart)
		l, err = ledger.OpenLedger(log, ledgerPathnamePrefix, false, genesisInitState, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open ledger config: %v", err)
			os.Exit(1)
		}
	}
	defer l.Close()
	if txnDir == nil || len(*txnDir) == 0 {
		fmt.Printf("No transaction directory specified, exiting at round %d\n", l.Latest())
		return
	}

	// start reading transactions and making blocks
	files, err := os.ReadDir(*txnDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read transaction directory %s: %v\n", *txnDir, err)
		os.Exit(1)
	}

	nextRound := l.Latest() + 1
	txCount := 0
	pool := pools.MakeTransactionPool(l, cfg, log)
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		path := filepath.Join(*txnDir, file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read transaction file %s: %v\n", path, err)
			os.Exit(1)
		}

		txgroup, err := decodeTxGroup(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot decode transaction file %s: %v\n", path, err)
			os.Exit(1)
		}

		err = pool.Remember(txgroup)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: Cannot remember txn %s: %v\n", path, err)
			continue
		}
		txCount++

		if txCount >= *blockSize {
			deadline := time.Now().Add(100 * time.Millisecond)
			vb, err := pool.AssembleBlock(nextRound, deadline)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot assemble block %d: %v\n", nextRound, err)
				os.Exit(1)
			}

			err = l.AddValidatedBlock(*vb, agreement.Certificate{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot add block %d: %v\n", nextRound, err)
				os.Exit(1)
			}
			txCount = 0
		}
	}
}
