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
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang/snappy"
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
	"github.com/algorand/go-codec/codec"
)

var dataDir = flag.String("d", "", "Data directory to track to get files from")
var roundStart = flag.Int("r", 0, "Target round number to catch up to")
var txnDir = flag.String("t", "", "Directory to read transaction files from")
var txnFile = flag.String("tfile", "", "File to read transaction from")
var txnLogDir = flag.String("txlog", "", "Directory to read txlog files from")
var txnLogFile = flag.String("txlogfile", "", "File to read txlog from")
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

func decodeTxGroupSlices(data []byte) ([]transactions.SignedTxn, error) {
	var result [][]transactions.SignedTxn
	err := protocol.DecodeReflect(data, &result)
	if err != nil {
		return nil, fmt.Errorf("received a non-decodable txn slices: %v", err)
	}
	return result[0], nil
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

type headerRow struct {
	Ts   time.Time
	IP   string
	Port int
}

type headerDecoder interface {
	decodeHeader(*snappy.Reader) (*headerRow, int, error)
}

type decoderV1 struct{}

func (decoderV1) decodeHeader(r *snappy.Reader) (*headerRow, int, error) {
	headerBytes := make([]byte, 12)
	n, err := io.ReadFull(r, headerBytes)
	if err != nil {
		return nil, 0, err
	} else if n != 12 {
		return nil, 0, errors.New("incomplete v1 header")
	}
	ts := int64(binary.BigEndian.Uint64(headerBytes))
	tsTime := time.Unix(0, ts)
	lenMsg := binary.BigEndian.Uint32(headerBytes[8:])
	return &headerRow{Ts: tsTime}, int(lenMsg), nil
}

type decoderV2 struct{}

func (decoderV2) decodeHeader(r *snappy.Reader) (*headerRow, int, error) {
	headerBytes := make([]byte, 18)
	n, err := io.ReadFull(r, headerBytes)
	if err != nil {
		return nil, 0, err
	} else if n != 18 {
		return nil, 0, errors.New("incomplete v2 header")
	}
	ts := int64(binary.BigEndian.Uint64(headerBytes))
	tsTime := time.Unix(0, ts)
	ip := net.IP(headerBytes[8:12])
	port := binary.BigEndian.Uint16(headerBytes[12:14])
	lenMsg := binary.BigEndian.Uint32(headerBytes[14:])
	return &headerRow{Ts: tsTime, IP: ip.String(), Port: int(port)}, int(lenMsg), nil
}

type txGroupItem struct {
	err     error
	path    string
	ts      time.Time
	txgroup []transactions.SignedTxn
}

func transcribeSnappyLog(filePath string, output chan txGroupItem, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}
	file, err := os.OpenFile(filePath, os.O_RDONLY, 0644)
	if err != nil {
		output <- txGroupItem{err: err}
		return
	}
	defer file.Close()

	decoder := decoderV2{}
	snappyReader := snappy.NewReader(file)
	var n int

	for {
		headers, lenMsg, err := decoder.decodeHeader(snappyReader)
		if err == io.EOF {
			break
		} else if err != nil {
			output <- txGroupItem{err: err}
			return
		}

		msgBuff := make([]byte, lenMsg)
		n, err = io.ReadFull(snappyReader, msgBuff)
		if err == io.EOF {
			output <- txGroupItem{err: fmt.Errorf("missing body in %s", filePath)}
			return
		}
		if n != int(lenMsg) {
			output <- txGroupItem{err: fmt.Errorf("incomplete message body in %s", filePath)}
			return
		}

		dec := codec.NewDecoderBytes(msgBuff, new(codec.MsgpackHandle))
		var txgroup []transactions.SignedTxn
		for {
			var stx transactions.SignedTxn
			err := dec.Decode(&stx)
			if err == io.EOF {
				break
			} else if err != nil {
				output <- txGroupItem{err: err}
				return
			}
			txgroup = append(txgroup, stx)
		}
		output <- txGroupItem{ts: headers.Ts, txgroup: txgroup, path: filePath}
	}
}

func readTransactions(output chan txGroupItem) {
	defer close(output)
	if len(*txnFile) > 0 {
		data, err := os.ReadFile(*txnFile)
		if err != nil {
			err = fmt.Errorf("cannot read transaction file %s: %v", *txnFile, err)
			output <- txGroupItem{err: err}
			return
		}

		txgroup, err := decodeTxGroup(data)
		if err != nil {
			txgroup, err = decodeTxGroupSlices(data)
			if err != nil {
				err = fmt.Errorf("cannot decode transaction file %s: %v", *txnFile, err)
				output <- txGroupItem{err: err}
				return
			}
		}
		output <- txGroupItem{ts: time.Time{}, path: *txnFile, txgroup: txgroup}
	} else if len(*txnDir) > 0 {
		files, err := os.ReadDir(*txnDir)
		if err != nil {
			err = fmt.Errorf("cannot read transaction directory %s: %v", *txnDir, err)
			output <- txGroupItem{err: err}
			return
		}
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			path := filepath.Join(*txnDir, file.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				err = fmt.Errorf("cannot read transaction file %s: %v", path, err)
				output <- txGroupItem{err: err}
				return
			}

			txgroup, err := decodeTxGroup(data)
			if err != nil {
				err = fmt.Errorf("cannot decode transaction file %s: %v", path, err)
				output <- txGroupItem{err: err}
				return
			}

			output <- txGroupItem{ts: time.Time{}, path: path, txgroup: txgroup}
		}
	} else {
		if len(*txnLogDir) > 0 {
			files, err := os.ReadDir(*txnLogDir)
			if err != nil {
				err = fmt.Errorf("cannot read transaction log directory %s: %v", *txnLogDir, err)
				output <- txGroupItem{err: err}
				return
			}
			for _, file := range files {
				if file.IsDir() {
					continue
				}
				path := filepath.Join(*txnLogDir, file.Name())
				var wg sync.WaitGroup
				wg.Add(1)
				go transcribeSnappyLog(path, output, &wg)
				wg.Wait()
			}
		} else {
			var wg sync.WaitGroup
			wg.Add(1)
			go transcribeSnappyLog(*txnLogFile, output, &wg)
			wg.Wait()
		}
	}
}

func main() {
	flag.Parse()

	if *help || *helpShort || len(*dataDir) == 0 || *roundStart == 0 {
		usage()
		os.Exit(1)
	}

	if len(*txnDir) > 0 && len(*txnLogDir) > 0 {
		fmt.Fprintln(os.Stderr, "Cannot specify both transactions and transaction logs dirs")
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
		err = followerNode.SetSyncRound(syncRound)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot configure catchup: %v", err)
			os.Exit(1)
		}

		err = followerNode.Start()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot start follower node: %v", err)
			os.Exit(1)
		}

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
	if len(*txnDir) == 0 && len(*txnLogDir) == 0 && len(*txnLogFile) == 0 && len(*txnFile) == 0 {
		fmt.Printf("No transaction [log] directory specified, exiting at round %d\n", l.Latest())
		return
	}

	input := make(chan txGroupItem)
	go readTransactions(input)

	nextRound := l.Latest() + 1
	txCount := 0
	totalTxCount := 0
	blockCount := 0
	pool := pools.MakeTransactionPool(l, cfg, log, nil)
	hdr, err := l.BlockHdr(l.Latest())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot get latest block header: %v", err)
		os.Exit(1)
	}
	for item := range input {
		if item.err != nil {
			fmt.Fprintf(os.Stderr, "ERR: reading transaction file %s failed: %v\n", item.path, item.err)
			os.Exit(1)
		}
		if !item.ts.IsZero() {
			txnTs := item.ts.Unix()
			if txnTs < hdr.TimeStamp {
				// fmt.Printf("INFO: skipping too early txn (%d < %d) from %s\n", txnTs, hdr.TimeStamp, item.path)
				continue
			}
			if txnTs > hdr.TimeStamp+int64(10) {
				fmt.Printf("INFO: too old txns, quitting... %s\n", item.path)
				break
			}
		}
		err = pool.Remember(item.txgroup)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: Cannot remember txn %s: %v\n", item.path, err)
			continue
		} else {
			fmt.Fprintf(os.Stderr, "ADDED: from %s\n", item.path)
		}
		txCount++
		totalTxCount++

		if txCount >= *blockSize {
			deadline := time.Now().Add(100 * time.Millisecond)
			ab, err := pool.AssembleBlock(nextRound, deadline)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERR: Cannot assemble block %d: %v\n", nextRound, err)
				break
			}
			// make validated block without calling FinishBlock
			vb := ledgercore.MakeValidatedBlock(ab.UnfinishedBlock(), ab.UnfinishedDeltas())

			err = l.AddValidatedBlock(vb, agreement.Certificate{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERR: Cannot add block %d: %v\n", nextRound, err)
				break
			}
			blockCount++
			txCount = 0
			hdr = vb.Block().BlockHeader
		}
	}

	fmt.Printf("Added %d blocks (%d transactions) up to round %d\n", blockCount, totalTxCount, l.Latest())
}
