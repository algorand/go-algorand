// Copyright (C) 2019-2022 Algorand, Inc.
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

package ledger

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/verify"
	"github.com/algorand/go-algorand/ledger/internal"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

func setupEnv(dbTempDir, name string, numAccts int) (l0,
	l1 *Ledger, creator basics.Address, accts []basics.Address, aIdxs []uint64, err error) {
	dbName := fmt.Sprintf("%s.%d", name, crypto.RandUint64())
	dbPrefix := filepath.Join(dbTempDir, dbName)

	genesisInitState := getInitState()

	// Use future protocol
	genesisInitState.Block.BlockHeader.GenesisHash = crypto.Digest{}
	genesisInitState.Block.CurrentProtocol = protocol.ConsensusFuture
	genesisInitState.GenesisHash = crypto.Digest{1}
	genesisInitState.Block.BlockHeader.GenesisHash = crypto.Digest{1}

	creator = basics.Address{}
	_, err = rand.Read(creator[:])
	if err != nil {
		return nil, nil, basics.Address{}, nil, nil, err
	}
	genesisInitState.Accounts[creator] = basics.MakeAccountData(basics.Offline, basics.MicroAlgos{Raw: 12345678900000})
	for i := 0; i < numAccts; i++ {
		acct := basics.Address{}
		_, err = rand.Read(acct[:])
		if err != nil {
			return nil, nil, basics.Address{}, nil, nil, err
		}
		genesisInitState.Accounts[acct] = basics.MakeAccountData(basics.Offline, basics.MicroAlgos{Raw: 1234567890})
		accts = append(accts, acct)
	}

	// open ledger
	const inMem = false
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l0, err = OpenLedger(logging.Base(), dbPrefix, inMem, genesisInitState, cfg)
	if err != nil {
		return nil, nil, basics.Address{}, nil, nil, err
	}

	// open second ledger
	dbName = fmt.Sprintf("%s.%d.2", name, crypto.RandUint64())
	dbPrefix = filepath.Join(dbTempDir, dbName)
	l1, err = OpenLedger(logging.Base(), dbPrefix, inMem, genesisInitState, cfg)
	if err != nil {
		return nil, nil, basics.Address{}, nil, nil, err
	}

	blk := genesisInitState.Block
	blk.BlockHeader.Round++
	blk.BlockHeader.TimeStamp += int64(crypto.RandUint64() % 100 * 1000)
	blk.BlockHeader.GenesisID = "x"
	cert := agreement.Certificate{}

	err = l0.AddBlock(blk, cert)
	if err != nil {
		return nil, nil, basics.Address{}, nil, nil, err
	}
	err = l1.AddBlock(blk, cert)
	if err != nil {
		return nil, nil, basics.Address{}, nil, nil, err
	}

	newBlk := bookkeeping.MakeBlock(blk.BlockHeader)
	eval, err := l0.StartEvaluator(newBlk.BlockHeader, 5000, 0)
	if err != nil {
		return nil, nil, basics.Address{}, nil, nil, err
	}

	for i, acct := range accts {
		tx := createAssetTransaction(uint64(i), 1, creator, crypto.Digest{1})
		stxn := transactions.SignedTxn{Txn: tx, Sig: crypto.Signature{1}}
		err = eval.Transaction(stxn, transactions.ApplyData{})
		if err != nil {
			return nil, nil, basics.Address{}, nil, nil, err
		}

		// opt in to the asset
		aIdx := eval.TestingTxnCounter()
		tx = sendAssetTransaction(uint64(i), 1, acct, 0, crypto.Digest{1}, basics.AssetIndex(aIdx), acct)
		aIdxs = append(aIdxs, aIdx)
		stxn = transactions.SignedTxn{Txn: tx, Sig: crypto.Signature{1}}
		err = eval.Transaction(stxn, transactions.ApplyData{})
		if err != nil {
			return nil, nil, basics.Address{}, nil, nil, err
		}

	}

	vblk, err := eval.GenerateBlock()
	if err != nil {
		return nil, nil, basics.Address{}, nil, nil, err
	}
	err = l0.AddBlock(vblk.Block(), cert)
	if err != nil {
		return nil, nil, basics.Address{}, nil, nil, err
	}
	err = l1.AddBlock(vblk.Block(), cert)
	if err != nil {
		return nil, nil, basics.Address{}, nil, nil, err
	}

	return l0, l1, creator, accts, aIdxs, nil
}

func BenchmarkBlockValidationMix(b *testing.B) {
	numAssets := 10000
	benchmarkBlockValidationMix(b, numAssets)
}

func BenchmarkBlockValidationPayments(b *testing.B) {
	benchmarkBlockValidationMix(b, 0)
}

func benchmarkBlockValidationMix(b *testing.B, numAssets int) {
	l0, l1, creator, accts, aIdxs, err :=
		setupEnv(b.TempDir(), b.Name(), numAssets)
	require.NoError(b, err)

	numBlocks := b.N
	cert := agreement.Certificate{}
	var blocks []bookkeeping.Block
	var txPerBlock int
	var numAss, numPay int
	fmt.Printf("Preparing transactions and adding the blocks (/%d): ", numBlocks)
	evalTime := float64(0)
	addBlockTime := float64(0)
	s2 := time.Now()
	s3 := time.Now()

	for i := 0; i < numBlocks; i++ {
		// Construct evaluator for next block
		prev, err := l0.BlockHdr(basics.Round(i + 2))
		require.NoError(b, err)
		newBlk := bookkeeping.MakeBlock(prev)
		eval, err := l0.StartEvaluator(newBlk.BlockHeader, 5000, 0)
		require.NoError(b, err)

		// build a payset
		var j int
		for a, acct := range accts {
			j++
			tx := sendAssetTransaction(uint64(j), uint64(i+1), creator, 1, crypto.Digest{1}, basics.AssetIndex(aIdxs[a]), acct)
			tx.Note = []byte(fmt.Sprintf("%d,%d,%d", i, j, 0))
			stxn := transactions.SignedTxn{Txn: tx, Sig: crypto.Signature{1}}
			err = eval.Transaction(stxn, transactions.ApplyData{})
			if err != nil {
				require.NoError(b, err)
			}
			numAss++
		}

		receiver := creator
		receiver[1] = receiver[2]
		amt := uint64(100000)
		for {
			j++
			tx := createPaymentTransaction(uint64(j), uint64(i+1), creator, receiver, amt, crypto.Digest{1})
			amt = 1
			var stxn transactions.SignedTxn
			stxn.Txn = tx
			stxn.Sig = crypto.Signature{1}
			et := time.Now()
			err = eval.Transaction(stxn, transactions.ApplyData{})
			evalTime += time.Since(et).Seconds()
			// check if block is full
			if err == ledgercore.ErrNoSpace {
				txPerBlock += eval.PaySetSize()
				break
			} else {
				require.NoError(b, err)
			}
			numPay++
		}
		vblk, err := eval.GenerateBlock()
		require.NoError(b, err)
		abt := time.Now()
		err = l0.AddBlock(vblk.Block(), cert)
		addBlockTime += time.Since(abt).Seconds()
		require.NoError(b, err)
		blocks = append(blocks, vblk.Block())
		if i*10%numBlocks == 0 {
			fmt.Printf("%d%% (%.1fsec) ", i*100/numBlocks, time.Since(s3).Seconds())
			s3 = time.Now()
		}
	}
	fmt.Printf("\n%s sec total (eval: %.1fsec  addBlock: %.1fsec)\n", time.Since(s2).String(), evalTime, addBlockTime)

	b.Logf("built %d blocks, each with %d txns: %d assets %d pay", numBlocks, txPerBlock/numBlocks, numAss/numBlocks, numPay/numBlocks)

	// eval + add all the (valid) blocks to the second ledger, measuring it this time
	vc := verify.GetMockedCache(true)
	tt := time.Now()
	b.ResetTimer()
	for _, blk := range blocks {
		_, err = internal.Eval(context.Background(), l1, blk, true, vc, nil)
		require.NoError(b, err)
		err = l1.AddBlock(blk, cert)
		require.NoError(b, err)
	}
	fmt.Printf("%s sec for %d block(s)\n", time.Since(tt).String(), numBlocks)
}

func createPaymentTransaction(
	counter uint64,
	round uint64,
	sender basics.Address,
	receiver basics.Address,
	amount uint64,
	genesisHash crypto.Digest) (txn transactions.Transaction) {

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)
	txn = transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(round),
			LastValid:   basics.Round(round + 1000),
			GenesisHash: genesisHash,
			Note:        note,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: amount},
		},
	}
	return
}

// prepares a create asset transaction
func createAssetTransaction(
	counter uint64,
	round uint64,
	sender basics.Address,
	genesisHash crypto.Digest) (assetTx transactions.Transaction) {

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)
	assetTx = transactions.Transaction{
		Type: protocol.AssetConfigTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(round),
			LastValid:   basics.Round(round + 1000),
			GenesisHash: genesisHash,
			Note:        note,
		},
		AssetConfigTxnFields: transactions.AssetConfigTxnFields{
			AssetParams: basics.AssetParams{
				Total:         3000000,
				DefaultFrozen: false,
				Manager:       sender,
			},
		},
	}
	return
}

// prepares a send asset transaction
func sendAssetTransaction(
	counter uint64,
	round uint64,
	sender basics.Address,
	amt uint64,
	genesisHash crypto.Digest,
	assetID basics.AssetIndex,
	receiver basics.Address) (tx transactions.Transaction) {

	note := make([]byte, 8)
	binary.LittleEndian.PutUint64(note, counter)
	tx = transactions.Transaction{
		Type: protocol.AssetTransferTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee},
			FirstValid:  basics.Round(round),
			LastValid:   basics.Round(round + 1000),
			GenesisHash: genesisHash,
			Note:        note,
		},
		AssetTransferTxnFields: transactions.AssetTransferTxnFields{
			XferAsset:     assetID,
			AssetAmount:   amt,
			AssetReceiver: receiver,
		},
	}
	return
}
