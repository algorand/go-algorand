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

package indexer

import (
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

type IndexSuite struct {
	suite.Suite
	idx *Indexer

	txns    []transactions.SignedTxn
	secrets []*crypto.SignatureSecrets
	addrs   []basics.Address
}

func (s *IndexSuite) SetupSuite() {
	var err error
	s.idx, err = MakeIndexer(".", &TestLedger{}, true)
	require.NoError(s.T(), err)

	numOfTransactions := 5000
	numOfAccounts := 10
	numOfBlocks := 10

	require.Equal(s.T(), 0, numOfTransactions%numOfBlocks, "Number of transaction must be "+
		"divisible by the number of blocks")

	_, s.txns, s.secrets, s.addrs = generateTestObjects(numOfTransactions, numOfAccounts)

	// Gen some simple blocks
	for i := 0; i < numOfBlocks; i++ {
		var txnEnc []transactions.SignedTxnInBlock
		b := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round:     basics.Round(uint64(i + 2)),
				TimeStamp: time.Now().Unix(),
			},
		}

		chunkSize := numOfTransactions / numOfBlocks
		for t := i * chunkSize; t < (i+1)*chunkSize; t++ {

			txid, err := b.EncodeSignedTxn(s.txns[t], transactions.ApplyData{})
			require.NoError(s.T(), err)
			txnEnc = append(txnEnc, txid)
		}

		b.Payset = txnEnc
		err = s.idx.NewBlock(b)
		require.NoError(s.T(), err)

		r, err := s.idx.LastBlock()
		require.NoError(s.T(), err)
		require.Equal(s.T(), basics.Round(i+2), r)
	}
}

func (s *IndexSuite) TearDownSuite() {
	s.idx.Shutdown()
	err := os.RemoveAll(s.idx.IDB.DBPath)
	require.NoError(s.T(), err)
}

func (s *IndexSuite) TestIndexer_GetRoundByTXID() {
	txID := s.txns[0].ID().String()

	_, err := s.idx.GetRoundByTXID(txID)

	require.NoError(s.T(), err)

}

func (s *IndexSuite) TestIndexer_GetRoundsByAddress() {
	var count int

	res, err := s.idx.GetRoundsByAddress(s.addrs[0].GetUserAddress(), uint64(count))
	require.NoError(s.T(), err)

	// Should be equal to the number of blocks.
	require.Equal(s.T(), 10, len(res))
}

func (s *IndexSuite) TestIndexer_DuplicateRounds() {
	// Get Transactions (we're guaranteed to have more than one txn per address per block)

	res, err := s.idx.GetRoundsByAddress(s.addrs[0].String(), 100)

	require.NoError(s.T(), err)

	// Check for dups
	seen := make(map[uint64]bool)
	for _, b := range res {
		require.False(s.T(), seen[b])
		seen[b] = true
	}
}

func (s *IndexSuite) TestIndexer_Asset() {
	query := "SELECT txid from transactions where (from_addr = $1 OR to_addr = $1)"
	rows, err := s.idx.IDB.dbr.Handle.Query(query, s.addrs[0].String())
	require.NoError(s.T(), err)
	defer rows.Close()

	txids := make(map[string]bool, 0)
	var txid string
	for rows.Next() {
		err := rows.Scan(&txid)
		require.NoError(s.T(), err)
		txids[txid] = true
	}

	// make sure all txns are in list
	for _, txn := range s.txns {
		if txn.Txn.Type == protocol.AssetTransferTx {
			if txn.Txn.Sender == s.addrs[0] || txn.Txn.AssetReceiver == s.addrs[0] {
				require.True(s.T(), txids[txn.ID().String()])
			}
		}
	}

}

func TestExampleTestSuite(t *testing.T) {
	suite.Run(t, new(IndexSuite))
}

func BenchmarkORM_AddTransactions(b *testing.B) {
	idx, _ := MakeIndexer(".", &TestLedger{}, false)
	_, txns, _, _ := generateTestObjects(5000, 100)
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		var txnEnc []transactions.SignedTxnInBlock
		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round:     basics.Round(n),
				TimeStamp: time.Now().Unix(),
			},
		}
		for _, tx := range txns {
			txib, err := blk.EncodeSignedTxn(tx, transactions.ApplyData{})
			require.NoError(b, err)
			txnEnc = append(txnEnc, txib)
		}
		blk.Payset = txnEnc
		idx.NewBlock(blk)
	}
}

func BenchmarkORM_AddTransactions2(b *testing.B) {
	numTxn := 5000
	idx, _ := MakeIndexer(".", &TestLedger{}, false)
	_, txns, _, _ := generateTestObjects(numTxn, 100)
	b.ResetTimer()

	t := 5
	for n := 0; n < b.N; n++ {
		for i := 0; i < t; i++ {
			var txnEnc []transactions.SignedTxnInBlock
			blk := bookkeeping.Block{
				BlockHeader: bookkeeping.BlockHeader{
					Round:     basics.Round(i),
					TimeStamp: time.Now().Unix(),
				},
			}
			bTxns := txns[numTxn/t*i : numTxn/t*(i+1)]
			for _, tx := range bTxns {
				txib, err := blk.EncodeSignedTxn(tx, transactions.ApplyData{})
				require.NoError(b, err)
				txnEnc = append(txnEnc, txib)
			}
			blk.Payset = txnEnc
			idx.NewBlock(blk)
		}
	}
}

func generateTestObjects(numTxs, numAccs int) ([]transactions.Transaction, []transactions.SignedTxn, []*crypto.SignatureSecrets, []basics.Address) {
	txs := make([]transactions.Transaction, numTxs)
	signed := make([]transactions.SignedTxn, numTxs)
	secrets := make([]*crypto.SignatureSecrets, numAccs)
	addresses := make([]basics.Address, numAccs)

	for i := 0; i < numAccs; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	for i := 0; i < numTxs; i++ {
		s := rand.Intn(numAccs)
		r := rand.Intn(numAccs)
		a := rand.Intn(1000)
		f := config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee + uint64(rand.Intn(10))
		iss := 50 + rand.Intn(30)
		exp := iss + 10

		txs[i] = transactions.Transaction{
			Header: transactions.Header{
				Sender:     addresses[s],
				Fee:        basics.MicroAlgos{Raw: f},
				FirstValid: basics.Round(iss),
				LastValid:  basics.Round(exp),
			},
		}

		// Create half assets and half payment
		if i%2 == 0 {
			txs[i].Type = protocol.PaymentTx
			txs[i].PaymentTxnFields = transactions.PaymentTxnFields{
				Receiver: addresses[r],
				Amount:   basics.MicroAlgos{Raw: uint64(a)},
			}
		} else {
			txs[i].Type = protocol.AssetTransferTx
			txs[i].AssetTransferTxnFields = transactions.AssetTransferTxnFields{
				AssetReceiver: addresses[r],
				AssetAmount:   uint64(a),
				XferAsset:     basics.AssetIndex(uint64(rand.Intn(20000))),
			}
		}
		signed[i] = txs[i].Sign(secrets[s])
	}

	return txs, signed, secrets, addresses
}

func keypair() *crypto.SignatureSecrets {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

type TestLedger struct {
}

func (l *TestLedger) Block(rnd basics.Round) (blk bookkeeping.Block, err error) {
	return bookkeeping.Block{}, nil
}

func (l *TestLedger) Wait(r basics.Round) chan struct{} {
	return nil
}
