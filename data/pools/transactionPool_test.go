// Copyright (C) 2019-2025 Algorand, Inc.
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

package pools

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	cryptostateproof "github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/stateproof"
	"github.com/algorand/go-algorand/stateproof/verify"
	"github.com/algorand/go-algorand/test/partitiontest"
)

var proto = config.Consensus[protocol.ConsensusCurrentVersion]

func keypair() *crypto.SignatureSecrets {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

type TestingT interface {
	Errorf(format string, args ...interface{})
	FailNow()
	Name() string
}

var minBalance = config.Consensus[protocol.ConsensusCurrentVersion].MinBalance

func mockLedger(t TestingT, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) *ledger.Ledger {
	var hash crypto.Digest
	crypto.RandBytes(hash[:])

	var pool basics.Address
	crypto.RandBytes(pool[:])
	var poolData basics.AccountData
	poolData.MicroAlgos.Raw = 1 << 32
	initAccounts[pool] = poolData

	initBlock := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			GenesisID:   "pooltest",
			GenesisHash: hash,
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: proto,
			},
			RewardsState: bookkeeping.RewardsState{
				FeeSink:     pool,
				RewardsPool: pool,
			},
		},
	}

	var err error
	initBlock.TxnCommitments, err = initBlock.PaysetCommit()
	require.NoError(t, err)

	fn := fmt.Sprintf("/tmp/%s.%d.sqlite3", t.Name(), crypto.RandUint64())
	const inMem = true
	genesisInitState := ledgercore.InitState{Block: initBlock, Accounts: initAccounts, GenesisHash: hash}
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	l, err := ledger.OpenLedger(logging.Base(), fn, inMem, genesisInitState, cfg)
	require.NoError(t, err)
	return l
}

func makeMockLedger(t TestingT, initAccounts map[basics.Address]basics.AccountData) *ledger.Ledger {
	return mockLedger(t, initAccounts, protocol.ConsensusCurrentVersion)
}

func makeMockLedgerFuture(t TestingT, initAccounts map[basics.Address]basics.AccountData) *ledger.Ledger {
	return mockLedger(t, initAccounts, protocol.ConsensusFuture)
}

func newBlockEvaluator(t TestingT, l *ledger.Ledger) BlockEvaluator {
	latest := l.Latest()
	prev, err := l.BlockHdr(latest)
	require.NoError(t, err)

	next := bookkeeping.MakeBlock(prev)
	eval, err := l.StartEvaluator(next.BlockHeader, 0, 0, nil)
	require.NoError(t, err)

	return eval
}

func initAcc(initBalances map[basics.Address]uint64) map[basics.Address]basics.AccountData {
	res := make(map[basics.Address]basics.AccountData)
	for addr, bal := range initBalances {
		var data basics.AccountData
		data.MicroAlgos.Raw = bal
		res[addr] = data
	}
	return res
}

func initAccFixed(initAddrs []basics.Address, bal uint64) map[basics.Address]basics.AccountData {
	res := make(map[basics.Address]basics.AccountData)
	for _, addr := range initAddrs {
		var data basics.AccountData
		data.MicroAlgos.Raw = bal
		res[addr] = data
	}
	return res
}

// rememberOne is handy for these tests of single transactions
func (pool *TransactionPool) rememberOne(t transactions.SignedTxn) error {
	return pool.Remember([]transactions.SignedTxn{t})
}

// generateAccounts reduces boilerplate in these tests.
func generateAccounts(numAccs int) ([]*crypto.SignatureSecrets, []basics.Address) {
	secrets := make([]*crypto.SignatureSecrets, numAccs)
	addresses := make([]basics.Address, numAccs)

	for i := 0; i < numAccs; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}
	return secrets, addresses
}

func TestMinBalanceOK(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	secrets, addresses := generateAccounts(5)

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance + proto.MinTxnFee
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: minBalance},
		},
	}
	signedTx := tx.Sign(secrets[0])
	require.NoError(t, transactionPool.rememberOne(signedTx))
}

func TestSenderGoesBelowMinBalance(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	secrets, addresses := generateAccounts(5)

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance + proto.MinTxnFee
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)

	// sender goes below min
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: minBalance},
		},
	}
	signedTx := tx.Sign(secrets[0])
	require.ErrorContains(t, transactionPool.rememberOne(signedTx),
		"balance 99999 below min 100000")
}

func TestSenderGoesBelowMinBalanceDueToAssets(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	secrets, addresses := generateAccounts(5)
	proto := config.Consensus[protocol.ConsensusFuture]

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 3*minBalance + 2*proto.MinTxnFee
	ledger := makeMockLedgerFuture(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)

	assetTx := transactions.Transaction{
		Type: protocol.AssetConfigTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		AssetConfigTxnFields: transactions.AssetConfigTxnFields{
			AssetParams: basics.AssetParams{
				Total:         100,
				DefaultFrozen: false,
				Manager:       addresses[0],
			},
		},
	}
	signedAssetTx := assetTx.Sign(secrets[0])
	require.NoError(t, transactionPool.rememberOne(signedAssetTx))

	// sender goes below min
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: minBalance},
		},
	}
	signedTx := tx.Sign(secrets[0])
	err := transactionPool.rememberOne(signedTx)
	require.ErrorContains(t, err, "balance 199999 below min 200000 (1 assets)")
}

func TestCloseAccount(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	secrets, addresses := generateAccounts(5)

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 3*minBalance + 2*proto.MinTxnFee
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)

	closeTx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         addresses[1],
			Amount:           basics.MicroAlgos{Raw: minBalance},
			CloseRemainderTo: addresses[2],
		},
	}
	signedTx := closeTx.Sign(secrets[0])
	require.NoError(t, transactionPool.rememberOne(signedTx))

	// sender is closed - it can't spend fee or make payment)
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: minBalance},
		},
	}
	signedTx2 := tx.Sign(secrets[0])
	require.ErrorContains(t, transactionPool.rememberOne(signedTx2), "overspend")
}

func TestCloseAccountWhileTxIsPending(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	secrets, addresses := generateAccounts(5)

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance + 2*proto.MinTxnFee - 1
	limitedAccounts[addresses[1]] = minBalance // to allow the small payment
	limitedAccounts[addresses[2]] = minBalance // to allow the small close-to
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: minBalance},
		},
	}
	signedTx := tx.Sign(secrets[0])
	require.NoError(t, transactionPool.rememberOne(signedTx))

	// first transaction paid minBalance + minFee, leaving minBalance + minFee -
	// 1, this tx tries to pay minBlance and using minFee again, so it goes negative
	closeTx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         addresses[1],
			Amount:           basics.MicroAlgos{Raw: minBalance},
			CloseRemainderTo: addresses[2],
		},
	}
	signedCloseTx := closeTx.Sign(secrets[0])
	require.ErrorContains(t, transactionPool.rememberOne(signedCloseTx), "overspend")

	// it's ok to pay a bit less, because although it _would_ end up under min
	// balance, it's closing, so it's ok.
	closeTx = transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         addresses[1],
			Amount:           basics.MicroAlgos{Raw: minBalance - 10}, // a bit less
			CloseRemainderTo: addresses[2],
		},
	}
	signedCloseTx = closeTx.Sign(secrets[0])
	require.NoError(t, transactionPool.rememberOne(signedCloseTx))
}

func TestCloseToAccountBelowMinBalance(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	secrets, addresses := generateAccounts(5)

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance - 1 + proto.MinTxnFee
	limitedAccounts[addresses[2]] = 0
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)

	closeTx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         addresses[1],
			Amount:           basics.MicroAlgos{Raw: minBalance},
			CloseRemainderTo: addresses[2],
		},
	}
	signedTx := closeTx.Sign(secrets[0])
	// Note it's CloseRemainderTo address that has the problem - it receives < minBalance
	require.ErrorContains(t, transactionPool.rememberOne(signedTx), addresses[2].String())
}

func TestReceiverGoesBelowMinBalance(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	secrets, addresses := generateAccounts(5)

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance + proto.MinTxnFee
	limitedAccounts[addresses[1]] = 0
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  0,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: minBalance - 1},
		},
	}
	signedTx := tx.Sign(secrets[0])
	require.ErrorContains(t, transactionPool.rememberOne(signedTx), addresses[1].String())
}

func TestRememberForget(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	numOfAccounts := 5
	secrets, addresses := generateAccounts(numOfAccounts)

	mockLedger := makeMockLedger(t, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(mockLedger, cfg, logging.Base(), nil)

	eval := newBlockEvaluator(t, mockLedger)

	for i, sender := range addresses {
		for j, receiver := range addresses {
			if sender != receiver {
				tx := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:      sender,
						Fee:         basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
						FirstValid:  0,
						LastValid:   basics.Round(proto.MaxTxnLife),
						Note:        make([]byte, 2),
						GenesisHash: mockLedger.GenesisHash(),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: 1},
					},
				}
				tx.Note[0] = byte(i)
				tx.Note[1] = byte(j)
				signedTx := tx.Sign(secrets[i])
				transactionPool.rememberOne(signedTx)
				err := eval.Transaction(signedTx, transactions.ApplyData{})
				require.NoError(t, err)
			}
		}
	}

	pending := transactionPool.PendingTxGroups()
	numberOfTxns := numOfAccounts*numOfAccounts - numOfAccounts
	require.Len(t, pending, numberOfTxns)

	ufblk, err := eval.GenerateBlock(nil)
	require.NoError(t, err)

	blk := ledgercore.MakeValidatedBlock(ufblk.UnfinishedBlock(), ufblk.UnfinishedDeltas())
	err = mockLedger.AddValidatedBlock(blk, agreement.Certificate{})
	require.NoError(t, err)
	transactionPool.OnNewBlock(blk.Block(), ledgercore.StateDelta{})

	pending = transactionPool.PendingTxGroups()
	require.Len(t, pending, 0)
}

// Test that clean up works
func TestCleanUp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	secrets, addresses := generateAccounts(10)

	mockLedger := makeMockLedger(t, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(mockLedger, cfg, logging.Base(), nil)

	issuedTransactions := 0
	for i, sender := range addresses {
		for j, receiver := range addresses {
			if sender != receiver {
				tx := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:      sender,
						Fee:         basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
						FirstValid:  0,
						LastValid:   5,
						Note:        make([]byte, 2),
						GenesisHash: mockLedger.GenesisHash(),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: 1},
					},
				}
				tx.Note[0] = byte(i)
				tx.Note[1] = byte(j)
				signedTx := tx.Sign(secrets[i])
				require.NoError(t, transactionPool.rememberOne(signedTx))
				issuedTransactions++
			}
		}
	}

	for mockLedger.Latest() < 6 {
		eval := newBlockEvaluator(t, mockLedger)
		ufblk, err := eval.GenerateBlock(nil)
		require.NoError(t, err)

		blk := ledgercore.MakeValidatedBlock(ufblk.UnfinishedBlock(), ufblk.UnfinishedDeltas())
		err = mockLedger.AddValidatedBlock(blk, agreement.Certificate{})
		require.NoError(t, err)

		transactionPool.OnNewBlock(blk.Block(), ledgercore.StateDelta{})
	}

	pending := transactionPool.PendingTxGroups()
	require.Zero(t, len(pending))
	require.Zero(t, transactionPool.numExpired(4))
	require.Equal(t, issuedTransactions, transactionPool.numExpired(5))

	for mockLedger.Latest() < 6+basics.Round(expiredHistory*proto.MaxTxnLife) {
		eval := newBlockEvaluator(t, mockLedger)
		ufblk, err := eval.GenerateBlock(nil)
		require.NoError(t, err)

		blk := ledgercore.MakeValidatedBlock(ufblk.UnfinishedBlock(), ufblk.UnfinishedDeltas())
		err = mockLedger.AddValidatedBlock(blk, agreement.Certificate{})
		require.NoError(t, err)

		transactionPool.OnNewBlock(blk.Block(), ledgercore.StateDelta{})
		require.Zero(t, transactionPool.numExpired(blk.Block().Round()))
	}
	require.Len(t, transactionPool.expiredTxCount, int(expiredHistory*proto.MaxTxnLife))
}

func TestFixOverflowOnNewBlock(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	secrets, addresses := generateAccounts(10)

	mockLedger := makeMockLedger(t, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(mockLedger, cfg, logging.Base(), nil)

	overSpender := addresses[0]
	var overSpenderAmount uint64
	savedTransactions := 0
	for i, sender := range addresses {
		amount := uint64(0)
		for _, receiver := range addresses {
			if sender != receiver {
				tx := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:      sender,
						Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee + amount},
						FirstValid:  0,
						LastValid:   10,
						Note:        make([]byte, 0),
						GenesisHash: mockLedger.GenesisHash(),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: 0},
					},
				}
				amount++

				if sender == overSpender {
					overSpenderAmount += tx.Fee.Raw
				}

				signedTx := tx.Sign(secrets[i])
				require.NoError(t, transactionPool.rememberOne(signedTx))
				savedTransactions++
			}
		}
	}
	pending := transactionPool.PendingTxGroups()
	require.Len(t, pending, savedTransactions)

	secret := keypair()
	recv := basics.Address(secret.SignatureVerifier)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      overSpender,
			Fee:         basics.MicroAlgos{Raw: 1<<32 - proto.MinBalance - overSpenderAmount + proto.MinTxnFee},
			FirstValid:  0,
			LastValid:   10,
			Note:        []byte{1},
			GenesisHash: mockLedger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: recv,
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}
	signedTx := tx.Sign(secrets[0])

	blockEval := newBlockEvaluator(t, mockLedger)
	err := blockEval.Transaction(signedTx, transactions.ApplyData{})
	require.NoError(t, err)

	// simulate this transaction was applied
	ufblk, err := blockEval.GenerateBlock(nil)
	require.NoError(t, err)

	block := ledgercore.MakeValidatedBlock(ufblk.UnfinishedBlock(), ufblk.UnfinishedDeltas())
	err = mockLedger.AddValidatedBlock(block, agreement.Certificate{})
	require.NoError(t, err)

	transactionPool.OnNewBlock(block.Block(), ledgercore.StateDelta{})

	pending = transactionPool.PendingTxGroups()
	// only one transaction is missing
	require.Len(t, pending, savedTransactions-1)
}

func TestOverspender(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	secrets, addresses := generateAccounts(2)

	overSpender := addresses[0]
	receiver := addresses[1]
	ledger := makeMockLedger(t, initAcc(map[basics.Address]uint64{
		overSpender: proto.MinTxnFee + 10,
		receiver:    proto.MinBalance, // Allows receive of small pay
	}))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      overSpender,
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  0,
			LastValid:   10,
			Note:        make([]byte, 0),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 11},
		},
	}

	signedTx := tx.Sign(secrets[0])
	require.ErrorContains(t, transactionPool.rememberOne(signedTx),
		"overspend (account "+overSpender.String())

	tx.Amount = basics.MicroAlgos{Raw: 10}
	signedTx = tx.Sign(secrets[0])
	require.NoError(t, transactionPool.rememberOne(signedTx))
}

func TestRemove(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	secrets, addresses := generateAccounts(2)

	ledger := makeMockLedger(t, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)

	sender := addresses[0]
	receiver := addresses[1]
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
			FirstValid:  0,
			LastValid:   10,
			Note:        []byte{0},
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}
	signedTx := tx.Sign(secrets[0])
	require.NoError(t, transactionPool.rememberOne(signedTx))
	require.Equal(t, transactionPool.PendingTxGroups(), [][]transactions.SignedTxn{{signedTx}})
}

func TestLogicSigOK(t *testing.T) {
	partitiontest.PartitionTest(t)
	// t.Parallel() manipulates config.Consensus

	oparams := config.Consensus[protocol.ConsensusCurrentVersion]
	params := oparams
	params.LogicSigMaxCost = 20000
	params.LogicSigMaxSize = 1000
	params.LogicSigVersion = 1
	config.Consensus[protocol.ConsensusCurrentVersion] = params
	defer func() {
		config.Consensus[protocol.ConsensusCurrentVersion] = oparams
	}()
	_, addresses := generateAccounts(5)

	src := `int 1`
	ops, err := logic.AssembleString(src)
	require.NoError(t, err)
	programAddress := logic.HashProgram(ops.Program)
	addresses[0] = basics.Address(programAddress)

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance + proto.MinTxnFee
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[0],
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid:  1,
			LastValid:   basics.Round(proto.MaxTxnLife),
			Note:        make([]byte, 2),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: minBalance},
		},
	}
	signedTx := transactions.SignedTxn{
		Txn: tx,
		Lsig: transactions.LogicSig{
			Logic: ops.Program,
		},
	}
	require.NoError(t, transactionPool.rememberOne(signedTx))
}

func TestTransactionPoolEnforcesTax(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	const numAccounts = 5
	secrets, addresses := generateAccounts(5)
	proto := config.Consensus[protocol.ConsensusFuture]

	ledger := makeMockLedgerFuture(t, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)

	blockSize := proto.MaxTxnBytesPerBlock
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     addresses[0],
			Fee:        proto.MinFee(),
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 8),
			// no genesis hash, since it is removed in stib
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[0],
			Amount:   proto.MinFee(),
		},
	}
	crypto.RandBytes(tx.Note)
	signedTx := tx.Sign(secrets[0])
	paySize := len(protocol.Encode(&transactions.SignedTxnInBlock{
		SignedTxnWithAD: transactions.SignedTxnWithAD{SignedTxn: signedTx},
	}))
	// size estimates aren't perfect, we can get 1 more in.
	for i := range blockSize/paySize + 1 {
		sender := addresses[i%numAccounts]
		receiver := addresses[(i+1)%numAccounts]
		tx := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      sender,
				Fee:         proto.MinFee(),
				FirstValid:  0,
				LastValid:   basics.Round(proto.MaxTxnLife),
				Note:        make([]byte, 8),
				GenesisHash: ledger.GenesisHash(),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: receiver,
				Amount:   proto.MinFee(),
			},
		}
		crypto.RandBytes(tx.Note)
		signedTx := tx.Sign(secrets[i%numAccounts])
		err := transactionPool.rememberOne(signedTx)
		require.NoError(t, err)
	}

	// But now the pool is simulating the next block after a full, so tax is 10%
	tx = transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      addresses[1],
			Fee:         proto.MinFee(),
			FirstValid:  0,
			LastValid:   2,
			Note:        make([]byte, 8),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[2],
			Amount:   proto.MinFee(),
		},
	}
	crypto.RandBytes(tx.Note)
	signedTx = tx.Sign(secrets[1])
	err := transactionPool.rememberOne(signedTx)
	require.ErrorContains(t, err, "insufficient extra fees to cover 0.100000 congestion tax")

	tx.Tip = 99_999
	signedTx = tx.Sign(secrets[1])
	err = transactionPool.rememberOne(signedTx)
	require.ErrorContains(t, err, "insufficient extra fees to cover 0.100000 congestion tax")

	// Now we've specified a Tip, so the failure is that the fee wasn't enough to
	// pay that much.
	tx.Tip = 100_000
	signedTx = tx.Sign(secrets[1])
	err = transactionPool.rememberOne(signedTx)
	require.ErrorContains(t, err, "fees is less than")

	var o bool
	tx.Fee, o = tx.Fee.MulMicros(1.1e6)
	require.False(t, o)
	signedTx = tx.Sign(secrets[1])
	err = transactionPool.rememberOne(signedTx)
	require.NoError(t, err)

	// while we're here, let's test that the pool reject LastValid=1 now, since
	// it's planning ahead for block 2.
	tx.LastValid = 1
	signedTx = tx.Sign(secrets[1])
	err = transactionPool.rememberOne(signedTx)
	require.ErrorContains(t, err, "round 2 outside of 0--1")
}

func BenchmarkTransactionPoolRememberOne(b *testing.B) {
	secrets, addresses := generateAccounts(5)

	ledger := makeMockLedger(b, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = b.N
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)
	signedTransactions := make([]transactions.SignedTxn, 0, b.N)
	for i, sender := range addresses {
		for j := 0; j < b.N/len(addresses); j++ {
			var receiver basics.Address
			crypto.RandBytes(receiver[:])
			tx := transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender:      sender,
					Fee:         basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
					FirstValid:  0,
					LastValid:   basics.Round(proto.MaxTxnLife),
					Note:        make([]byte, 2),
					GenesisHash: ledger.GenesisHash(),
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: receiver,
					Amount:   basics.MicroAlgos{Raw: proto.MinBalance},
				},
			}
			tx.Note = make([]byte, 8)
			crypto.RandBytes(tx.Note)
			signedTx := tx.Sign(secrets[i])
			signedTransactions = append(signedTransactions, signedTx)
			err := transactionPool.rememberOne(signedTx)
			require.NoError(b, err)
		}
	}
	b.StopTimer()
	b.ResetTimer()
	ledger = makeMockLedger(b, initAccFixed(addresses, 1<<32))
	transactionPool = MakeTransactionPool(ledger, cfg, logging.Base(), nil)

	b.StartTimer()
	for _, signedTx := range signedTransactions {
		transactionPool.rememberOne(signedTx)
	}
}

func BenchmarkTransactionPoolPending(b *testing.B) {
	secrets, addresses := generateAccounts(5)

	sub := func(b *testing.B, benchPoolSize int) {
		b.StopTimer()
		b.ResetTimer()

		ledger := makeMockLedger(b, initAccFixed(addresses, 1<<32))
		cfg := config.GetDefaultLocal()
		cfg.TxPoolSize = benchPoolSize
		transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)
		var block bookkeeping.Block
		block.Payset = make(transactions.Payset, 0)

		for i, sender := range addresses {
			for j := 0; j < benchPoolSize/len(addresses); j++ {
				var receiver basics.Address
				crypto.RandBytes(receiver[:])
				tx := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:      sender,
						Fee:         basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
						FirstValid:  0,
						LastValid:   basics.Round(proto.MaxTxnLife),
						Note:        make([]byte, 2),
						GenesisHash: ledger.GenesisHash(),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: proto.MinBalance},
					},
				}
				tx.Note = make([]byte, 8)
				crypto.RandBytes(tx.Note)
				signedTx := tx.Sign(secrets[i])
				err := transactionPool.rememberOne(signedTx)
				require.NoError(b, err)
			}
		}

		b.StartTimer()
		for i := 0; i < b.N; i++ {
			transactionPool.PendingTxGroups()
		}
	}
	subs := []int{1000, 5000, 10000, 25000, 50000}
	for _, bps := range subs {
		b.Run(fmt.Sprintf("PendingTxGroups-%d", bps), func(b *testing.B) {
			sub(b, bps)
		})
	}
}

// BenchmarkTransactionPoolRecompute attempts to build a transaction pool of 3x block size
// and then calls recomputeBlockEvaluator, to update the pool given the just-committed txns.
// For b.N is does this process repeatedly given the size of N.
func BenchmarkTransactionPoolRecompute(b *testing.B) {
	b.Log("Running with b.N", b.N)
	poolSize := 100000
	numOfAccounts := 100
	numTransactions := 75000
	blockTxnCount := 25000

	myVersion := protocol.ConsensusVersion("test-large-blocks")
	myProto := config.Consensus[protocol.ConsensusCurrentVersion]
	if myProto.MaxTxnBytesPerBlock != 5*1024*1024 {
		b.FailNow() // intended to use with 5MB blocks
	}
	config.Consensus[myVersion] = myProto

	secrets, addresses := generateAccounts(numOfAccounts)

	l := mockLedger(b, initAccFixed(addresses, 1<<50), myVersion)
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = poolSize

	setupPool := func() (*TransactionPool, map[transactions.Txid]ledgercore.IncludedTransactions, uint) {
		transactionPool := MakeTransactionPool(l, cfg, logging.Base(), nil)

		// make some transactions
		var signedTransactions []transactions.SignedTxn
		for i := 0; i < numTransactions; i++ {
			tx := transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender:      addresses[i%numOfAccounts],
					Fee:         basics.MicroAlgos{Raw: 20000 + proto.MinTxnFee},
					FirstValid:  0,
					LastValid:   basics.Round(proto.MaxTxnLife),
					GenesisHash: l.GenesisHash(),
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: addresses[rand.Intn(numOfAccounts)],
					Amount:   basics.MicroAlgos{Raw: proto.MinBalance + uint64(rand.Intn(1<<32))},
				},
			}

			signedTx := tx.Sign(secrets[i%numOfAccounts])
			signedTransactions = append(signedTransactions, signedTx)
			require.NoError(b, transactionPool.rememberOne(signedTx))
		}

		// make args for recomputeBlockEvaluator() like OnNewBlock() would
		var knownCommitted uint
		committedTxIDs := make(map[transactions.Txid]ledgercore.IncludedTransactions)
		for i := 0; i < blockTxnCount; i++ {
			knownCommitted++
			// OK to use empty IncludedTransactions: recomputeBlockEvaluator is only checking map membership
			committedTxIDs[signedTransactions[i].ID()] = ledgercore.IncludedTransactions{}
		}
		b.Logf("Made transactionPool with %d signedTransactions, %d committedTxIDs, %d knownCommitted",
			len(signedTransactions), len(committedTxIDs), knownCommitted)
		b.Logf("transactionPool pendingTxGroups %d rememberedTxGroups %d",
			len(transactionPool.pendingTxGroups), len(transactionPool.rememberedTxGroups))
		return transactionPool, committedTxIDs, knownCommitted
	}

	transactionPool := make([]*TransactionPool, b.N)
	committedTxIDs := make([]map[transactions.Txid]ledgercore.IncludedTransactions, b.N)
	knownCommitted := make([]uint, b.N)
	for i := 0; i < b.N; i++ {
		transactionPool[i], committedTxIDs[i], knownCommitted[i] = setupPool()
	}
	time.Sleep(time.Second)
	runtime.GC()
	// CPU profiler if CPUPROFILE set
	var profF *os.File
	if os.Getenv("CPUPROFILE") != "" {
		var err error
		profF, err = os.Create(fmt.Sprintf("recomputePool-%d-%d.prof", b.N, crypto.RandUint64()))
		require.NoError(b, err)
	}

	// call recomputeBlockEvaluator
	if profF != nil {
		pprof.StartCPUProfile(profF)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transactionPool[i].recomputeBlockEvaluator(committedTxIDs[i], knownCommitted[i])
	}
	b.StopTimer()
	if profF != nil {
		pprof.StopCPUProfile()
	}
}

func BenchmarkTransactionPoolSteadyState(b *testing.B) {
	poolSize := 100000

	fmt.Printf("BenchmarkTransactionPoolSteadyState: N=%d\n", b.N)

	numOfAccounts := 100
	_, addresses := generateAccounts(numOfAccounts)

	l := makeMockLedger(b, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = poolSize
	transactionPool := MakeTransactionPool(l, cfg, logging.Base(), nil)

	var signedTransactions []transactions.SignedTxn
	for i := 0; i < b.N; i++ {
		var receiver basics.Address
		crypto.RandBytes(receiver[:])
		tx := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      addresses[i%numOfAccounts],
				Fee:         basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
				FirstValid:  0,
				LastValid:   basics.Round(proto.MaxTxnLife),
				GenesisHash: l.GenesisHash(),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: receiver,
				Amount:   basics.MicroAlgos{Raw: proto.MinBalance},
			},
		}
		tx.Note = make([]byte, 8)
		crypto.RandBytes(tx.Note)

		signedTx, err := transactions.AssembleSignedTxn(tx, crypto.Signature{}, crypto.MultisigSig{})
		require.NoError(b, err)
		signedTransactions = append(signedTransactions, signedTx)
	}

	b.StopTimer()
	b.ResetTimer()
	b.StartTimer()

	poolTxnQueue := signedTransactions
	var ledgerTxnQueue []transactions.SignedTxn

	for len(poolTxnQueue) > 0 || len(ledgerTxnQueue) > 0 {
		// Fill up txpool
		for len(poolTxnQueue) > 0 {
			stx := poolTxnQueue[0]
			err := transactionPool.rememberOne(stx)
			if err == nil {
				poolTxnQueue = poolTxnQueue[1:]
				ledgerTxnQueue = append(ledgerTxnQueue, stx)
				continue
			}
			if strings.Contains(err.Error(), "transaction pool is full") {
				break
			}
			require.NoError(b, err)
		}

		// Commit a block
		eval := newBlockEvaluator(b, l)
		for len(ledgerTxnQueue) > 0 {
			stx := ledgerTxnQueue[0]
			err := eval.Transaction(stx, transactions.ApplyData{})
			if err == ledgercore.ErrNoSpace {
				break
			}
			require.NoError(b, err)
			ledgerTxnQueue = ledgerTxnQueue[1:]
		}

		ufblk, err := eval.GenerateBlock(nil)
		require.NoError(b, err)

		blk := ledgercore.MakeValidatedBlock(ufblk.UnfinishedBlock(), ufblk.UnfinishedDeltas())
		err = l.AddValidatedBlock(blk, agreement.Certificate{})
		require.NoError(b, err)

		transactionPool.OnNewBlock(blk.Block(), ledgercore.StateDelta{})

		fmt.Printf("BenchmarkTransactionPoolSteadyState: committed block %d\n", blk.Block().Round())
	}
}

func TestTxPoolSizeLimits(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	secrets, addresses := generateAccounts(2)

	firstAddress := addresses[0]
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = 1000 // ensure we don't go over one block

	ledger := makeMockLedger(t, initAcc(map[basics.Address]uint64{firstAddress: proto.MinBalance + 2*proto.MinTxnFee*uint64(cfg.TxPoolSize)}))

	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base(), nil)

	receiver := addresses[1]

	uniqueTxID := 0
	// almost fill the transaction pool, leaving room for one additional
	// transaction group of size 2.
	const leftover = 2
	for range cfg.TxPoolSize - leftover {
		tx := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      firstAddress,
				Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
				FirstValid:  0,
				LastValid:   10,
				Note:        []byte{byte(uniqueTxID), byte(uniqueTxID >> 8), byte(uniqueTxID >> 16)},
				GenesisHash: ledger.GenesisHash(),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: receiver,
				Amount:   basics.MicroAlgos{Raw: 0},
			},
		}
		signedTx := tx.Sign(secrets[0])
		require.NoError(t, transactionPool.rememberOne(signedTx))
		uniqueTxID++
	}

	for groupSize := config.Consensus[protocol.ConsensusCurrentVersion].MaxTxGroupSize; groupSize > leftover; groupSize-- {
		var txgroup []transactions.SignedTxn
		// fill the transaction group with groupSize transactions.
		for i := 0; i < groupSize; i++ {
			tx := transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender:      firstAddress,
					Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
					FirstValid:  0,
					LastValid:   10,
					Note:        []byte{byte(uniqueTxID), byte(uniqueTxID >> 8), byte(uniqueTxID >> 16)},
					GenesisHash: ledger.GenesisHash(),
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: receiver,
					Amount:   basics.MicroAlgos{Raw: 0},
				},
			}
			signedTx := tx.Sign(secrets[0])
			txgroup = append(txgroup, signedTx)
			uniqueTxID++
		}

		// We're playing fast and loose by not setting Group properly.  But the
		// assertion indicates we're covering the right error.
		require.ErrorContains(t, transactionPool.Remember(txgroup),
			"transaction pool has reached capacity")
	}

	// Now show those last ones go in.
	for range leftover {
		tx := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      firstAddress,
				Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
				FirstValid:  0,
				LastValid:   10,
				Note:        []byte{byte(uniqueTxID), byte(uniqueTxID >> 8), byte(uniqueTxID >> 16)},
				GenesisHash: ledger.GenesisHash(),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: receiver,
				Amount:   basics.MicroAlgos{Raw: 0},
			},
		}
		signedTx := tx.Sign(secrets[0])
		require.NoError(t, transactionPool.rememberOne(signedTx))
		uniqueTxID++
	}
}

func TestStateProofLogging(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	cfg := config.GetDefaultLocal()

	const numOfAccounts = 20
	_, addresses := generateAccounts(numOfAccounts)
	initAccounts := initAccFixed(addresses, 1_000_000_000)

	// Prepare the SP signing keys
	allKeys := make([]*merklesignature.Secrets, 0, 3)
	stateproofIntervals := uint64(256)
	for a := 2; a < numOfAccounts; a++ {
		keys, err := merklesignature.New(0, 512, stateproofIntervals)
		require.NoError(t, err)

		acct := initAccounts[addresses[a]]
		acct.StateProofID = keys.GetVerifier().Commitment
		acct.Status = basics.Online
		acct.VoteLastValid = 100000
		initAccounts[addresses[a]] = acct

		allKeys = append(allKeys, keys)
	}

	// Set the logging to capture the telemetry Metrics into logging
	logger := logging.TestingLog(t)
	logger.SetLevel(logging.Info)
	logger.EnableTelemetryContext(context.Background(), logging.TelemetryConfig{Enable: true, SendToLog: true})
	var buf bytes.Buffer
	logger.SetOutput(&buf)

	// Set the ledger and the transaction pool
	mockLedger := makeMockLedger(t, initAccounts)
	transactionPool := MakeTransactionPool(mockLedger, cfg, logger, nil)
	transactionPool.logAssembleStats = true

	// Set the first round block
	var b bookkeeping.Block
	b.BlockHeader.GenesisID = "pooltest"
	b.BlockHeader.GenesisHash = mockLedger.GenesisHash()
	b.CurrentProtocol = protocol.ConsensusCurrentVersion
	b.BlockHeader.Round = 1
	b.BlockHeader.Bonus = basics.MicroAlgos{Raw: 10000000}

	phdr, err := mockLedger.BlockHdr(0)
	require.NoError(t, err)
	b.BlockHeader.Branch = phdr.Hash()
	if proto.EnableSha512BlockHash {
		b.BlockHeader.Branch512 = phdr.Hash512()
	}

	_, err = mockLedger.StartEvaluator(b.BlockHeader, 0, 10000, nil)
	require.NoError(t, err)

	// Simulate the blocks up to round 512 without any transactions
	for i := 1; true; i++ {
		ufblk, err := transactionPool.AssembleBlock(basics.Round(i), time.Time{})
		require.NoError(t, err)

		blk := ledgercore.MakeValidatedBlock(ufblk.UnfinishedBlock(), ufblk.UnfinishedDeltas())
		err = mockLedger.AddValidatedBlock(blk, agreement.Certificate{})
		require.NoError(t, err)

		// Move to the next round
		b.BlockHeader.Round++
		transactionPool.OnNewBlock(blk.Block(), ledgercore.StateDelta{})

		phdr, err := mockLedger.BlockHdr(basics.Round(i))
		require.NoError(t, err)
		b.BlockHeader.Branch = phdr.Hash()
		if proto.EnableSha512BlockHash {
			b.BlockHeader.Branch512 = phdr.Hash512()
		}
		b.BlockHeader.TimeStamp = phdr.TimeStamp + 10

		if i == 513 {
			break
		}

		_, err = mockLedger.StartEvaluator(b.BlockHeader, 0, 10000, nil)
		require.NoError(t, err)
	}

	// Prepare the transaction with the SP
	round := basics.Round(512)
	spRoundHdr, err := mockLedger.BlockHdr(round)
	require.NoError(t, err)

	votersRound := round.SubSaturate(basics.Round(proto.StateProofInterval))
	votersRoundHdr, err := mockLedger.BlockHdr(votersRound)
	require.NoError(t, err)

	provenWeight, err := verify.GetProvenWeight(&votersRoundHdr, &spRoundHdr)
	require.NoError(t, err)

	lookback := votersRound.SubSaturate(basics.Round(proto.StateProofVotersLookback))
	voters, err := mockLedger.VotersForStateProof(lookback)
	require.NoError(t, err)
	require.NotNil(t, voters)

	// Get the message
	msg, err := stateproof.GenerateStateProofMessage(mockLedger, round)

	// Get the SP
	proof := generateProofForTesting(uint64(round), msg, provenWeight, voters.Participants, voters.Tree, allKeys, t)

	// Set the transaction with the SP
	var stxn transactions.SignedTxn
	stxn.Txn.Type = protocol.StateProofTx
	stxn.Txn.Sender = transactions.StateProofSender
	stxn.Txn.FirstValid = 512
	stxn.Txn.LastValid = 1024
	stxn.Txn.GenesisHash = mockLedger.GenesisHash()
	stxn.Txn.StateProofType = protocol.StateProofBasic
	stxn.Txn.StateProof = *proof
	require.NoError(t, err)
	stxn.Txn.Message = msg

	err = stxn.Txn.WellFormed(transactions.SpecialAddresses{}, proto)
	require.NoError(t, err)

	// Add it to the transaction pool and assemble the block
	eval, err := mockLedger.StartEvaluator(b.BlockHeader, 0, 1000000, nil)
	require.NoError(t, err)

	err = eval.Transaction(stxn, transactions.ApplyData{})
	require.NoError(t, err)

	err = transactionPool.rememberOne(stxn)
	require.NoError(t, err)
	transactionPool.recomputeBlockEvaluator(nil, 0)
	_, err = transactionPool.AssembleBlock(514, time.Time{})
	require.NoError(t, err)

	// parse the log messages and retrieve the Metrics for SP in assemble block
	scanner := bufio.NewScanner(strings.NewReader(buf.String()))
	lines := make([]string, 0)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	fmt.Println(lines[len(lines)-1])
	// Verify that the StateProofNextRound is added when there are no transactions
	var int1, nextRound uint64
	var str1 string
	partsNext := strings.Split(lines[len(lines)-10], "TransactionsLoopStartTime:")
	fmt.Sscanf(partsNext[1], "%d, StateProofNextRound:%d, %s", &int1, &nextRound, &str1)
	require.Equal(t, int(512), int(nextRound))

	parts := strings.Split(lines[len(lines)-1], "StateProofNextRound:")

	// Verify the Metrics is correct
	var pWeight, signedWeight, numReveals, posToReveal, txnSize uint64
	fmt.Sscanf(parts[1], "%d, ProvenWeight:%d, SignedWeight:%d, NumReveals:%d, NumPosToReveal:%d, TxnSize:%d\"%s",
		&nextRound, &pWeight, &signedWeight, &numReveals, &posToReveal, &txnSize, &str1)
	require.Equal(t, uint64(768), nextRound)
	require.Equal(t, provenWeight, pWeight)
	require.Equal(t, proof.SignedWeight, signedWeight)
	require.Less(t, numOfAccounts/2, int(numReveals))
	require.Greater(t, numOfAccounts, int(numReveals))
	require.Equal(t, len(proof.PositionsToReveal), int(posToReveal))
	stxn.Txn.GenesisHash = crypto.Digest{}
	require.Equal(t, stxn.GetEncodedLength(), int(txnSize))
}

// Given the round number, partArray and partTree from the previous period block, the keys and the totalWeight
// return a stateProof which can be submitted in a transaction to the transaction pool and assembled into a new block.
func generateProofForTesting(
	round uint64,
	msg stateproofmsg.Message,
	provenWeight uint64,
	partArray basics.ParticipantsArray,
	partTree *merklearray.Tree,
	allKeys []*merklesignature.Secrets,
	t *testing.T) *cryptostateproof.StateProof {

	data := msg.Hash()

	// Sign with the participation keys
	sigs := make(map[merklesignature.Verifier]merklesignature.Signature)
	for _, keys := range allKeys {
		signerInRound := keys.GetSigner(round)
		sig, err := signerInRound.SignBytes(data[:])
		require.NoError(t, err)
		sigs[*keys.GetVerifier()] = sig
	}

	// Prepare the builder
	stateProofStrengthTargetForTests := config.Consensus[protocol.ConsensusCurrentVersion].StateProofStrengthTarget
	b, err := cryptostateproof.MakeProver(data, round, provenWeight,
		partArray, partTree, stateProofStrengthTargetForTests)
	require.NoError(t, err)

	// Add the signatures
	for i := range partArray {
		p, err := b.Present(uint64(i))
		require.False(t, p)
		require.NoError(t, err)
		s := sigs[partArray[i].PK]
		err = b.IsValid(uint64(i), &s, true)
		require.NoError(t, err)
		b.Add(uint64(i), s)

		// sanity check that the builder add the signature
		isPresent, err := b.Present(uint64(i))
		require.NoError(t, err)
		require.True(t, isPresent)
	}

	// Build the SP
	proof, err := b.CreateProof()
	require.NoError(t, err)

	return proof
}
