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

package pools

import (
	"bufio"
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
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
	l, err := ledger.OpenLedger(logging.Base(), fn, true, genesisInitState, cfg)
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
	eval, err := l.StartEvaluator(next.BlockHeader, 0, 0)
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

const testPoolSize = 1000

func TestMinBalanceOK(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 5
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance + proto.MinTxnFee
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base())

	// sender goes below min
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
	require.NoError(t, transactionPool.RememberOne(signedTx))
}

func TestSenderGoesBelowMinBalance(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 5
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance + proto.MinTxnFee
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base())

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
	require.Error(t, transactionPool.RememberOne(signedTx))
}

func TestSenderGoesBelowMinBalanceDueToAssets(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 5
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}
	proto := config.Consensus[protocol.ConsensusFuture]

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 3*minBalance + 2*proto.MinTxnFee
	ledger := makeMockLedgerFuture(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base())

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
	require.NoError(t, transactionPool.RememberOne(signedAssetTx))

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
	err := transactionPool.RememberOne(signedTx)
	require.Error(t, err)
	var returnedTxid, returnedAcct string
	var returnedBal, returnedMin, numAssets uint64
	_, err = fmt.Sscanf(err.Error(), "TransactionPool.Remember: transaction %s account %s balance %d below min %d (%d assets)",
		&returnedTxid, &returnedAcct, &returnedBal, &returnedMin, &numAssets)
	require.NoError(t, err)
	require.Equal(t, (1+numAssets)*proto.MinBalance, returnedMin)
}

func TestCloseAccount(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 5
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 3*minBalance + 2*proto.MinTxnFee
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base())

	// sender goes below min
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
	require.NoError(t, transactionPool.RememberOne(signedTx))

	// sender goes below min
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
	require.Error(t, transactionPool.RememberOne(signedTx2))
}

func TestCloseAccountWhileTxIsPending(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 5
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance + 2*proto.MinTxnFee - 1
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base())

	// sender goes below min
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
	require.NoError(t, transactionPool.RememberOne(signedTx))

	// sender goes below min
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
	require.Error(t, transactionPool.RememberOne(signedCloseTx))
}

func TestClosingAccountBelowMinBalance(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 5
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance - 1 + proto.MinTxnFee
	limitedAccounts[addresses[2]] = 0
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base())

	// sender goes below min
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
	require.Error(t, transactionPool.RememberOne(signedTx))
}

func TestRecipientGoesBelowMinBalance(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 5
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[1]] = 0
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base())

	// sender goes below min
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
	require.Error(t, transactionPool.RememberOne(signedTx))
}

func TestRememberForget(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 5
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	mockLedger := makeMockLedger(t, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(mockLedger, cfg, logging.Base())

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
				transactionPool.RememberOne(signedTx)
				err := eval.Transaction(signedTx, transactions.ApplyData{})
				require.NoError(t, err)
			}
		}
	}

	pending := transactionPool.PendingTxGroups()
	numberOfTxns := numOfAccounts*numOfAccounts - numOfAccounts
	require.Len(t, pending, numberOfTxns)

	blk, err := eval.GenerateBlock()
	require.NoError(t, err)

	err = mockLedger.AddValidatedBlock(*blk, agreement.Certificate{})
	require.NoError(t, err)
	transactionPool.OnNewBlock(blk.Block(), ledgercore.StateDelta{})

	pending = transactionPool.PendingTxGroups()
	require.Len(t, pending, 0)
}

//	Test that clean up works
func TestCleanUp(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 10
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	mockLedger := makeMockLedger(t, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(mockLedger, cfg, logging.Base())

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
				require.NoError(t, transactionPool.RememberOne(signedTx))
				issuedTransactions++
			}
		}
	}

	for mockLedger.Latest() < 6 {
		eval := newBlockEvaluator(t, mockLedger)
		blk, err := eval.GenerateBlock()
		require.NoError(t, err)

		err = mockLedger.AddValidatedBlock(*blk, agreement.Certificate{})
		require.NoError(t, err)

		transactionPool.OnNewBlock(blk.Block(), ledgercore.StateDelta{})
	}

	pending := transactionPool.PendingTxGroups()
	require.Zero(t, len(pending))
	require.Zero(t, transactionPool.NumExpired(4))
	require.Equal(t, issuedTransactions, transactionPool.NumExpired(5))

	for mockLedger.Latest() < 6+basics.Round(expiredHistory*proto.MaxTxnLife) {
		eval := newBlockEvaluator(t, mockLedger)
		blk, err := eval.GenerateBlock()
		require.NoError(t, err)

		err = mockLedger.AddValidatedBlock(*blk, agreement.Certificate{})
		require.NoError(t, err)

		transactionPool.OnNewBlock(blk.Block(), ledgercore.StateDelta{})
		require.Zero(t, transactionPool.NumExpired(blk.Block().Round()))
	}
	require.Len(t, transactionPool.expiredTxCount, int(expiredHistory*proto.MaxTxnLife))
}

func TestFixOverflowOnNewBlock(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 10
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	mockLedger := makeMockLedger(t, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(mockLedger, cfg, logging.Base())

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
				require.NoError(t, transactionPool.RememberOne(signedTx))
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
	block, err := blockEval.GenerateBlock()
	require.NoError(t, err)

	err = mockLedger.AddValidatedBlock(*block, agreement.Certificate{})
	require.NoError(t, err)

	transactionPool.OnNewBlock(block.Block(), ledgercore.StateDelta{})

	pending = transactionPool.PendingTxGroups()
	// only one transaction is missing
	require.Len(t, pending, savedTransactions-1)
}

func TestOverspender(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 2
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	overSpender := addresses[0]
	ledger := makeMockLedger(t, initAcc(map[basics.Address]uint64{overSpender: proto.MinTxnFee - 1}))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base())

	receiver := addresses[1]
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      overSpender,
			Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
			FirstValid:  0,
			LastValid:   10,
			Note:        make([]byte, 0),
			GenesisHash: ledger.GenesisHash(),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}
	signedTx := tx.Sign(secrets[0])

	// consume the transaction of allowed limit
	require.Error(t, transactionPool.RememberOne(signedTx))

	// min transaction
	minTx := transactions.Transaction{
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
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}
	signedMinTx := minTx.Sign(secrets[0])
	require.Error(t, transactionPool.RememberOne(signedMinTx))
}

func TestRemove(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 2
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	ledger := makeMockLedger(t, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base())

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
	require.NoError(t, transactionPool.RememberOne(signedTx))
	require.Equal(t, transactionPool.PendingTxGroups(), [][]transactions.SignedTxn{{signedTx}})
}

func TestLogicSigOK(t *testing.T) {
	partitiontest.PartitionTest(t)

	oparams := config.Consensus[protocol.ConsensusCurrentVersion]
	params := oparams
	params.LogicSigMaxCost = 20000
	params.LogicSigMaxSize = 1000
	params.LogicSigVersion = 1
	config.Consensus[protocol.ConsensusCurrentVersion] = params
	defer func() {
		config.Consensus[protocol.ConsensusCurrentVersion] = oparams
	}()
	numOfAccounts := 5
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		addresses[i] = addr
	}

	src := `int 1`
	ops, err := logic.AssembleString(src)
	require.NoError(t, err)
	programAddress := logic.HashProgram(ops.Program)
	addresses[0] = basics.Address(programAddress)

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*minBalance + proto.MinTxnFee
	ledger := makeMockLedger(t, initAcc(limitedAccounts))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base())

	// sender goes below min
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
	require.NoError(t, transactionPool.RememberOne(signedTx))
}

func TestTransactionPool_CurrentFeePerByte(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 5
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	l := makeMockLedger(t, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize * 15
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(l, cfg, logging.Base())

	for i, sender := range addresses {
		for j := 0; j < testPoolSize*15/len(addresses); j++ {
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
					GenesisHash: l.GenesisHash(),
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: receiver,
					Amount:   basics.MicroAlgos{Raw: proto.MinBalance},
				},
			}
			tx.Note = make([]byte, 8, 8)
			crypto.RandBytes(tx.Note)
			signedTx := tx.Sign(secrets[i])
			err := transactionPool.RememberOne(signedTx)
			require.NoError(t, err)
		}
	}

	// The fee should be 1^(number of whole blocks - 1)
	require.Equal(t, uint64(1<<(transactionPool.numPendingWholeBlocks-1)), transactionPool.FeePerByte())

}

func BenchmarkTransactionPoolRememberOne(b *testing.B) {
	numOfAccounts := 5
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	ledger := makeMockLedger(b, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = b.N
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base())
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
			tx.Note = make([]byte, 8, 8)
			crypto.RandBytes(tx.Note)
			signedTx := tx.Sign(secrets[i])
			signedTransactions = append(signedTransactions, signedTx)
			err := transactionPool.RememberOne(signedTx)
			require.NoError(b, err)
		}
	}
	b.StopTimer()
	b.ResetTimer()
	ledger = makeMockLedger(b, initAccFixed(addresses, 1<<32))
	transactionPool = MakeTransactionPool(ledger, cfg, logging.Base())

	b.StartTimer()
	for _, signedTx := range signedTransactions {
		transactionPool.RememberOne(signedTx)
	}
}

func BenchmarkTransactionPoolPending(b *testing.B) {
	numOfAccounts := 5
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	sub := func(b *testing.B, benchPoolSize int) {
		b.StopTimer()
		b.ResetTimer()

		ledger := makeMockLedger(b, initAccFixed(addresses, 1<<32))
		cfg := config.GetDefaultLocal()
		cfg.TxPoolSize = benchPoolSize
		cfg.EnableProcessBlockStats = false
		transactionPool := MakeTransactionPool(ledger, cfg, logging.Base())
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
				tx.Note = make([]byte, 8, 8)
				crypto.RandBytes(tx.Note)
				signedTx := tx.Sign(secrets[i])
				err := transactionPool.RememberOne(signedTx)
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

func BenchmarkTransactionPoolSteadyState(b *testing.B) {
	poolSize := 100000

	fmt.Printf("BenchmarkTransactionPoolSteadyState: N=%d\n", b.N)

	numOfAccounts := 100
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	l := makeMockLedger(b, initAccFixed(addresses, 1<<32))
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = poolSize
	cfg.EnableProcessBlockStats = false
	transactionPool := MakeTransactionPool(l, cfg, logging.Base())

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
		tx.Note = make([]byte, 8, 8)
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
			err := transactionPool.RememberOne(stx)
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

		blk, err := eval.GenerateBlock()
		require.NoError(b, err)

		err = l.AddValidatedBlock(*blk, agreement.Certificate{})
		require.NoError(b, err)

		transactionPool.OnNewBlock(blk.Block(), ledgercore.StateDelta{})

		fmt.Printf("BenchmarkTransactionPoolSteadyState: committed block %d\n", blk.Block().Round())
	}
}

func TestTxPoolSizeLimits(t *testing.T) {
	partitiontest.PartitionTest(t)

	numOfAccounts := 2
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	firstAddress := addresses[0]
	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false

	ledger := makeMockLedger(t, initAcc(map[basics.Address]uint64{firstAddress: proto.MinBalance + 2*proto.MinTxnFee*uint64(cfg.TxPoolSize)}))

	transactionPool := MakeTransactionPool(ledger, cfg, logging.Base())

	receiver := addresses[1]

	uniqueTxID := 0
	// almost fill the transaction pool, leaving room for one additional transaction group of the biggest size.
	for i := 0; i <= cfg.TxPoolSize-config.Consensus[protocol.ConsensusCurrentVersion].MaxTxGroupSize; i++ {
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

		// consume the transaction of allowed limit
		require.NoError(t, transactionPool.RememberOne(signedTx))
		uniqueTxID++
	}

	for groupSize := config.Consensus[protocol.ConsensusCurrentVersion].MaxTxGroupSize; groupSize > 0; groupSize-- {
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

		// ensure that we would fail adding this.
		require.Error(t, transactionPool.Remember(txgroup))

		if groupSize > 1 {
			// add a single transaction and ensure we succeed
			// consume the transaction of allowed limit
			require.NoError(t, transactionPool.RememberOne(txgroup[0]))
		}
	}
}

func TestTStateProofLogging(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusFuture]

	cfg := config.GetDefaultLocal()
	cfg.TxPoolSize = testPoolSize
	cfg.EnableProcessBlockStats = false

	numOfAccounts := 3
	// Generate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	firstAddress := addresses[0]
	initAccounts := initAcc(map[basics.Address]uint64{
		firstAddress:                  proto.MinBalance*1000 + 2*proto.MinTxnFee*uint64(cfg.TxPoolSize),
		transactions.StateProofSender: 200000,
		addresses[1]:                  100000,
		addresses[2]:                  100000,
	})
	stateproofIntervals := uint64(256)
	keys, err := merklesignature.New(0, uint64(stateproofIntervals)*stateproofIntervals+1, stateproofIntervals)
	require.NoError(t, err)

	firstAcct := initAccounts[firstAddress]
	firstAcct.StateProofID = *keys.GetVerifier()
	initAccounts[firstAddress] = firstAcct
	acctData := initAccounts[addresses[0]]
	acctData.Status = basics.Online
	acctData.VoteLastValid = 1000000
	initAccounts[addresses[0]] = acctData
	ledger := makeMockLedgerFuture(t, initAccounts)

	var b bookkeeping.Block
	b.BlockHeader.GenesisID = "pooltest"
	b.BlockHeader.GenesisHash = ledger.GenesisHash()
	b.CurrentProtocol = protocol.ConsensusFuture

	b.BlockHeader.Round = 1

	logger := logging.TestingLog(t)
	logger.SetLevel(logging.Info)
	logger.EnableTelemetry(logging.TelemetryConfig{Enable: true, SendToLog: true})
	var buf bytes.Buffer
	logger.SetOutput(&buf)

	transactionPool := MakeTransactionPool(ledger, cfg, logger)
	transactionPool.logAssembleStats = true

	phdr, err := ledger.BlockHdr(0)
	require.NoError(t, err)
	b.BlockHeader.Branch = phdr.Hash()
	b.BlockHeader.FeeSink = addresses[1]
	b.BlockHeader.RewardsPool = addresses[2]

	eval, err := ledger.StartEvaluator(b.BlockHeader, 0, 10000)
	require.NoError(t, err)

	for i := 1; true; i++ {
		blk, err := eval.GenerateBlock()
		require.NoError(t, err)

		blk, err = transactionPool.AssembleBlock(basics.Round(i), time.Time{})
		require.NoError(t, err)

		err = ledger.AddValidatedBlock(*blk, agreement.Certificate{})
		require.NoError(t, err)

		b.BlockHeader.Round++
		transactionPool.OnNewBlock(blk.Block(), ledgercore.StateDelta{})

		phdr, err := ledger.BlockHdr(basics.Round(i))
		require.NoError(t, err)
		b.BlockHeader.Branch = phdr.Hash()
		b.BlockHeader.TimeStamp = phdr.TimeStamp + 10

		if i == 513 {
			break
		}

		eval, err = ledger.StartEvaluator(b.BlockHeader, 0, 10000)
		require.NoError(t, err)
	}

	lookback := basics.Round(512).SubSaturate(basics.Round(proto.StateProofVotersLookback))
	voters, err := ledger.VotersForStateProof(lookback)
	require.NoError(t, err)
	require.NotNil(t, voters)

	proof := generateProofForTesting(uint64(512), voters.Participants, voters.Tree, keys, voters.TotalWeight.Raw, t)

	uniqueTxID := 0
	var stxn transactions.SignedTxn
	stxn.Txn.Type = protocol.StateProofTx
	stxn.Txn.Sender = transactions.StateProofSender
	stxn.Txn.Fee = basics.MicroAlgos{Raw: proto.MinTxnFee + 1}
	stxn.Txn.FirstValid = 512
	stxn.Txn.LastValid = 1024
	stxn.Txn.Note = []byte{byte(uniqueTxID), byte(uniqueTxID >> 8), byte(uniqueTxID >> 16)}
	stxn.Txn.GenesisHash = ledger.GenesisHash()
	stxn.Txn.StateProofIntervalLatestRound = 512
	stxn.Txn.StateProofType = protocol.StateProofBasic
	stxn.Txn.StateProof = *proof
	stxn.Txn.StateProofMessage = stateproofmsg.Message{
		LnProvenWeight: 1,
	}

	eval, err = ledger.StartEvaluator(b.BlockHeader, 0, 10000)
	require.NoError(t, err)

	err = eval.Transaction(stxn, transactions.ApplyData{})
	require.NoError(t, err)

	err = transactionPool.RememberOne(stxn)
	require.NoError(t, err)

	transactionPool.recomputeBlockEvaluator(nil, 0) //[]transactions.SignedTxn{stxn}, nil)//telemetryspec.AssembleBlockMetrics{})

	_, err = transactionPool.AssembleBlock(514, time.Time{})
	require.NoError(t, err)

	scanner := bufio.NewScanner(strings.NewReader(buf.String()))
	lines := make([]string, 0)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	fmt.Println(lines[len(lines)-1])
	//	fmt.Println(buf.String())
}

func generateProofForTesting(
	round uint64,
	partArray basics.ParticipantsArray,
	partTree *merklearray.Tree,
	keys *merklesignature.Secrets,
	totalWeight uint64,
	t *testing.T) *stateproof.StateProof {

	npart := 1 //npartHi + npartLo

	data := stateproofmsg.Message{
		LnProvenWeight: 1,
	}.IntoStateProofMessageHash()

	var sigs []merklesignature.Signature

	signerInRound := keys.GetSigner(round)
	sig, err := signerInRound.SignBytes(data[:])
	require.NoError(t, err)

	for i := 0; i < npart; i++ {
		sigs = append(sigs, sig)
	}

	stateProofStrengthTargetForTests := uint64(256)
	b, err := stateproof.MkBuilder(data, round, uint64(totalWeight/2),
		partArray, partTree, stateProofStrengthTargetForTests)
	require.NoError(t, err)

	for i := uint64(0); i < uint64(npart); i++ {
		p, err := b.Present(i)
		require.False(t, p)
		require.NoError(t, err)
		err = b.IsValid(i, sigs[i], true)
		require.NoError(t, err)
		b.Add(i, sigs[i])

		// sanity check that the builder add the signature
		isPresent, err := b.Present(i)
		require.NoError(t, err)
		require.True(t, isPresent)
	}

	proof, err := b.Build()
	require.NoError(t, err)

	return proof
}
