// Copyright (C) 2019 Algorand, Inc.
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
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

var proto = config.Consensus[protocol.ConsensusCurrentVersion]

func keypair() *crypto.SignatureSecrets {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

type mockSpendableBalancesUnbounded struct {
	balance    uint64
	exceptions map[basics.Address]uint64
}

func (b mockSpendableBalancesUnbounded) BalanceAndStatus(address basics.Address) (total basics.MicroAlgos, rewards basics.MicroAlgos, totalWithoutPendingRewards basics.MicroAlgos, status basics.Status, round basics.Round, err error) {
	if b.exceptions != nil {
		if balance, has := b.exceptions[address]; has {
			total = basics.MicroAlgos{Raw: balance}
			return
		}
	}
	total = basics.MicroAlgos{Raw: b.balance}
	rewards = basics.MicroAlgos{Raw: 0}
	round = 1
	return
}

func (b mockSpendableBalancesUnbounded) Committed(transactions.SignedTxn) (bool, error) {
	return false, nil
}

const mockBalancesMinBalance = 1000

func (b mockSpendableBalancesUnbounded) ConsensusParams(basics.Round) (config.ConsensusParams, error) {
	return config.ConsensusParams{MinBalance: mockBalancesMinBalance}, nil
}

func (b mockSpendableBalancesUnbounded) BlockHdr(basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader{}, nil
}

func (b mockSpendableBalancesUnbounded) LastRound() basics.Round {
	return 0
}

const exponentialGrowth = 2
const testPoolSize = 1000

func TestMinBalanceOK(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*mockBalancesMinBalance + proto.MinTxnFee

	transactionPool := MakeTransactionPool(mockSpendableBalancesUnbounded{balance: 1 << 60, exceptions: limitedAccounts}, exponentialGrowth, testPoolSize, false)

	// sender goes below min
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     addresses[0],
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 2),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance},
		},
	}
	signedTx := tx.Sign(secrets[0])
	require.NoError(t, transactionPool.Remember(signedTx))
}

func TestSenderGoesBelowMinBalance(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*mockBalancesMinBalance + proto.MinTxnFee

	transactionPool := MakeTransactionPool(mockSpendableBalancesUnbounded{balance: 1 << 60, exceptions: limitedAccounts}, exponentialGrowth, testPoolSize, false)

	// sender goes below min
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     addresses[0],
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 2),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance},
		},
	}
	signedTx := tx.Sign(secrets[0])
	require.Error(t, transactionPool.Remember(signedTx))
}

func TestCloseAccount(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 3*mockBalancesMinBalance + 2*proto.MinTxnFee

	transactionPool := MakeTransactionPool(mockSpendableBalancesUnbounded{balance: 1 << 60, exceptions: limitedAccounts}, exponentialGrowth, testPoolSize, false)

	// sender goes below min
	closeTx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     addresses[0],
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 2),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         addresses[1],
			Amount:           basics.MicroAlgos{Raw: mockBalancesMinBalance},
			CloseRemainderTo: addresses[2],
		},
	}
	signedTx := closeTx.Sign(secrets[0])
	require.NoError(t, transactionPool.Remember(signedTx))

	// sender goes below min
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     addresses[0],
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 2),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance},
		},
	}
	signedTx2 := tx.Sign(secrets[0])
	require.Error(t, transactionPool.Remember(signedTx2))

	transactionPool.Remove(closeTx.ID(), fmt.Errorf("removing close account tx"))
	require.NoError(t, transactionPool.Remember(signedTx2))
}

func TestCloseAccountWhileTxIsPending(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*mockBalancesMinBalance + 2*proto.MinTxnFee

	transactionPool := MakeTransactionPool(mockSpendableBalancesUnbounded{balance: 1 << 60, exceptions: limitedAccounts}, exponentialGrowth, testPoolSize, false)

	// sender goes below min
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     addresses[0],
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 2),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance},
		},
	}
	signedTx := tx.Sign(secrets[0])
	require.NoError(t, transactionPool.Remember(signedTx))

	// sender goes below min
	closeTx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     addresses[0],
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 2),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         addresses[1],
			Amount:           basics.MicroAlgos{Raw: mockBalancesMinBalance},
			CloseRemainderTo: addresses[2],
		},
	}
	signedCloseTx := closeTx.Sign(secrets[0])
	require.Error(t, transactionPool.Remember(signedCloseTx))
}

func TestClosingAccountBelowMinBalance(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	limitedAccounts := make(map[basics.Address]uint64)
	limitedAccounts[addresses[0]] = 2*mockBalancesMinBalance - 1 + proto.MinTxnFee
	limitedAccounts[addresses[2]] = 0

	transactionPool := MakeTransactionPool(mockSpendableBalancesUnbounded{balance: 1 << 60, exceptions: limitedAccounts}, exponentialGrowth, testPoolSize, false)

	// sender goes below min
	closeTx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     addresses[0],
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 2),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver:         addresses[1],
			Amount:           basics.MicroAlgos{Raw: mockBalancesMinBalance},
			CloseRemainderTo: addresses[2],
		},
	}
	signedTx := closeTx.Sign(secrets[0])
	require.Error(t, transactionPool.Remember(signedTx))
}

func TestRecipientGoesBelowMinBalance(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
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

	transactionPool := MakeTransactionPool(mockSpendableBalancesUnbounded{balance: 1 << 60, exceptions: limitedAccounts}, exponentialGrowth, testPoolSize, false)

	// sender goes below min
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     addresses[0],
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       make([]byte, 2),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: addresses[1],
			Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance - 1},
		},
	}
	signedTx := tx.Sign(secrets[0])
	require.Error(t, transactionPool.Remember(signedTx))
}

func TestRememberForget(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	transactionPool := MakeTransactionPool(mockSpendableBalancesUnbounded{balance: 1 << 60}, exponentialGrowth, testPoolSize, false)
	var block bookkeeping.Block
	block.Payset = make(transactions.Payset, 0)

	for i, sender := range addresses {
		for j, receiver := range addresses {
			if sender != receiver {
				tx := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:     sender,
						Fee:        basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
						FirstValid: 0,
						LastValid:  basics.Round(proto.MaxTxnLife),
						Note:       make([]byte, 2),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: 1},
					},
				}
				tx.Note[0] = byte(i)
				tx.Note[1] = byte(j)
				signedTx := tx.Sign(secrets[i])
				transactionPool.Remember(signedTx)
				txib, err := block.EncodeSignedTxn(signedTx, transactions.ApplyData{})
				require.NoError(t, err)
				block.Payset = append(block.Payset, txib)
			}
		}
	}

	pending := transactionPool.Pending()
	numberOfTxns := numOfAccounts*numOfAccounts - numOfAccounts
	require.Len(t, pending, numberOfTxns)
	transactionPool.OnNewBlock(block)
	pending = transactionPool.Pending()
	require.Len(t, pending, 0)
}

func TestPendingIsOrdered(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	transactionPool := MakeTransactionPool(mockSpendableBalancesUnbounded{balance: 1 << 60}, exponentialGrowth, testPoolSize, false)

	for i, sender := range addresses {
		for j, receiver := range addresses {
			if sender != receiver {
				tx := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:     sender,
						Fee:        basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
						FirstValid: 0,
						LastValid:  basics.Round(proto.MaxTxnLife),
						Note:       make([]byte, 2),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: 1},
					},
				}
				tx.Note[0] = byte(i)
				tx.Note[1] = byte(j)
				signedTx := tx.Sign(secrets[i])
				transactionPool.Remember(signedTx)
			}
		}
	}

	pending := transactionPool.Pending()
	numberOfTxns := numOfAccounts*numOfAccounts - numOfAccounts
	require.Len(t, pending, numberOfTxns)

	last := pending[0].Txn.TxFee()
	for i := 0; i < numberOfTxns; i++ {
		require.False(t, last.LessThan(pending[i].Txn.TxFee()))
		last = pending[i].Txn.TxFee()
	}

	ids := transactionPool.PendingTxIDs()
	require.Equal(t, len(pending), len(ids))

	idset := make(map[transactions.Txid]bool)

	for _, id := range ids {
		idset[id] = true
	}
	for _, tx := range pending {
		require.True(t, idset[tx.ID()])
	}
}

//	Test that clean up works
func TestCleanUp(t *testing.T) {
	numOfAccounts := 10
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	transactionPool := MakeTransactionPool(mockSpendableBalancesUnbounded{balance: 1 << 60}, exponentialGrowth, testPoolSize, false)

	issuedTransactions := 0
	for i, sender := range addresses {
		for j, receiver := range addresses {
			if sender != receiver {
				tx := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:     sender,
						Fee:        basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
						FirstValid: 0,
						LastValid:  5,
						Note:       make([]byte, 2),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: 1},
					},
				}
				tx.Note[0] = byte(i)
				tx.Note[1] = byte(j)
				signedTx := tx.Sign(secrets[i])
				require.NoError(t, transactionPool.Remember(signedTx))
				issuedTransactions++
			}
		}
	}

	block := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round: basics.Round(6),
		},
	}
	block.CurrentProtocol = protocol.ConsensusCurrentVersion
	transactionPool.OnNewBlock(block)

	pending := transactionPool.Pending()

	require.Zero(t, len(pending))
	require.Zero(t, transactionPool.NumExpired(block.Round()-1))
	require.Equal(t, issuedTransactions, transactionPool.NumExpired(block.Round()))

	for r := block.Round(); r <= block.Round()+basics.Round(expiredHistory*proto.MaxTxnLife); r++ {
		b := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: basics.Round(r),
			},
		}
		b.CurrentProtocol = protocol.ConsensusCurrentVersion
		transactionPool.OnNewBlock(b)
		require.Zero(t, transactionPool.NumExpired(b.Round()))
	}
	require.Len(t, transactionPool.expiredTxCount, int(expiredHistory*proto.MaxTxnLife))
}

func TestFixOverflowOnNewBlock(t *testing.T) {
	numOfAccounts := 10
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	balance := mockSpendableBalancesUnbounded{balance: 1 << 60}

	transactionPool := MakeTransactionPool(&balance, exponentialGrowth, testPoolSize, false)

	overSpender := addresses[0]
	overSpenderPendingSpend := make(accountsToPendingTransactions)
	savedTransactions := 0
	for i, sender := range addresses {
		amount := uint64(0)
		for _, receiver := range addresses {
			if sender != receiver {
				tx := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:     sender,
						Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee + amount},
						FirstValid: 0,
						LastValid:  10,
						Note:       make([]byte, 0),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: 0},
					},
				}
				amount++

				if sender == overSpender {
					pending, err := overSpenderPendingSpend.deductionsWithTransaction(tx)
					require.NoError(t, err)
					overSpenderPendingSpend.accountForTransactionDeductions(tx, pending)
				}

				signedTx := tx.Sign(secrets[i])
				require.NoError(t, transactionPool.Remember(signedTx))
				savedTransactions++
			}
		}
	}
	pending := transactionPool.Pending()
	require.Len(t, pending, savedTransactions)

	secret := keypair()
	recv := basics.Address(secret.SignatureVerifier)

	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     overSpender,
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid: 0,
			LastValid:  10,
			Note:       []byte{1},
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: recv,
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}
	signedTx := tx.Sign(secrets[0])

	block := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round: basics.Round(1),
		},
	}
	txib, err := block.EncodeSignedTxn(signedTx, transactions.ApplyData{})
	require.NoError(t, err)
	block.Payset = []transactions.SignedTxnInBlock{
		txib,
	}

	// simulate this transaction was applied
	balance.exceptions = make(map[basics.Address]uint64)
	balance.exceptions[overSpender] = overSpenderPendingSpend[overSpender].deductions.amount.Raw - tx.TxFee().Raw - tx.TxAmount().Raw

	transactionPool.OnNewBlock(block)

	pending = transactionPool.Pending()
	// only one transaction is missing
	require.Len(t, pending, savedTransactions-1)

	for _, tx := range pending {
		// ensure it's the lowest priority one that is removed
		if tx.Txn.Src() == overSpender {
			require.True(t, tx.Txn.TxFee().Raw > proto.MinTxnFee)
		}
	}
}

func TestExponentialPriorityGrowth(t *testing.T) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	poolSize := 2
	transactionPool := MakeTransactionPool(mockSpendableBalancesUnbounded{balance: 1 << 60}, exponentialGrowth, poolSize, false)

	sender := addresses[0]
	receiver := addresses[1]

	baseFee := uint64(2)
	for i := 0; i < poolSize; i++ {
		tx := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:     sender,
				Fee:        basics.MicroAlgos{Raw: baseFee},
				FirstValid: 0,
				LastValid:  basics.Round(proto.MaxTxnLife),
				Note:       []byte{byte(i)},
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: receiver,
				Amount:   basics.MicroAlgos{Raw: 1},
			},
		}
		signedTx := tx.Sign(secrets[0])
		require.NoError(t, transactionPool.Remember(signedTx))
	}

	txLowFee := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     sender,
			Fee:        basics.MicroAlgos{Raw: baseFee*exponentialGrowth - 1},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       []byte{byte(poolSize + 1)},
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 1},
		},
	}
	signed := txLowFee.Sign(secrets[0])
	require.Error(t, transactionPool.Remember(signed))

	txHighFee := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     sender,
			Fee:        basics.MicroAlgos{Raw: baseFee * exponentialGrowth},
			FirstValid: 0,
			LastValid:  basics.Round(proto.MaxTxnLife),
			Note:       []byte{byte(poolSize + 2)},
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 1},
		},
	}
	require.NoError(t, transactionPool.Remember(txHighFee.Sign(secrets[0])))
}

func TestOverspender(t *testing.T) {
	numOfAccounts := 2
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	balance := mockSpendableBalancesUnbounded{balance: 1 << 60}

	transactionPool := MakeTransactionPool(&balance, exponentialGrowth, testPoolSize, false)

	overSpender := addresses[0]
	overSpenderPendingSpend := make(accountsToPendingTransactions)

	receiver := addresses[1]
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     overSpender,
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
			FirstValid: 0,
			LastValid:  10,
			Note:       make([]byte, 0),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}
	signedTx := tx.Sign(secrets[0])

	// simulate this transaction was applied
	balance.exceptions = make(map[basics.Address]uint64)
	limit, err := overSpenderPendingSpend.deductionsWithTransaction(tx)
	require.NoError(t, err)
	balance.exceptions[overSpender] = limit.amount.Raw

	// consume the transaction of allowed limit
	require.Error(t, transactionPool.Remember(signedTx))

	// min transaction
	minTx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     overSpender,
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid: 0,
			LastValid:  10,
			Note:       make([]byte, 0),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}
	signedMinTx := minTx.Sign(secrets[0])
	require.Error(t, transactionPool.Remember(signedMinTx))
}

func TestAddError(t *testing.T) {
	numOfAccounts := 2
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	balance := mockSpendableBalancesUnbounded{balance: 1 << 60}

	transactionPool := MakeTransactionPool(&balance, exponentialGrowth, testPoolSize, false)

	sender := addresses[0]
	senderPendingSpend := make(accountsToPendingTransactions)

	receiver := addresses[1]
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     sender,
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
			FirstValid: 0,
			LastValid:  10,
			Note:       make([]byte, 0),
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}
	signedTx := tx.Sign(secrets[0])

	// simulate this transaction was applied
	limit, err := senderPendingSpend.deductionsWithTransaction(tx)
	require.NoError(t, err)
	transactionPool.algosPendingSpend[sender] = pendingTransactions{
		deductions: accountDeductions{
			amount: basics.MicroAlgos{Raw: 0xffffffffffffffff - limit.amount.Raw + 1},
		},
	}

	// overflow accounting, and result in error
	require.Error(t, transactionPool.Remember(signedTx))
}

func TestRemove(t *testing.T) {
	numOfAccounts := 2
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	balance := mockSpendableBalancesUnbounded{balance: 1 << 60}

	transactionPool := MakeTransactionPool(&balance, exponentialGrowth, testPoolSize, false)

	sender := addresses[0]
	receiver := addresses[1]
	tx := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     sender,
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
			FirstValid: 0,
			LastValid:  10,
			Note:       []byte{0},
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}
	signedTx := tx.Sign(secrets[0])
	require.NoError(t, transactionPool.Remember(signedTx))
	require.Equal(t, transactionPool.Pending(), []transactions.SignedTxn{signedTx})

	tx2 := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:     sender,
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee + 1},
			FirstValid: 0,
			LastValid:  10,
			Note:       []byte{1},
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 0},
		},
	}

	// invalid remove
	transactionPool.remove(tx2.ID(), nil)
	require.Equal(t, transactionPool.Pending(), []transactions.SignedTxn{signedTx})

}

func BenchmarkTransactionPoolRemember(b *testing.B) {
	numOfAccounts := 5
	// Genereate accounts
	secrets := make([]*crypto.SignatureSecrets, numOfAccounts)
	addresses := make([]basics.Address, numOfAccounts)

	for i := 0; i < numOfAccounts; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}

	transactionPool := MakeTransactionPool(mockSpendableBalancesUnbounded{balance: 1 << 60}, exponentialGrowth, b.N, false)
	signedTransactions := make([]transactions.SignedTxn, 0, b.N)
	for i, sender := range addresses {
		for j := 0; j < b.N/len(addresses); j++ {
			var receiver basics.Address
			crypto.RandBytes(receiver[:])
			tx := transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender:     sender,
					Fee:        basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
					FirstValid: 0,
					LastValid:  basics.Round(proto.MaxTxnLife),
					Note:       make([]byte, 2),
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: receiver,
					Amount:   basics.MicroAlgos{Raw: 1},
				},
			}
			tx.Note = make([]byte, 8, 8)
			crypto.RandBytes(tx.Note)
			signedTx := tx.Sign(secrets[i])
			signedTransactions = append(signedTransactions, signedTx)
			err := transactionPool.Remember(signedTx)
			require.NoError(b, err)
		}
	}
	b.StopTimer()
	b.ResetTimer()
	transactionPool = MakeTransactionPool(mockSpendableBalancesUnbounded{balance: 1 << 60}, exponentialGrowth, b.N, false)

	b.StartTimer()
	for _, signedTx := range signedTransactions {
		transactionPool.Remember(signedTx)
	}
}

func BenchmarkTransactionPoolPending(b *testing.B) {
	numOfAccounts := 5
	// Genereate accounts
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
		transactionPool := MakeTransactionPool(mockSpendableBalancesUnbounded{balance: 1 << 60}, exponentialGrowth, benchPoolSize, false)
		var block bookkeeping.Block
		block.Payset = make(transactions.Payset, 0)

		for i, sender := range addresses {
			for j := 0; j < benchPoolSize/len(addresses); j++ {
				var receiver basics.Address
				crypto.RandBytes(receiver[:])
				tx := transactions.Transaction{
					Type: protocol.PaymentTx,
					Header: transactions.Header{
						Sender:     sender,
						Fee:        basics.MicroAlgos{Raw: uint64(rand.Int()%10000) + proto.MinTxnFee},
						FirstValid: 0,
						LastValid:  basics.Round(proto.MaxTxnLife),
						Note:       make([]byte, 2),
					},
					PaymentTxnFields: transactions.PaymentTxnFields{
						Receiver: receiver,
						Amount:   basics.MicroAlgos{Raw: 1},
					},
				}
				tx.Note = make([]byte, 8, 8)
				crypto.RandBytes(tx.Note)
				signedTx := tx.Sign(secrets[i])
				err := transactionPool.Remember(signedTx)
				require.NoError(b, err)
			}
		}

		b.StartTimer()
		for i := 0; i < b.N; i++ {
			transactionPool.Pending()
		}
	}
	subs := []int{1000, 5000, 10000, 25000, 50000}
	for _, bps := range subs {
		b.Run(fmt.Sprintf("Pending-%d", bps), func(b *testing.B) {
			sub(b, bps)
		})
	}
}
