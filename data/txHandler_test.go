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

package data

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/pools"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

func makeTestingTransactionPoolAndLedger(tb testing.TB, N int) (*pools.TransactionPool, *Ledger, []*crypto.SignatureSecrets, []basics.Address) {
	const numUsers = 100
	log := logging.TestingLog(tb)
	secrets := make([]*crypto.SignatureSecrets, numUsers)
	addresses := make([]basics.Address, numUsers)

	genesis := make(map[basics.Address]basics.AccountData)
	for i := 0; i < numUsers; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
		genesis[addr] = basics.AccountData{
			Status:     basics.Online,
			MicroAlgos: basics.MicroAlgos{Raw: 10000000000000},
		}
	}

	genesis[poolAddr] = basics.AccountData{
		Status:     basics.NotParticipating,
		MicroAlgos: basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinBalance},
	}

	require.Equal(tb, len(genesis), numUsers+1)
	genBal := MakeGenesisBalances(genesis, sinkAddr, poolAddr)
	ledgerName := fmt.Sprintf("%s-mem-%d", tb.Name(), N)
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genBal, genesisID, genesisHash, nil, cfg)
	require.NoError(tb, err)

	cfg.TxPoolSize = 20000
	cfg.EnableProcessBlockStats = false
	tp := pools.MakeTransactionPool(ledger.Ledger, cfg, logging.Base())
	return tp, ledger, secrets, addresses
}

func BenchmarkTxHandlerProcessDecoded(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()
	const numUsers = 100
	tp, l, secrets, addresses := makeTestingTransactionPoolAndLedger(b, b.N)
	defer l.Close()
	signedTransactions := make([]transactions.SignedTxn, 0, b.N)
	for i := 0; i < b.N/numUsers; i++ {
		for u := 0; u < numUsers; u++ {
			// generate transactions
			tx := transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender:     addresses[u],
					Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
					FirstValid: 0,
					LastValid:  basics.Round(proto.MaxTxnLife),
					Note:       make([]byte, 2),
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: addresses[(u+1)%numUsers],
					Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance + (rand.Uint64() % 10000)},
				},
			}
			signedTx := tx.Sign(secrets[u])
			signedTransactions = append(signedTransactions, signedTx)
		}
	}
	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	txHandler := MakeTxHandler(tp, l, &mocks.MockNetwork{}, "", crypto.Digest{}, backlogPool)
	b.StartTimer()
	for _, signedTxn := range signedTransactions {
		txHandler.processDecoded([]transactions.SignedTxn{signedTxn})
	}
}

func BenchmarkTimeAfter(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()
	deadline := time.Now().Add(5 * time.Second)
	after := 0
	before := 0
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if time.Now().After(deadline) {
			after++
		} else {
			before++
		}
	}
}
func TestFilterAlreadyCommitted(t *testing.T) {
	const numUsers = 100
	tp, l, secrets, addresses := makeTestingTransactionPoolAndLedger(t, 1)
	defer l.Close()
	signedTransactions := make([]transactions.SignedTxn, 0, 100)

	for u := 0; u < numUsers; u++ {
		// generate transactions
		tx := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      addresses[u],
				Fee:         basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
				FirstValid:  0,
				LastValid:   basics.Round(proto.MaxTxnLife),
				GenesisHash: l.GenesisHash(),
				Note:        make([]byte, 2),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: addresses[(u+1)%numUsers],
				Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance + (rand.Uint64() % 10000)},
			},
		}
		signedTx := tx.Sign(secrets[u])
		signedTransactions = append(signedTransactions, signedTx)
	}

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	txHandler := MakeTxHandler(tp, l, &mocks.MockNetwork{}, "", crypto.Digest{}, backlogPool)

	// add the first 10 transactions to the pool.
	for i := 0; i < 10; i++ {
		tp.Remember(transactions.SignedTxGroup{Transactions: []transactions.SignedTxn{signedTransactions[i]}})
	}

	allNew := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions: signedTransactions[10:11],
		},
		transactions.SignedTxGroup{
			Transactions: signedTransactions[11:12],
		},
	}
	allNewRef := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions: signedTransactions[10:11],
		},
		transactions.SignedTxGroup{
			Transactions: signedTransactions[11:12],
		},
	}
	allNewTransactions, allNewNonDupFilteredGroups := txHandler.filterAlreadyCommitted(allNew)
	require.Equal(t, allNewRef, allNewTransactions)
	require.False(t, allNewNonDupFilteredGroups)

	firstTxDup := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions: []transactions.SignedTxn{signedTransactions[1]},
		},
		transactions.SignedTxGroup{
			Transactions: signedTransactions[11:12],
		},
	}
	firstTxExpectedOutput := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions: signedTransactions[11:12],
		},
	}
	firstTxDupTransactions, firstTxDupNonDupFilteredGroups := txHandler.filterAlreadyCommitted(firstTxDup)
	require.Equal(t, firstTxExpectedOutput, firstTxDupTransactions)
	require.False(t, firstTxDupNonDupFilteredGroups)

	lastTxDup := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions: signedTransactions[11:12],
		},
		transactions.SignedTxGroup{
			Transactions: []transactions.SignedTxn{signedTransactions[1]},
		},
	}
	lastTxExpectedOutput := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions: signedTransactions[11:12],
		},
	}
	lastTxDupTransactions, lastTxDupNonDupFilteredGroups := txHandler.filterAlreadyCommitted(lastTxDup)
	require.Equal(t, lastTxExpectedOutput, lastTxDupTransactions)
	require.False(t, lastTxDupNonDupFilteredGroups)

	midTxDup := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions: signedTransactions[10:11],
		},
		transactions.SignedTxGroup{
			Transactions: signedTransactions[11:12],
		},
		transactions.SignedTxGroup{
			Transactions: []transactions.SignedTxn{signedTransactions[1]},
		},
		transactions.SignedTxGroup{
			Transactions: signedTransactions[13:14],
		},
		transactions.SignedTxGroup{
			Transactions: signedTransactions[14:15],
		},
		transactions.SignedTxGroup{
			Transactions: []transactions.SignedTxn{signedTransactions[2]},
		},
		transactions.SignedTxGroup{
			Transactions: []transactions.SignedTxn{signedTransactions[3]},
		},
		transactions.SignedTxGroup{
			Transactions: signedTransactions[15:16],
		},
	}
	midTxDupExpectedOutput := []transactions.SignedTxGroup{
		transactions.SignedTxGroup{
			Transactions: signedTransactions[10:11],
		},
		transactions.SignedTxGroup{
			Transactions: signedTransactions[11:12],
		},
		transactions.SignedTxGroup{
			Transactions: signedTransactions[13:14],
		},
		transactions.SignedTxGroup{
			Transactions: signedTransactions[14:15],
		},
		transactions.SignedTxGroup{
			Transactions: signedTransactions[15:16],
		},
	}
	midTxDupTransactions, midTxDupNonDupFilteredGroups := txHandler.filterAlreadyCommitted(midTxDup)
	require.Equal(t, midTxDupExpectedOutput, midTxDupTransactions)
	require.False(t, midTxDupNonDupFilteredGroups)

	return
}
