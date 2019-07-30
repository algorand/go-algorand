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

package data

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/pools"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

func incaddr(user *basics.Address) {
	pos := len(user) - 1
	for true {
		v := user[pos] + 1
		user[pos] = v
		if v == 0 {
			pos--
		} else {
			return
		}
	}
}

func keypair() *crypto.SignatureSecrets {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

var proto = config.Consensus[protocol.ConsensusCurrentVersion]

const mockBalancesMinBalance = 1000

func BenchmarkAssemblePayset(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()
	const numRounds = 10
	const numUsers = 100
	log := logging.TestingLog(b)
	secrets := make([]*crypto.SignatureSecrets, numUsers)
	addresses := make([]basics.Address, numUsers)

	backlogPool := execpool.MakeBacklog(nil, 0, execpool.LowPriority, nil)
	defer backlogPool.Shutdown()

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
		//b.Log(addr)
	}

	require.Equal(b, len(genesis), numUsers)
	genBal := MakeGenesisBalances(genesis, poolAddr, sinkAddr)
	ledgerName := fmt.Sprintf("%s-mem-%d", b.Name(), b.N)
	ledger, err := LoadLedger(log, ledgerName, true, protocol.ConsensusCurrentVersion, genBal, "", crypto.Digest{}, nil)
	require.NoError(b, err)

	l := ledger
	// allb, err := l.AllBalances(l.Latest())
	// require.NoError(b, err)
	// for addr, ad := range allb {
	// 	b.Logf("%s\t%d", addr, ad.MicroAlgos)
	// }
	next := l.LastRound()
	prev, err := l.BlockHdr(next)
	if err != nil {
		b.Errorf("could not make proposals at round %d: could not read block from ledger: %v", next, err)
		return
	}
	sourcei := 0
	for i := 0; i < b.N; i++ {
		// generate transactions
		const txPoolSize = 6000
		tp := pools.MakeTransactionPool(l.Ledger, txPoolSize, false)
		errcount := 0
		okcount := 0
		var worstTxID transactions.Txid
		for tp.PendingCount() < txPoolSize {
			desti := rand.Intn(len(addresses))
			for desti == sourcei {
				desti = rand.Intn(len(addresses))
			}
			tx := transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					Sender:     addresses[sourcei],
					Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee * 2},
					FirstValid: 0,
					LastValid:  basics.Round(proto.MaxTxnLife),
					Note:       make([]byte, 2),
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: addresses[desti],
					Amount:   basics.MicroAlgos{Raw: mockBalancesMinBalance + (rand.Uint64() % 10000)},
				},
			}
			if okcount == 0 {
				// make one transaction with less fee to make sure we're sorting in the right order
				tx.Header.Fee.Raw = proto.MinTxnFee
			}
			signedTx := tx.Sign(secrets[sourcei])
			if okcount == 0 {
				worstTxID = signedTx.ID()
			}
			err := tp.Remember(signedTx)
			if err != nil {
				errcount++
				b.Logf("(%d/%d) could not send [%d] %s -> [%d] %s: %s", errcount, okcount, sourcei, addresses[sourcei], desti, addresses[desti], err)
				if errcount > 100 {
					b.Fatal("too many errors: ", err)
				}
			} else {
				okcount++
			}
			sourcei = (sourcei + 1) % len(addresses)
		}
		b.StartTimer()
		newEmptyBlk := bookkeeping.MakeBlock(prev)
		eval, err := l.StartEvaluator(newEmptyBlk.BlockHeader, tp, backlogPool)
		if err != nil {
			b.Errorf("could not make proposals at round %d: could not start evaluator: %v", next, err)
			return
		}
		var stats telemetryspec.AssembleBlockMetrics
		deadline := time.Now().Add(time.Second)
		stats.AssembleBlockStats = l.AssemblePayset(tp, eval, deadline)
		b.StopTimer()
		require.Equal(b, stats.AssembleBlockStats.StopReason, telemetryspec.AssembleBlockFull)
		// the worst txn, with lower fee than the rest, should still be in the pool
		_, _, found := tp.Lookup(worstTxID)
		require.True(b, found)
	}
}
