// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package prefetcher

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestEmitColdResults covers the panic-recovery path of prefetch: a cache-less, error-bearing
// result must be emitted for every group not yet sent, so the consumer still receives one result
// per group (and evaluates each from the ledger) rather than silently skipping the unsent tail.
func TestEmitColdResults(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	groups := make([][]transactions.SignedTxnWithAD, 3)
	for i := range groups {
		groups[i] = []transactions.SignedTxnWithAD{{SignedTxn: transactions.SignedTxn{Txn: transactions.Transaction{
			Type:   protocol.PaymentTx,
			Header: transactions.Header{Sender: basics.Address{byte(i + 1)}},
		}}}}
	}

	p := &paysetPrefetcher{txnGroups: groups, outChan: make(chan LoadedTransactionGroup, len(groups))}
	wantErr := errors.New("boom")

	// Pretend group 0 was already emitted; cold results must cover only groups 1 and 2.
	got := p.emitColdResults(1, wantErr)
	require.Equal(t, len(groups), got)
	close(p.outChan)

	var results []LoadedTransactionGroup
	for r := range p.outChan {
		results = append(results, r)
	}
	require.Len(t, results, len(groups)-1)
	for i, r := range results {
		require.ErrorIs(t, r.Err, wantErr)
		require.Equal(t, groups[i+1], r.TxnGroup) // original group preserved, in order
		require.Nil(t, r.Accounts)                // no prefetched cache on the cold path
		require.Nil(t, r.Resources)
	}
}

func BenchmarkChannelWrites(b *testing.B) {
	b.Run("groupTaskDone", func(b *testing.B) {
		c := make(chan groupTaskDone, b.N)
		for i := 0; i < b.N; i++ {
			c <- groupTaskDone{groupIdx: int64(i)}
		}
	})

	b.Run("int64", func(b *testing.B) {
		c := make(chan int64, b.N)
		for i := int64(0); i < int64(b.N); i++ {
			c <- i
		}
	})
}
