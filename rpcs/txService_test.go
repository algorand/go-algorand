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

package rpcs

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/bloom"
)

func TestMain(m *testing.M) {
	logging.Base().SetLevel(logging.Debug)
	os.Exit(m.Run())
}

func TestTxSync(t *testing.T) {
	// A network with two nodes, A and B
	nodeA, nodeB := nodePair()
	defer nodeA.stop()
	defer nodeB.stop()

	pool := makeMockPendingTxAggregate(3)
	RegisterTxService(pool, nodeA, "test genesisID", config.GetDefaultLocal().TxPoolSize, config.GetDefaultLocal().TxSyncServeResponseSize)

	// B tries to fetch block
	handler := mockHandler{}
	syncInterval := time.Second
	syncTimeout := time.Second
	syncerPool := makeMockPendingTxAggregate(0)
	syncer := MakeTxSyncer(syncerPool, nodeB, &handler, syncInterval, syncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
	require.NoError(t, syncer.sync())
	require.Equal(t, int32(3), atomic.LoadInt32(&handler.messageCounter))
}

func BenchmarkTxSync(b *testing.B) {
	// A network with two nodes, A and B
	nodeA, nodeB := nodePair()
	defer nodeA.stop()
	defer nodeB.stop()

	pool := makeMockPendingTxAggregate(10000)
	RegisterTxService(pool, nodeA, "test genesisID", config.GetDefaultLocal().TxPoolSize, config.GetDefaultLocal().TxSyncServeResponseSize)

	b.ResetTimer()
	wg := sync.WaitGroup{}
	wg.Add(30)
	for i := 0; i < 30; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < b.N/30; j++ {
				handler := mockHandler{}
				syncInterval := time.Second
				syncTimeout := time.Second
				syncPool := makeMockPendingTxAggregate(config.GetDefaultLocal().TxPoolSize)
				syncer := MakeTxSyncer(syncPool, nodeB, &handler, syncInterval, syncTimeout, config.GetDefaultLocal().TxSyncServeResponseSize)
				syncer.sync()
			}
		}()
	}
	wg.Wait()
}

func BenchmarkTransactionFilteringPerformance(b *testing.B) {
	pool := makeMockPendingTxAggregate(config.GetDefaultLocal().TxPoolSize)
	txService := makeTxService(pool, "test genesisID", config.GetDefaultLocal().TxPoolSize, config.GetDefaultLocal().TxSyncServeResponseSize)

	clientPool := makeMockPendingTxAggregate(config.GetDefaultLocal().TxPoolSize)
	pending := clientPool.PendingTxIDs()
	sizeBits, numHashes := bloom.Optimal(len(pending), bloomFilterFalsePositiveRate)
	filter := bloom.New(sizeBits, numHashes, 0)
	for _, txid := range pending {
		filter.Set(txid[:])
	}

	txService.updateTxCache()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		txService.getFilteredTxns(filter)
		i += config.GetDefaultLocal().TxPoolSize - 1
	}
}
