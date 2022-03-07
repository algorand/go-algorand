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
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestLRUBasicResources(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseRes lruResources
	baseRes.init(logging.TestingLog(t), 10, 5)

	resourcesNum := 50
	// write 50 resources
	for i := 0; i < resourcesNum; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		res := persistedResourcesData{
			addrid: int64(i),
			aidx:   basics.CreatableIndex(i),
			round:  basics.Round(i),
			data:   resourcesData{Total: uint64(i)},
		}
		baseRes.write(res, addr)
	}

	// verify that all these resources are truly there.
	for i := 0; i < resourcesNum; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		res, has := baseRes.read(addr, basics.CreatableIndex(i))
		require.True(t, has)
		require.Equal(t, basics.Round(i), res.round)
		require.Equal(t, int64(i), res.addrid)
		require.Equal(t, uint64(i), res.data.Total)
		require.Equal(t, basics.CreatableIndex(i), res.aidx)
	}

	// verify expected missing entries
	for i := resourcesNum; i < resourcesNum*2; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		res, has := baseRes.read(addr, basics.CreatableIndex(i%resourcesNum))
		require.False(t, has)
		require.Equal(t, persistedResourcesData{}, res)
	}

	baseRes.prune(resourcesNum / 2)

	// verify expected (missing/existing) entries
	for i := 0; i < resourcesNum*2; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		res, has := baseRes.read(addr, basics.CreatableIndex(i))

		if i >= resourcesNum/2 && i < resourcesNum {
			// expected to have it.
			require.True(t, has)
			require.Equal(t, basics.Round(i), res.round)
			require.Equal(t, int64(i), res.addrid)
			require.Equal(t, uint64(i), res.data.Total)
			require.Equal(t, basics.CreatableIndex(i), res.aidx)
		} else {
			require.False(t, has)
			require.Equal(t, persistedResourcesData{}, res)
		}
	}
}

func TestLRUResourcesPendingWrites(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseRes lruResources
	resourcesNum := 250
	baseRes.init(logging.TestingLog(t), resourcesNum*2, resourcesNum)

	for i := 0; i < resourcesNum; i++ {
		go func(i int) {
			time.Sleep(time.Duration((crypto.RandUint64() % 50)) * time.Millisecond)
			addr := basics.Address(crypto.Hash([]byte{byte(i)}))
			res := persistedResourcesData{
				addrid: int64(i),
				aidx:   basics.CreatableIndex(i),
				round:  basics.Round(i),
				data:   resourcesData{Total: uint64(i)},
			}
			baseRes.writePending(res, addr)
		}(i)
	}
	testStarted := time.Now()
	for {
		baseRes.flushPendingWrites()
		// check if all resources were loaded into "main" cache.
		allResourcesLoaded := true
		for i := 0; i < resourcesNum; i++ {
			addr := basics.Address(crypto.Hash([]byte{byte(i)}))
			_, has := baseRes.read(addr, basics.CreatableIndex(i))
			if !has {
				allResourcesLoaded = false
				break
			}
		}
		if allResourcesLoaded {
			break
		}
		if time.Since(testStarted).Seconds() > 20 {
			require.Fail(t, "failed after waiting for 20 second")
		}
		// not yet, keep looping.
	}
}

type lruResourcesTestLogger struct {
	logging.Logger
	WarnfCallback func(string, ...interface{})
	warnMsgCount  int
}

func (cl *lruResourcesTestLogger) Warnf(s string, args ...interface{}) {
	cl.warnMsgCount++
}

func TestLRUResourcesPendingWritesWarning(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseRes lruResources
	pendingWritesBuffer := 50
	pendingWritesThreshold := 40
	log := &lruResourcesTestLogger{Logger: logging.TestingLog(t)}
	baseRes.init(log, pendingWritesBuffer, pendingWritesThreshold)
	for j := 0; j < 50; j++ {
		for i := 0; i < j; i++ {
			addr := basics.Address(crypto.Hash([]byte{byte(i)}))
			res := persistedResourcesData{
				addrid: int64(i),
				aidx:   basics.CreatableIndex(i),
				round:  basics.Round(i),
				data:   resourcesData{Total: uint64(i)},
			}
			baseRes.writePending(res, addr)
		}
		baseRes.flushPendingWrites()
		if j >= pendingWritesThreshold {
			// expect a warning in the log
			require.Equal(t, 1+j-pendingWritesThreshold, log.warnMsgCount)
		}
	}
}

func TestLRUResourcesOmittedPendingWrites(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseRes lruResources
	pendingWritesBuffer := 50
	pendingWritesThreshold := 40
	log := &lruResourcesTestLogger{Logger: logging.TestingLog(t)}
	baseRes.init(log, pendingWritesBuffer, pendingWritesThreshold)

	for i := 0; i < pendingWritesBuffer*2; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		res := persistedResourcesData{
			addrid: int64(i),
			aidx:   basics.CreatableIndex(i),
			round:  basics.Round(i),
			data:   resourcesData{Total: uint64(i)},
		}
		baseRes.writePending(res, addr)
	}

	baseRes.flushPendingWrites()

	// verify that all these accounts are truly there.
	for i := 0; i < pendingWritesBuffer; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		res, has := baseRes.read(addr, basics.CreatableIndex(i))
		require.True(t, has)
		require.Equal(t, basics.Round(i), res.round)
		require.Equal(t, int64(i), res.addrid)
		require.Equal(t, uint64(i), res.data.Total)
		require.Equal(t, basics.CreatableIndex(i), res.aidx)
	}

	// verify expected missing entries
	for i := pendingWritesBuffer; i < pendingWritesBuffer*2; i++ {
		addr := basics.Address(crypto.Hash([]byte{byte(i)}))
		res, has := baseRes.read(addr, basics.CreatableIndex(i))
		require.False(t, has)
		require.Equal(t, persistedResourcesData{}, res)
	}
}

func BenchmarkLRUResourcesWrite(b *testing.B) {
	numTestAccounts := 5000
	// there are 2500 accounts that overlap
	fillerAccounts := generatePersistedResourcesData(0, 97500)
	accounts := generatePersistedResourcesData(97500-numTestAccounts/2, 97500+numTestAccounts/2)

	benchLruWriteResources(b, fillerAccounts, accounts)
}

func benchLruWriteResources(b *testing.B, fillerAccounts []cachedResourceData, accounts []cachedResourceData) {
	b.ResetTimer()
	b.StopTimer()
	var baseRes lruResources
	// setting up the baseRess with a predefined cache size
	baseRes.init(logging.TestingLog(b), baseResourcesPendingAccountsBufferSize, baseResourcesPendingAccountsWarnThreshold)
	for i := 0; i < b.N; i++ {
		baseRes = fillLRUResources(baseRes, fillerAccounts)

		b.StartTimer()
		fillLRUResources(baseRes, accounts)
		b.StopTimer()
		baseRes.prune(0)
	}
}

func fillLRUResources(baseRes lruResources, fillerAccounts []cachedResourceData) lruResources {
	for _, entry := range fillerAccounts {
		baseRes.write(entry.persistedResourcesData, entry.address)
	}
	return baseRes
}

func generatePersistedResourcesData(startRound, endRound int) []cachedResourceData {
	accounts := make([]cachedResourceData, endRound-startRound)
	buffer := make([]byte, 4)

	for i := startRound; i < endRound; i++ {
		binary.BigEndian.PutUint32(buffer, uint32(i))
		digest := crypto.Hash(buffer)

		accounts[i-startRound] = cachedResourceData{
			persistedResourcesData: persistedResourcesData{
				addrid: int64(i),
				aidx:   basics.CreatableIndex(i),
				round:  basics.Round(i + startRound),
				data:   resourcesData{Total: uint64(i)},
			},
			address: basics.Address(digest),
		}
	}
	return accounts
}
