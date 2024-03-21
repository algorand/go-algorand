// Copyright (C) 2019-2024 Algorand, Inc.
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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestLRUBasicKV(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseKV lruKV
	baseKV.init(logging.TestingLog(t), 10, 5)

	kvNum := 50
	// write 50 KVs
	for i := 0; i < kvNum; i++ {
		kvValue := fmt.Sprintf("kv %d value", i)
		kv := trackerdb.PersistedKVData{
			Value: []byte(kvValue),
			Round: basics.Round(i),
		}
		baseKV.write(kv, fmt.Sprintf("key%d", i))
	}

	// verify that all these KVs are truly there.
	for i := 0; i < kvNum; i++ {
		kv, has := baseKV.read(fmt.Sprintf("key%d", i))
		require.True(t, has)
		require.Equal(t, basics.Round(i), kv.Round)
		require.Equal(t, fmt.Sprintf("kv %d value", i), string(kv.Value))
	}

	// verify expected missing entries
	for i := kvNum; i < kvNum*2; i++ {
		kv, has := baseKV.read(fmt.Sprintf("key%d", i))
		require.False(t, has)
		require.Equal(t, trackerdb.PersistedKVData{}, kv)
	}

	baseKV.prune(kvNum / 2)

	// verify expected (missing/existing) entries
	for i := 0; i < kvNum*2; i++ {
		kv, has := baseKV.read(fmt.Sprintf("key%d", i))

		if i >= kvNum/2 && i < kvNum {
			// expected to have it.
			require.True(t, has)
			require.Equal(t, basics.Round(i), kv.Round)
			require.Equal(t, fmt.Sprintf("kv %d value", i), string(kv.Value))
		} else {
			require.False(t, has)
			require.Equal(t, trackerdb.PersistedKVData{}, kv)
		}
	}
}

func TestLRUKVDisable(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseKV lruKV
	baseKV.init(logging.TestingLog(t), 0, 1)

	kvNum := 5

	for i := 1; i <= kvNum; i++ {
		go func(i int) {
			time.Sleep(time.Duration((crypto.RandUint64() % 50)) * time.Millisecond)
			kvValue := fmt.Sprintf("kv %d value", i)
			kv := trackerdb.PersistedKVData{
				Value: []byte(kvValue),
				Round: basics.Round(i),
			}
			baseKV.writePending(kv, fmt.Sprintf("key%d", i))
		}(i)
	}
	require.Empty(t, baseKV.pendingKVs)
	baseKV.flushPendingWrites()
	require.Empty(t, baseKV.kvs)

	for i := 0; i < kvNum; i++ {
		kvValue := fmt.Sprintf("kv %d value", i)
		kv := trackerdb.PersistedKVData{
			Value: []byte(kvValue),
			Round: basics.Round(i),
		}
		baseKV.write(kv, fmt.Sprintf("key%d", i))
	}

	require.Empty(t, baseKV.kvs)
}

func TestLRUKVPendingWrites(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseKV lruKV
	kvNum := 250
	baseKV.init(logging.TestingLog(t), kvNum*2, kvNum)

	for i := 0; i < kvNum; i++ {
		go func(i int) {
			time.Sleep(time.Duration((crypto.RandUint64() % 50)) * time.Millisecond)
			kvValue := fmt.Sprintf("kv %d value", i)
			kv := trackerdb.PersistedKVData{
				Value: []byte(kvValue),
				Round: basics.Round(i),
			}
			baseKV.writePending(kv, fmt.Sprintf("key%d", i))
		}(i)
	}
	testStarted := time.Now()
	for {
		baseKV.flushPendingWrites()

		// check if all kvs were loaded into "main" cache.
		allKVsLoaded := true
		for i := 0; i < kvNum; i++ {
			_, has := baseKV.read(fmt.Sprintf("key%d", i))
			if !has {
				allKVsLoaded = false
				break
			}
		}
		if allKVsLoaded {
			break
		}
		if time.Since(testStarted).Seconds() > 20 {
			require.Fail(t, "failed after waiting for 20 second")
		}
		// not yet, keep looping.
	}
}

type lruKVTestLogger struct {
	logging.Logger
	WarnfCallback func(string, ...interface{})
	warnMsgCount  int
}

func (cl *lruKVTestLogger) Infof(s string, args ...interface{}) {
	if strings.Contains(s, "exceed the warning threshold of") {
		cl.warnMsgCount++
	}
}

func TestLRUKVPendingWritesWarning(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseKV lruKV
	pendingWritesBuffer := 50
	pendingWritesThreshold := 40
	log := &lruKVTestLogger{Logger: logging.TestingLog(t)}
	baseKV.init(log, pendingWritesBuffer, pendingWritesThreshold)
	for j := 0; j < 50; j++ {
		for i := 0; i < j; i++ {
			kvValue := fmt.Sprintf("kv %d value", i)
			kv := trackerdb.PersistedKVData{
				Value: []byte(kvValue),
				Round: basics.Round(i),
			}
			baseKV.writePending(kv, fmt.Sprintf("key%d", i))
		}
		baseKV.flushPendingWrites()
		if j >= pendingWritesThreshold {
			// expect a warning in the log
			require.Equal(t, 1+j-pendingWritesThreshold, log.warnMsgCount)
		}
	}
}

func TestLRUKVOmittedPendingWrites(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseKV lruKV
	pendingWritesBuffer := 50
	pendingWritesThreshold := 40
	log := &lruKVTestLogger{Logger: logging.TestingLog(t)}
	baseKV.init(log, pendingWritesBuffer, pendingWritesThreshold)

	for i := 0; i < pendingWritesBuffer*2; i++ {
		kvValue := fmt.Sprintf("kv %d value", i)
		kv := trackerdb.PersistedKVData{
			Value: []byte(kvValue),
			Round: basics.Round(i),
		}
		baseKV.writePending(kv, fmt.Sprintf("key%d", i))
	}

	baseKV.flushPendingWrites()

	// verify that all these kvs are truly there.
	for i := 0; i < pendingWritesBuffer; i++ {
		kv, has := baseKV.read(fmt.Sprintf("key%d", i))
		require.True(t, has)
		require.Equal(t, basics.Round(i), kv.Round)
		require.Equal(t, fmt.Sprintf("kv %d value", i), string(kv.Value))
	}

	// verify expected missing entries
	for i := pendingWritesBuffer; i < pendingWritesBuffer*2; i++ {
		kv, has := baseKV.read(fmt.Sprintf("key%d", i))
		require.False(t, has)
		require.Equal(t, trackerdb.PersistedKVData{}, kv)
	}
}

func BenchmarkLRUKVWrite(b *testing.B) {
	numTestKV := 5000
	// there are 2500 kvs that overlap
	fillerKVs := generatePersistedKVData(0, 97500)
	kvs := generatePersistedKVData(97500-numTestKV/2, 97500+numTestKV/2)

	benchLruWriteKVs(b, fillerKVs, kvs)
}

func benchLruWriteKVs(b *testing.B, fillerKVs []cachedKVData, kvs []cachedKVData) {
	b.ResetTimer()
	b.StopTimer()
	var baseKV lruKV
	// setting up the baseKV with a predefined cache size
	baseKV.init(logging.TestingLog(b), baseKVPendingBufferSize, baseKVPendingWarnThreshold)
	for i := 0; i < b.N; i++ {
		baseKV = fillLRUKV(baseKV, fillerKVs)

		b.StartTimer()
		fillLRUKV(baseKV, kvs)
		b.StopTimer()
		baseKV.prune(0)
	}
}

func fillLRUKV(baseKV lruKV, fillerKVs []cachedKVData) lruKV {
	for _, entry := range fillerKVs {
		baseKV.write(entry.PersistedKVData, entry.key)
	}
	return baseKV
}

func generatePersistedKVData(startRound, endRound int) []cachedKVData {
	kvs := make([]cachedKVData, endRound-startRound)
	for i := startRound; i < endRound; i++ {
		kvValue := fmt.Sprintf("kv %d value", i)

		kvs[i-startRound] = cachedKVData{
			PersistedKVData: trackerdb.PersistedKVData{
				Value: []byte(kvValue),
				Round: basics.Round(i + startRound),
			},
			key: fmt.Sprintf("key%d", i),
		}
	}
	return kvs
}
