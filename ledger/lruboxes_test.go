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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestLRUBasicBoxes(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseBoxes lruBoxes
	baseBoxes.init(logging.TestingLog(t), 10, 5)

	boxNum := 50
	// write 50 boxes
	for i := 0; i < boxNum; i++ {
		boxValue := fmt.Sprintf("box %d value", i)
		box := persistedBoxData{
			value: &boxValue,
			round: basics.Round(i),
		}
		baseBoxes.write(box, fmt.Sprintf("key%d", i))
	}

	// verify that all these boxes are truly there.
	for i := 0; i < boxNum; i++ {
		box, has := baseBoxes.read(fmt.Sprintf("key%d", i))
		require.True(t, has)
		require.Equal(t, basics.Round(i), box.round)
		require.Equal(t, fmt.Sprintf("box %d value", i), *(box.value))
	}

	// verify expected missing entries
	for i := boxNum; i < boxNum*2; i++ {
		box, has := baseBoxes.read(fmt.Sprintf("key%d", i))
		require.False(t, has)
		require.Equal(t, persistedBoxData{}, box)
	}

	baseBoxes.prune(boxNum / 2)

	// verify expected (missing/existing) entries
	for i := 0; i < boxNum*2; i++ {
		box, has := baseBoxes.read(fmt.Sprintf("key%d", i))

		if i >= boxNum/2 && i < boxNum {
			// expected to have it.
			require.True(t, has)
			require.Equal(t, basics.Round(i), box.round)
			require.Equal(t, fmt.Sprintf("box %d value", i), *(box.value))
		} else {
			require.False(t, has)
			require.Equal(t, persistedBoxData{}, box)
		}
	}
}

func TestLRUBoxesPendingWrites(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseBoxes lruBoxes
	boxesNum := 250
	baseBoxes.init(logging.TestingLog(t), boxesNum*2, boxesNum)

	for i := 0; i < boxesNum; i++ {
		go func(i int) {
			time.Sleep(time.Duration((crypto.RandUint64() % 50)) * time.Millisecond)
			boxValue := fmt.Sprintf("box %d value", i)
			box := persistedBoxData{
				value: &boxValue,
				round: basics.Round(i),
			}
			baseBoxes.writePending(box, fmt.Sprintf("key%d", i))
		}(i)
	}
	testStarted := time.Now()
	for {
		baseBoxes.flushPendingWrites()

		// check if all boxes were loaded into "main" cache.
		allBoxesLoaded := true
		for i := 0; i < boxesNum; i++ {
			_, has := baseBoxes.read(fmt.Sprintf("key%d", i))
			if !has {
				allBoxesLoaded = false
				break
			}
		}
		if allBoxesLoaded {
			break
		}
		if time.Since(testStarted).Seconds() > 20 {
			require.Fail(t, "failed after waiting for 20 second")
		}
		// not yet, keep looping.
	}
}

type lruBoxesTestLogger struct {
	logging.Logger
	WarnfCallback func(string, ...interface{})
	warnMsgCount  int
}

func (cl *lruBoxesTestLogger) Warnf(s string, args ...interface{}) {
	cl.warnMsgCount++
}

func TestLRUBoxesPendingWritesWarning(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseBoxes lruBoxes
	pendingWritesBuffer := 50
	pendingWritesThreshold := 40
	log := &lruBoxesTestLogger{Logger: logging.TestingLog(t)}
	baseBoxes.init(log, pendingWritesBuffer, pendingWritesThreshold)
	for j := 0; j < 50; j++ {
		for i := 0; i < j; i++ {
			boxValue := fmt.Sprintf("box %d value", i)
			box := persistedBoxData{
				value: &boxValue,
				round: basics.Round(i),
			}
			baseBoxes.writePending(box, fmt.Sprintf("key%d", i))
		}
		baseBoxes.flushPendingWrites()
		if j >= pendingWritesThreshold {
			// expect a warning in the log
			require.Equal(t, 1+j-pendingWritesThreshold, log.warnMsgCount)
		}
	}
}

func TestLRUBoxesOmittedPendingWrites(t *testing.T) {
	partitiontest.PartitionTest(t)

	var baseBoxes lruBoxes
	pendingWritesBuffer := 50
	pendingWritesThreshold := 40
	log := &lruBoxesTestLogger{Logger: logging.TestingLog(t)}
	baseBoxes.init(log, pendingWritesBuffer, pendingWritesThreshold)

	for i := 0; i < pendingWritesBuffer*2; i++ {
		boxValue := fmt.Sprintf("box %d value", i)
		box := persistedBoxData{
			value: &boxValue,
			round: basics.Round(i),
		}
		baseBoxes.writePending(box, fmt.Sprintf("key%d", i))
	}

	baseBoxes.flushPendingWrites()

	// verify that all these boxes are truly there.
	for i := 0; i < pendingWritesBuffer; i++ {
		box, has := baseBoxes.read(fmt.Sprintf("key%d", i))
		require.True(t, has)
		require.Equal(t, basics.Round(i), box.round)
		require.Equal(t, fmt.Sprintf("box %d value", i), *(box.value))
	}

	// verify expected missing entries
	for i := pendingWritesBuffer; i < pendingWritesBuffer*2; i++ {
		box, has := baseBoxes.read(fmt.Sprintf("key%d", i))
		require.False(t, has)
		require.Equal(t, persistedBoxData{}, box)
	}
}

func BenchmarkLRUBoxesWrite(b *testing.B) {
	numTestBoxes := 5000
	// there are 2500 boxes that overlap
	fillerBoxes := generatePersistedBoxesData(0, 97500)
	boxes := generatePersistedBoxesData(97500-numTestBoxes/2, 97500+numTestBoxes/2)

	benchLruWriteBoxes(b, fillerBoxes, boxes)
}

func benchLruWriteBoxes(b *testing.B, fillerBoxes []cachedBoxData, boxes []cachedBoxData) {
	b.ResetTimer()
	b.StopTimer()
	var baseBoxes lruBoxes
	// setting up the baseBoxes with a predefined cache size
	baseBoxes.init(logging.TestingLog(b), baseResourcesPendingAccountsBufferSize, baseResourcesPendingAccountsWarnThreshold)
	for i := 0; i < b.N; i++ {
		baseBoxes = fillLRUBoxes(baseBoxes, fillerBoxes)

		b.StartTimer()
		fillLRUBoxes(baseBoxes, boxes)
		b.StopTimer()
		baseBoxes.prune(0)
	}
}

func fillLRUBoxes(baseBoxes lruBoxes, fillerBoxes []cachedBoxData) lruBoxes {
	for _, entry := range fillerBoxes {
		baseBoxes.write(entry.persistedBoxData, entry.key)
	}
	return baseBoxes
}

func generatePersistedBoxesData(startRound, endRound int) []cachedBoxData {
	boxes := make([]cachedBoxData, endRound-startRound)
	for i := startRound; i < endRound; i++ {
		boxValue := fmt.Sprintf("box %d value", i)

		boxes[i-startRound] = cachedBoxData{
			persistedBoxData: persistedBoxData{
				value: &boxValue,
				round: basics.Round(i + startRound),
			},
			key: fmt.Sprintf("key%d", i),
		}
	}
	return boxes
}
