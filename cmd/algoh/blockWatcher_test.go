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

package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/stretchr/testify/require"
)

func bw(client Client) *blockWatcher {
	return &blockWatcher{
		abort:  make(chan struct{}),
		delay:  0,
		client: client,
	}
}

// Given we are at block 300.
// When the status continues to report block 300
// Then blockIfStalled will block until the next block is reported
func TestBlockIfStalled(t *testing.T) {
	client := mockClient{
		error:   []error{nil, nil, nil},
		status:  makeNodeStatuses(300, 300, 300, 301),
		block:   makeBlocks(),
		routine: []string{"", "", ""},
	}

	ret, ok := bw(&client).blockIfStalled()
	require.True(t, ok)

	if ret != 301 {
		t.Errorf("Unexpected result, wanted 301 found: %d", ret)
	}

	require.Equal(t, 4, client.StatusCalls)
}

// Given we are at block 300.
// When the status continues to increase quickly
// Then blockIfCatchup will block until a block is reported twice
func TestBlockIfCatchup(t *testing.T) {
	client := mockClient{
		error:   []error{nil, nil, nil},
		status:  makeNodeStatuses(301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 310),
		block:   makeBlocks(),
		routine: []string{"", "", ""},
	}

	ret, ok := bw(&client).blockIfCatchup(300)
	require.True(t, ok)

	if ret != 310 {
		t.Errorf("Unexpected result, wanted 310 found: %d", ret)
	}

	require.Equal(t, 11, client.StatusCalls)
}

// Given we are at block 300.
// When the status is not changing quickly
// Then blockIfCatchup will return after the first status call.
func TestBlockIfCaughtUp(t *testing.T) {
	client := mockClient{
		error:   []error{nil, nil, nil},
		status:  makeNodeStatuses(300),
		block:   makeBlocks(),
		routine: []string{"", "", ""},
	}

	ret, ok := bw(&client).blockIfCatchup(300)

	require.True(t, ok)
	if ret != 300 {
		t.Errorf("Unexpected result, wanted 300 found: %d", ret)
	}

	require.Equal(t, 1, client.StatusCalls)
}

type testlistener struct {
	initCount  uint32
	blockCount uint32
}

func (l *testlistener) init(block uint64) {
	atomic.AddUint32(&(l.initCount), 1)
}

func (l *testlistener) onBlock(block v1.Block) {
	atomic.AddUint32(&(l.blockCount), 1)
}

func TestE2E(t *testing.T) {
	client := makeMockClient(
		[]error{nil, nil, nil},
		makeNodeStatuses(300, 301, 302, 302, 302, 302, 302, 302, 310, 320, 321, 321, 321, 322),
		makeBlocks(302, 321, 322),
		[]string{"", "", ""})

	listener := testlistener{
		initCount:  0,
		blockCount: 0,
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)

	listeners := []blockListener{&listener}

	// Start block watcher in background.
	go runBlockWatcher(listeners, &client, done, &wg, time.Second, 2*time.Second)

	// Wait until the first block has been requested after the init/catchup phase.
	start := time.Now()
	for time.Since(start) < 20*time.Second && atomic.LoadUint32(&listener.initCount) == uint32(0) {
		time.Sleep(time.Second)
	}

	require.Equal(t, uint32(1), atomic.LoadUint32(&listener.initCount), "Init should have been called once.")

	// Simulate stall at block 301 followed by catchup.
	waitForStall := time.Now()
	for time.Since(waitForStall) < 10*time.Second && atomic.LoadUint32(&listener.blockCount) < uint32(3) {
		time.Sleep(time.Second)
	}

	// Shutdown blockwatcher.
	done <- struct{}{}
	wg.Wait()

	// Stalled while attempting to fetch block 303
	require.Equal(t, 1, client.BlockCalls[302])
	require.True(t, client.BlockCalls[303] > 1)

	// After catching up successfully fetched 321 / 322
	require.Equal(t, 1, client.BlockCalls[321])
	require.Equal(t, 1, client.BlockCalls[322])
}

func TestAbortDuringStall(t *testing.T) {
	client := makeMockClient(
		[]error{},
		makeNodeStatuses(300),
		makeBlocks(),
		[]string{})

	listener := testlistener{
		initCount:  0,
		blockCount: 0,
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)

	listeners := []blockListener{&listener}

	// Start block watcher in background.
	go runBlockWatcher(listeners, &client, done, &wg, time.Second, 2*time.Second)

	time.Sleep(500 * time.Millisecond)
	done <- struct{}{}
	wg.Wait()
}
