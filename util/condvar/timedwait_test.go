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

package condvar

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-deadlock"
)

func TestTimedWaitSignal(t *testing.T) {
	var m deadlock.Mutex
	var signal bool
	c := sync.NewCond(&m)

	m.Lock()
	defer m.Unlock()

	go func() {
		<-time.After(time.Second)
		m.Lock()
		defer m.Unlock()

		c.Signal()
		signal = true
	}()

	// If the signal doesn't get delivered, the test will time out.
	TimedWait(c, 24*time.Hour)

	// Make sure TimedWait() didn't return prematurely
	require.True(t, signal)
}

func TestTimedWaitBroadcast(t *testing.T) {
	var m deadlock.Mutex
	var signal bool
	c := sync.NewCond(&m)

	m.Lock()
	defer m.Unlock()

	go func() {
		<-time.After(time.Second)
		m.Lock()
		defer m.Unlock()

		c.Broadcast()
		signal = true
	}()

	// If the signal doesn't get delivered, the test will time out.
	TimedWait(c, 24*time.Hour)

	// Make sure TimedWait() didn't return prematurely
	require.True(t, signal)
}

func TestTimedWaitTimeout(t *testing.T) {
	var m deadlock.Mutex
	c := sync.NewCond(&m)

	m.Lock()
	defer m.Unlock()

	// If the timeout doesn't work, the test will time out.
	TimedWait(c, time.Second)
}
