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
	"time"

	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/logging"
)

var log = logging.Base()

type blockListener interface {
	init(uint64)
	onBlock(v1.Block)
}

type blockWatcher struct {
	client Client
	delay  time.Duration
	abort  <-chan struct{}
}

func runBlockWatcher(watchers []blockListener, client Client, abort <-chan struct{}, wg *sync.WaitGroup, delay time.Duration, stallDetect time.Duration) {
	defer wg.Done()

	blockWatcher := blockWatcher{
		client: client,
		delay:  delay,
		abort:  abort,
	}

	log.Infof("Block watcher initializing with %d watchers.", len(watchers))

	curBlock, ok := blockWatcher.blockUntilReady()
	if !ok {
		return
	}
	log.Infof("Block watcher initialized with block %d.", curBlock)

	for _, watcher := range watchers {
		watcher.init(curBlock)
	}

	// Continue until things are not ok
	for ok {
		ok = blockWatcher.run(watchers, stallDetect, curBlock)
		if !ok {
			return
		}

		// If we returned, we hit a stall, so restart our logic once we get the next block
		curBlock, ok = blockWatcher.blockUntilReady()
	}
}

func (bw *blockWatcher) run(watchers []blockListener, stallDetect time.Duration, curBlock uint64) bool {
	lastBlock := time.Now()
	for {
		// Inner loop needed during catchup.
		for {
			block, err := bw.client.Block(curBlock)

			// Generally this error will be due to the new block not being ready. In the case of a stall we will
			// return, causing the loop to restart and handle any possible stall/catchup.
			if err != nil {
				if time.Since(lastBlock) > stallDetect {
					return true
				}
				if !bw.sleep(bw.delay) {
					return false
				}
				break
			}

			curBlock++
			for _, watcher := range watchers {
				watcher.onBlock(block)
			}
			lastBlock = time.Now()

			if !bw.sleep(bw.delay) {
				return false
			}
		}
	}
}

// This keeps retrying forever, or until an abort signal is received.
func (bw *blockWatcher) getLastRound() (uint64, bool) {
	for {
		status, err := bw.client.Status()
		if err != nil {
			if !bw.sleep(bw.delay) {
				return 0, false
			}
			continue
		}
		return status.LastRound, true
	}
}

func (bw *blockWatcher) blockUntilReady() (curBlock uint64, ok bool) {
	curBlock, ok = bw.blockIfStalled()
	if !ok {
		return
	}

	return bw.blockIfCatchup(curBlock)
}

// blockIfStalled keeps checking status until the LastRound updates.
func (bw *blockWatcher) blockIfStalled() (uint64, bool) {
	curBlock, ok := bw.getLastRound()
	if !ok {
		return 0, false
	}

	for {
		next, ok := bw.getLastRound()
		if !ok {
			return 0, false
		}

		if next != curBlock {
			return next, true
		}

		curBlock = next

		if !bw.sleep(bw.delay) {
			return 0, false
		}
	}
}

// blockIfCatchup blocks until the lastBlock stops quickly changing. An initial block is passed
func (bw *blockWatcher) blockIfCatchup(start uint64) (uint64, bool) {
	last := start

	for {
		if !bw.sleep(bw.delay) {
			return 0, false
		}

		next, ok := bw.getLastRound()
		if !ok {
			return 0, false
		}

		if last == next {
			return last, true
		}

		last = next
	}
}

func (bw *blockWatcher) sleep(duration time.Duration) (ok bool) {
	select {
	case <-bw.abort:
		return false
	case <-time.After(duration):
		return true
	}
}
