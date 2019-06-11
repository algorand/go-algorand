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

package ledger

import (
	"sync"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
)

// BlockListener represents an object that needs to get notified on new blocks.
type BlockListener interface {
	OnNewBlock(block bookkeeping.Block)
}

type blockNotifier struct {
	mu            deadlock.Mutex
	cond          *sync.Cond
	listeners     []BlockListener
	pendingBlocks []bookkeeping.Block
	running       bool
}

func (bn *blockNotifier) worker() {
	bn.mu.Lock()

	for {
		for bn.running && len(bn.pendingBlocks) == 0 {
			bn.cond.Wait()
		}

		if !bn.running {
			bn.mu.Unlock()
			return
		}

		blocks := bn.pendingBlocks
		listeners := bn.listeners
		bn.pendingBlocks = nil
		bn.mu.Unlock()

		for _, blk := range blocks {
			for _, listener := range listeners {
				listener.OnNewBlock(blk)
			}
		}

		bn.mu.Lock()
	}
}

func (bn *blockNotifier) close() {
	bn.mu.Lock()
	defer bn.mu.Unlock()
	if bn.running {
		bn.running = false
		bn.cond.Broadcast()
	}
}

func (bn *blockNotifier) loadFromDisk(l ledgerForTracker) error {
	bn.cond = sync.NewCond(&bn.mu)
	bn.running = true

	go bn.worker()
	return nil
}

func (bn *blockNotifier) register(listeners []BlockListener) {
	bn.mu.Lock()
	defer bn.mu.Unlock()

	bn.listeners = append(bn.listeners, listeners...)
}

func (bn *blockNotifier) newBlock(blk bookkeeping.Block, delta stateDelta) {
	bn.mu.Lock()
	defer bn.mu.Unlock()

	bn.pendingBlocks = append(bn.pendingBlocks, blk)
	bn.cond.Broadcast()
}

func (bn *blockNotifier) committedUpTo(rnd basics.Round) basics.Round {
	return rnd
}
