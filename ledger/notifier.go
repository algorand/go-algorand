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

package ledger

import (
	"context"
	"database/sql"
	"sync"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// BlockListener represents an object that needs to get notified on new blocks.
type BlockListener interface {
	OnNewBlock(block bookkeeping.Block, delta ledgercore.StateDelta)
}

type blockDeltaPair struct {
	block bookkeeping.Block
	delta ledgercore.StateDelta
}

type blockNotifier struct {
	mu            deadlock.Mutex
	cond          *sync.Cond
	listeners     []BlockListener
	pendingBlocks []blockDeltaPair
	running       bool
	// closing is the waitgroup used to synchronize closing the worker goroutine. It's being increased during loadFromDisk, and the worker is responsible to call Done on it once it's aborting it's goroutine. The close function waits on this to complete.
	closing sync.WaitGroup
}

func (bn *blockNotifier) worker() {
	defer bn.closing.Done()
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
				listener.OnNewBlock(blk.block, blk.delta)
			}
		}

		bn.mu.Lock()
	}
}

func (bn *blockNotifier) close() {
	bn.mu.Lock()
	if bn.running {
		bn.running = false
		bn.cond.Broadcast()
	}
	bn.mu.Unlock()
	bn.closing.Wait()
}

func (bn *blockNotifier) loadFromDisk(l ledgerForTracker, _ basics.Round) error {
	bn.cond = sync.NewCond(&bn.mu)
	bn.running = true
	bn.pendingBlocks = nil
	bn.closing.Add(1)
	go bn.worker()
	return nil
}

func (bn *blockNotifier) register(listeners []BlockListener) {
	bn.mu.Lock()
	defer bn.mu.Unlock()

	bn.listeners = append(bn.listeners, listeners...)
}

func (bn *blockNotifier) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	bn.mu.Lock()
	defer bn.mu.Unlock()
	bn.pendingBlocks = append(bn.pendingBlocks, blockDeltaPair{block: blk, delta: delta})
	bn.cond.Broadcast()
}

func (bn *blockNotifier) committedUpTo(rnd basics.Round) (retRound, lookback basics.Round) {
	return rnd, basics.Round(0)
}

func (bn *blockNotifier) prepareCommit(dcc *deferredCommitContext) error {
	return nil
}

func (bn *blockNotifier) commitRound(context.Context, *sql.Tx, *deferredCommitContext) error {
	return nil
}

func (bn *blockNotifier) postCommit(ctx context.Context, dcc *deferredCommitContext) {
}

func (bn *blockNotifier) postCommitUnlocked(ctx context.Context, dcc *deferredCommitContext) {
}

func (bn *blockNotifier) handleUnorderedCommit(uint64, basics.Round, basics.Round) {
}

func (bn *blockNotifier) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return dcr
}
