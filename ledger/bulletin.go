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
	"sync/atomic"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/common"
)

// notifier is a struct that encapsulates a single-shot channel; it will only be signaled once.
type notifier struct {
	signal   chan struct{}
	notified uint32
}

// makeNotifier constructs a notifier that has not been signaled.
func makeNotifier() notifier {
	return notifier{signal: make(chan struct{}), notified: 0}
}

// notify signals the channel if it hasn't already done so
func (notifier *notifier) notify() {
	if atomic.CompareAndSwapUint32(&notifier.notified, 0, 1) {
		close(notifier.signal)
	}
}

// bulletin provides an easy way to wait on a round to be written to the ledger.
// To use it, call <-Wait(round)
type bulletin struct {
	mu                          deadlock.Mutex
	pendingNotificationRequests map[basics.Round]notifier
	latestRound                 basics.Round
}

func makeBulletin() *bulletin {
	b := new(bulletin)
	b.pendingNotificationRequests = make(map[basics.Round]notifier)
	return b
}

// Wait returns a channel which gets closed when the ledger reaches a given round.
func (b *bulletin) Wait(round basics.Round) chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Return an already-closed channel if we already have the block.
	if round <= b.latestRound {
		closed := make(chan struct{})
		close(closed)
		return closed
	}

	signal, exists := b.pendingNotificationRequests[round]
	if !exists {
		signal = makeNotifier()
		b.pendingNotificationRequests[round] = signal
	}
	return signal.signal
}

func (b *bulletin) loadFromDisk(l ledgerForTracker) error {
	b.pendingNotificationRequests = make(map[basics.Round]notifier)
	b.latestRound = l.Latest()
	return nil
}

func (b *bulletin) close() {
}

func (b *bulletin) newBlock(blk bookkeeping.Block, delta common.StateDelta) {
}

func (b *bulletin) committedUpTo(rnd basics.Round) basics.Round {
	b.mu.Lock()
	defer b.mu.Unlock()

	for pending, signal := range b.pendingNotificationRequests {
		if pending > rnd {
			continue
		}

		delete(b.pendingNotificationRequests, pending)
		signal.notify()
	}

	b.latestRound = rnd
	return rnd
}
