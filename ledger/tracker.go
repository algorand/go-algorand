// Copyright (C) 2019-2020 Algorand, Inc.
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
	"reflect"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
)

// ledgerTracker defines part of the API for any state machine that
// tracks the ledger's blockchain.  In addition to the API below,
// each ledgerTracker provides a tracker-specific read-only API
// (e.g., querying the balance of an account).
//
// A tracker's read-only API must be indexed by rounds, and the
// tracker must be prepared to answer queries for rounds until a
// subsequent call to committedUpTo().
//
// For example, the rewards AVL tree must be prepared to answer
// queries for old rounds, even if the tree has moved on in response
// to newBlock() calls.  It should do so by remembering the precise
// answer for old rounds, until committedUpTo() allows it to GC
// those old answers.
//
// The ledger provides a RWMutex to ensure that the tracker is invoked
// with at most one modification API call (below), OR zero modification
// calls and any number of read-only calls.  If internally the tracker
// modifies state in response to read-only calls, it is the tracker's
// responsibility to ensure thread-safety.
type ledgerTracker interface {
	// loadFromDisk loads the state of a tracker from persistent
	// storage.  The ledger argument allows loadFromDisk to load
	// blocks from the database, or access its own state.  The
	// ledgerForTracker interface abstracts away the details of
	// ledger internals so that individual trackers can be tested
	// in isolation.
	loadFromDisk(ledgerForTracker) error

	// newBlock informs the tracker of a new block from round
	// rnd and a given StateDelta as produced by BlockEvaluator.
	newBlock(blk bookkeeping.Block, delta StateDelta)

	// committedUpTo informs the tracker that the database has
	// committed all blocks up to and including rnd to persistent
	// storage (the SQL database).  This can allow the tracker
	// to garbage-collect state that will not be needed.
	//
	// committedUpTo() returns the round number of the earliest
	// block that this tracker needs to be stored in the ledger
	// for subsequent calls to loadFromDisk().  All blocks with
	// round numbers before that may be deleted to save space,
	// and the tracker is expected to still function after a
	// restart and a call to loadFromDisk().  For example,
	// returning 0 means that no blocks can be deleted.
	committedUpTo(basics.Round) basics.Round

	// close terminates the tracker, reclaiming any resources
	// like open database connections or goroutines.  close may
	// be called even if loadFromDisk() is not called or does
	// not succeed.
	close()
}

// ledgerForTracker defines the part of the ledger that a tracker can
// access.  This is particularly useful for testing trackers in isolation.
type ledgerForTracker interface {
	trackerDB() dbPair
	blockDB() dbPair
	trackerLog() logging.Logger
	trackerEvalVerified(bookkeeping.Block, ledgerForEvaluator) (StateDelta, error)

	Latest() basics.Round
	Block(basics.Round) (bookkeeping.Block, error)
	BlockHdr(basics.Round) (bookkeeping.BlockHeader, error)
	GenesisHash() crypto.Digest
	GenesisProto() config.ConsensusParams
}

type trackerRegistry struct {
	trackers []ledgerTracker
}

func (tr *trackerRegistry) register(lt ledgerTracker) {
	tr.trackers = append(tr.trackers, lt)
}

func (tr *trackerRegistry) loadFromDisk(l ledgerForTracker) error {
	for _, lt := range tr.trackers {
		err := lt.loadFromDisk(l)
		if err != nil {
			// find the tracker name.
			trackerName := reflect.TypeOf(lt).String()
			return fmt.Errorf("tracker %s failed to loadFromDisk : %v", trackerName, err)
		}
	}

	return nil
}

func (tr *trackerRegistry) newBlock(blk bookkeeping.Block, delta StateDelta) {
	for _, lt := range tr.trackers {
		lt.newBlock(blk, delta)
	}
	if len(tr.trackers) == 0 {
		fmt.Printf("trackerRegistry::newBlock - no trackers (%d)\n", blk.Round())
	}
}

func (tr *trackerRegistry) committedUpTo(rnd basics.Round) basics.Round {
	minBlock := rnd

	for _, lt := range tr.trackers {
		retain := lt.committedUpTo(rnd)
		if retain < minBlock {
			minBlock = retain
		}
	}

	return minBlock
}

func (tr *trackerRegistry) close() {
	for _, lt := range tr.trackers {
		lt.close()
	}
	tr.trackers = nil
}
