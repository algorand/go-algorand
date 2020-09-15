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
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/metrics"
)

type blockEntry struct {
	block bookkeeping.Block
	cert  agreement.Certificate
}

type blockQueue struct {
	l *Ledger

	lastCommitted basics.Round
	q             []blockEntry

	mu      deadlock.Mutex
	cond    *sync.Cond
	running bool
	closed  chan struct{}
}

var ledger_init_count = metrics.NewCounter("ledger_init_count", "calls to init block queue")
var ledger_init_ms = metrics.NewCounter("ledger_init_ms", "ms spent to init block queue")
var ledger_sync_blockput_count = metrics.NewCounter("ledger_sync_blockput_count", "calls to sync block queue")
var ledger_sync_blockput_ms = metrics.NewCounter("ledger_sync_blockput_ms", "ms spent to sync block queue")
var ledger_sync_blockforget_count = metrics.NewCounter("ledger_sync_blockforget_count", "calls")
var ledger_sync_blockforget_ms = metrics.NewCounter("ledger_sync_blockforget_ms", "ms spent")
var ledger_getblock_count = metrics.NewCounter("ledger_getblock_count", "calls")
var ledger_getblock_ms = metrics.NewCounter("ledger_getblock_ms", "ms spent")
var ledger_getblockhdr_count = metrics.NewCounter("ledger_getblockhdr_count", "calls")
var ledger_getblockhdr_ms = metrics.NewCounter("ledger_getblockhdr_ms", "ms spent")
var ledger_geteblockcert_count = metrics.NewCounter("ledger_geteblockcert_count", "calls")
var ledger_geteblockcert_ms = metrics.NewCounter("ledger_geteblockcert_ms", "ms spent")
var ledger_getblockcert_count = metrics.NewCounter("ledger_getblockcert_count", "calls")
var ledger_getblockcert_ms = metrics.NewCounter("ledger_getblockcert_ms", "ms spent")

// TODO: promote this to a utility function in util/metrics ?
func counterMs(counter *metrics.Counter, start time.Time) {
	counter.AddUint64(uint64(time.Now().Sub(start).Milliseconds()), nil)
}

func bqInit(l *Ledger) (*blockQueue, error) {
	bq := &blockQueue{}
	bq.cond = sync.NewCond(&bq.mu)
	bq.l = l
	bq.running = true
	bq.closed = make(chan struct{})
	ledger_init_count.Inc(nil)
	start := time.Now()
	err := bq.l.blockDBs.rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var err0 error
		bq.lastCommitted, err0 = blockLatest(tx)
		return err0
	})
	counterMs(ledger_init_ms, start)
	if err != nil {
		return nil, err
	}

	go bq.syncer()
	return bq, nil
}

func (bq *blockQueue) close() {
	bq.mu.Lock()
	defer func() {
		bq.mu.Unlock()
		// we want to block here until the sync go routine is done.
		// it's not (just) for the sake of a complete cleanup, but rather
		// to ensure that the sync goroutine isn't busy in a notifyCommit
		// call which might be blocked inside one of the trackers.
		<-bq.closed
	}()

	if bq.running {
		bq.running = false
		bq.cond.Broadcast()
	}

}

func (bq *blockQueue) syncer() {
	defer close(bq.closed)
	bq.mu.Lock()
	for {
		for bq.running && len(bq.q) == 0 {
			bq.cond.Wait()
		}

		if !bq.running {
			bq.mu.Unlock()
			return
		}

		workQ := bq.q
		bq.mu.Unlock()

		start := time.Now()
		ledger_sync_blockput_count.Inc(nil)
		err := bq.l.blockDBs.wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			for _, e := range workQ {
				err0 := blockPut(tx, e.block, e.cert)
				if err0 != nil {
					return err0
				}
			}
			return nil
		})
		counterMs(ledger_sync_blockput_ms, start)

		bq.mu.Lock()

		if err != nil {
			bq.l.log.Warnf("blockQueue.syncer: could not flush: %v", err)
		} else {
			bq.lastCommitted += basics.Round(len(workQ))
			bq.q = bq.q[len(workQ):]

			// Sanity-check: if we wrote any blocks, then the last
			// one must be from round bq.lastCommitted.
			if len(workQ) > 0 {
				lastWritten := workQ[len(workQ)-1].block.Round()
				if lastWritten != bq.lastCommitted {
					bq.l.log.Panicf("blockQueue.syncer: lastCommitted %v lastWritten %v workQ %v",
						bq.lastCommitted, lastWritten, workQ)
				}
			}

			committed := bq.lastCommitted
			bq.cond.Broadcast()
			bq.mu.Unlock()

			minToSave := bq.l.notifyCommit(committed)
			bfstart := time.Now()
			ledger_sync_blockforget_count.Inc(nil)
			err = bq.l.blockDBs.wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
				return blockForgetBefore(tx, minToSave)
			})
			counterMs(ledger_sync_blockforget_ms, bfstart)
			if err != nil {
				bq.l.log.Warnf("blockQueue.syncer: blockForgetBefore(%d): %v", minToSave, err)
			}

			bq.mu.Lock()
		}
	}
}

func (bq *blockQueue) waitCommit(r basics.Round) {
	bq.mu.Lock()
	defer bq.mu.Unlock()

	for bq.lastCommitted < r {
		bq.cond.Wait()
	}
}

func (bq *blockQueue) latest() basics.Round {
	bq.mu.Lock()
	defer bq.mu.Unlock()
	return bq.lastCommitted + basics.Round(len(bq.q))
}

func (bq *blockQueue) latestCommitted() basics.Round {
	bq.mu.Lock()
	defer bq.mu.Unlock()
	return bq.lastCommitted
}

func (bq *blockQueue) putBlock(blk bookkeeping.Block, cert agreement.Certificate) error {
	bq.mu.Lock()
	defer bq.mu.Unlock()

	nextRound := bq.lastCommitted + basics.Round(len(bq.q)) + 1

	// As an optimization to reduce warnings in logs, return a special
	// error when we're trying to store an old block.
	if blk.Round() < nextRound {
		bq.mu.Unlock()
		// lock is unnecessary here for sanity check
		myblk, mycert, err := bq.getBlockCert(blk.Round())
		if err == nil && myblk.Hash() != blk.Hash() {
			logging.Base().Errorf("bqPutBlock: tried to write fork: our (block,cert) is (%#v, %#v); other (block,cert) is (%#v, %#v)", myblk, mycert, blk, cert)
		}
		bq.mu.Lock()

		return BlockInLedgerError{blk.Round(), nextRound}
	}

	if blk.Round() != nextRound {
		return fmt.Errorf("bqPutBlock: got block %d, but expected %d", blk.Round(), nextRound)
	}

	bq.q = append(bq.q, blockEntry{
		block: blk,
		cert:  cert,
	})
	bq.cond.Broadcast()
	return nil
}

func (bq *blockQueue) checkEntry(r basics.Round) (e *blockEntry, lastCommitted basics.Round, latest basics.Round, err error) {
	bq.mu.Lock()
	defer bq.mu.Unlock()

	// To help the caller form a more informative ErrNoEntry
	lastCommitted = bq.lastCommitted
	latest = bq.lastCommitted + basics.Round(len(bq.q))

	if r > bq.lastCommitted+basics.Round(len(bq.q)) {
		return nil, lastCommitted, latest, ErrNoEntry{
			Round:     r,
			Latest:    latest,
			Committed: lastCommitted,
		}
	}

	if r <= bq.lastCommitted {
		return nil, lastCommitted, latest, nil
	}

	return &bq.q[r-bq.lastCommitted-1], lastCommitted, latest, nil
}

func updateErrNoEntry(err error, lastCommitted basics.Round, latest basics.Round) error {
	if err != nil {
		switch errt := err.(type) {
		case ErrNoEntry:
			errt.Committed = lastCommitted
			errt.Latest = latest
			return errt
		}
	}

	return err
}

func (bq *blockQueue) getBlock(r basics.Round) (blk bookkeeping.Block, err error) {
	e, lastCommitted, latest, err := bq.checkEntry(r)
	if e != nil {
		return e.block, nil
	}

	if err != nil {
		return
	}

	start := time.Now()
	ledger_getblock_count.Inc(nil)
	err = bq.l.blockDBs.rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var err0 error
		blk, err0 = blockGet(tx, r)
		return err0
	})
	counterMs(ledger_getblock_ms, start)
	err = updateErrNoEntry(err, lastCommitted, latest)
	return
}

func (bq *blockQueue) getBlockHdr(r basics.Round) (hdr bookkeeping.BlockHeader, err error) {
	e, lastCommitted, latest, err := bq.checkEntry(r)
	if e != nil {
		return e.block.BlockHeader, nil
	}

	if err != nil {
		return
	}

	start := time.Now()
	ledger_getblockhdr_count.Inc(nil)
	err = bq.l.blockDBs.rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var err0 error
		hdr, err0 = blockGetHdr(tx, r)
		return err0
	})
	counterMs(ledger_getblockhdr_ms, start)
	err = updateErrNoEntry(err, lastCommitted, latest)
	return
}

func (bq *blockQueue) getEncodedBlockCert(r basics.Round) (blk []byte, cert []byte, err error) {
	e, lastCommitted, latest, err := bq.checkEntry(r)
	if e != nil {
		// block has yet to be committed. we'll need to encode it.
		blk = protocol.Encode(&e.block)
		cert = protocol.Encode(&e.cert)
		err = nil
		return
	}

	if err != nil {
		return
	}

	start := time.Now()
	ledger_geteblockcert_count.Inc(nil)
	err = bq.l.blockDBs.rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var err0 error
		blk, cert, err0 = blockGetEncodedCert(tx, r)
		return err0
	})
	counterMs(ledger_geteblockcert_ms, start)
	err = updateErrNoEntry(err, lastCommitted, latest)
	return
}

func (bq *blockQueue) getBlockCert(r basics.Round) (blk bookkeeping.Block, cert agreement.Certificate, err error) {
	e, lastCommitted, latest, err := bq.checkEntry(r)
	if e != nil {
		return e.block, e.cert, nil
	}

	if err != nil {
		return
	}

	start := time.Now()
	ledger_getblockcert_count.Inc(nil)
	err = bq.l.blockDBs.rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var err0 error
		blk, cert, err0 = blockGetCert(tx, r)
		return err0
	})
	counterMs(ledger_getblockcert_ms, start)
	err = updateErrNoEntry(err, lastCommitted, latest)
	return
}
