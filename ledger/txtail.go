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
	"context"
	"database/sql"
	"fmt"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

const initialLastValidArrayLen = 256

// enableTxTailHashes enables txtail data hashing for catchpoints.
// enable by removing it as needed (phase 2 of the catchpoints re-work)
const enableTxTailHashes = false

type roundLeases struct {
	txleases map[ledgercore.Txlease]basics.Round // map of transaction lease to when it expires
	proto    config.ConsensusParams
}

type txTail struct {
	recent map[basics.Round]roundLeases

	// roundTailSerializedDeltas contains the rounds that need to be flushed to disk.
	// It contain the serialized(encoded) form of the txTailRound. This field would remain
	// maintained in this data structure up until being cleared out by postCommit
	roundTailSerializedDeltas [][]byte

	// roundTailHashes contains the recent (MaxTxnLife + DeeperBlockHeaderHistory + len(deltas)) hashes.
	// The first entry matches that current tracker database round - (MaxTxnLife + DeeperBlockHeaderHistory) + 1
	// the second to tracker database round - (MaxTxnLife + DeeperBlockHeaderHistory - 1) + 1, and so forth.
	// See blockHeaderData description below for the indexing details.
	//
	// The layout for MaxTxnLife = 3 and 3 elements in in-memory deltas:
	// ──────────────────┐
	// maxTxnLife(3) + 1 ├────────────
	//                   │  deltas
	//   │ 0 │ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ indices
	//   └───┴───┴───┴───┴───┴───┴───┘
	//     3   4   5   6   7   8   9   rounds
	//                /|\
	//                 │
	//              dbRound
	roundTailHashes []crypto.Digest

	// blockHeaderData contains the recent (MaxTxnLife + DeeperBlockHeaderHistory + len(deltas)) block header data.
	// The oldest entry is lowestBlockHeaderRound = database round - (MaxTxnLife + DeeperBlockHeaderHistory) + 1
	blockHeaderData map[basics.Round]bookkeeping.BlockHeader
	// lowestBlockHeaderRound is the lowest round in blockHeaderData, used as a starting point for old entries removal
	lowestBlockHeaderRound basics.Round

	// tailMu is the synchronization mutex for accessing roundTailHashes, roundTailSerializedDeltas and blockHeaderData.
	tailMu deadlock.RWMutex

	lastValid map[basics.Round]map[transactions.Txid]struct{} // map tx.LastValid -> tx confirmed set

	// duplicate detection queries with LastValid before
	// lowWaterMark are not guaranteed to succeed
	lowWaterMark basics.Round // the last round known to be committed to disk
}

func (t *txTail) loadFromDisk(l ledgerForTracker, dbRound basics.Round) error {
	rdb := l.trackerDB().Rdb

	var roundData []*txTailRound
	var roundTailHashes []crypto.Digest
	var baseRound basics.Round
	if dbRound > 0 {
		err := rdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
			roundData, roundTailHashes, baseRound, err = loadTxTail(ctx, tx, dbRound)
			return
		})
		if err != nil {
			return err
		}
	}

	t.lowWaterMark = l.Latest()
	t.lastValid = make(map[basics.Round]map[transactions.Txid]struct{})
	t.recent = make(map[basics.Round]roundLeases)

	// the roundsLastValids is a temporary map used during the execution of
	// loadFromDisk, allowing us to construct the lastValid maps in their
	// optimal size. This would ensure that upon startup, we don't preallocate
	// more memory than we truly need.
	roundsLastValids := make(map[basics.Round][]transactions.Txid)

	// the roundTailHashes and blockHeaderData need a single element to start with
	// in order to allow lookups on zero offsets when they are empty (new database)
	roundTailHashes = append([]crypto.Digest{{}}, roundTailHashes...)
	blockHeaderData := make(map[basics.Round]bookkeeping.BlockHeader, len(roundData)+1)

	t.lowestBlockHeaderRound = baseRound
	for old := baseRound; old <= dbRound && dbRound > baseRound; old++ {
		txTailRound := roundData[0]
		consensusParams := config.Consensus[txTailRound.Hdr.CurrentProtocol]

		t.recent[old] = roundLeases{
			txleases: make(map[ledgercore.Txlease]basics.Round, len(txTailRound.Leases)),
			proto:    consensusParams,
		}

		if consensusParams.SupportTransactionLeases {
			for i := 0; i < len(txTailRound.Leases); i++ {
				if txTailRound.Leases[i].Lease != [32]byte{} {
					key := ledgercore.Txlease{Sender: txTailRound.Leases[i].Sender, Lease: txTailRound.Leases[i].Lease}
					t.recent[old].txleases[key] = txTailRound.LastValid[txTailRound.Leases[i].TxnIdx]
				}
			}
		}

		for i := 0; i < len(txTailRound.LastValid); i++ {
			if txTailRound.LastValid[i] > t.lowWaterMark {
				list := roundsLastValids[txTailRound.LastValid[i]]
				// if the list reached capacity, resize.
				if len(list) == cap(list) {
					var newList []transactions.Txid
					if cap(list) == 0 {
						newList = make([]transactions.Txid, 0, initialLastValidArrayLen)
					} else {
						newList = make([]transactions.Txid, len(list), len(list)*2)
					}
					copy(newList[:], list[:])
					list = newList
				}
				list = append(list, txTailRound.TxnIDs[i])
				roundsLastValids[txTailRound.LastValid[i]] = list
			}
		}

		blockHeaderData[old] = txTailRound.Hdr
		roundData = roundData[1:]
	}

	// add all the entries in roundsLastValids to their corresponding map entry in t.lastValid
	for lastValid, list := range roundsLastValids {
		lastValueMap := make(map[transactions.Txid]struct{}, len(list))
		for _, id := range list {
			lastValueMap[id] = struct{}{}
		}
		t.lastValid[lastValid] = lastValueMap
	}

	if enableTxTailHashes {
		t.roundTailHashes = roundTailHashes
	}
	t.blockHeaderData = blockHeaderData
	t.roundTailSerializedDeltas = make([][]byte, 0)

	return nil
}

func (t *txTail) close() {
}

func (t *txTail) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	rnd := blk.Round()

	if _, has := t.recent[rnd]; has {
		// Repeat, ignore
		return
	}

	var tail txTailRound
	tail.TxnIDs = make([]transactions.Txid, len(delta.Txids))
	tail.LastValid = make([]basics.Round, len(delta.Txids))
	tail.Hdr = blk.BlockHeader

	for txid, txnInc := range delta.Txids {
		t.putLV(txnInc.LastValid, txid)
		tail.TxnIDs[txnInc.TransactionIndex] = txid
		tail.LastValid[txnInc.TransactionIndex] = txnInc.LastValid
		if blk.Payset[txnInc.TransactionIndex].Txn.Lease != [32]byte{} {
			tail.Leases = append(tail.Leases, txTailRoundLease{
				Sender: blk.Payset[txnInc.TransactionIndex].Txn.Sender,
				Lease:  blk.Payset[txnInc.TransactionIndex].Txn.Lease,
				TxnIdx: txnInc.TransactionIndex,
			})
		}
	}
	encodedTail, tailHash := tail.encode()

	t.tailMu.Lock()
	t.recent[rnd] = roundLeases{
		txleases: delta.Txleases,
		proto:    config.Consensus[blk.CurrentProtocol],
	}
	t.roundTailSerializedDeltas = append(t.roundTailSerializedDeltas, encodedTail)
	if enableTxTailHashes {
		t.roundTailHashes = append(t.roundTailHashes, tailHash)
	}
	t.blockHeaderData[rnd] = blk.BlockHeader
	t.tailMu.Unlock()
}

func (t *txTail) committedUpTo(rnd basics.Round) (retRound, lookback basics.Round) {
	proto := t.recent[rnd].proto
	maxlife := basics.Round(proto.MaxTxnLife)

	for r := range t.recent {
		if r+maxlife < rnd {
			delete(t.recent, r)
		}
	}
	for ; t.lowWaterMark < rnd; t.lowWaterMark++ {
		delete(t.lastValid, t.lowWaterMark)
	}

	deeperHistory := basics.Round(proto.DeeperBlockHeaderHistory)
	return (rnd + 1).SubSaturate(maxlife + deeperHistory), basics.Round(0)
}

func (t *txTail) prepareCommit(dcc *deferredCommitContext) (err error) {
	if !dcc.catchpointFirstStage {
		return nil
	}

	if enableTxTailHashes {
		rnd := dcc.oldBase + basics.Round(dcc.offset)
		t.tailMu.RLock()
		proto, ok := config.Consensus[t.blockHeaderData[rnd].CurrentProtocol]
		if !ok {
			lowest := t.lowestBlockHeaderRound
			t.tailMu.RUnlock()
			return fmt.Errorf("round %d not found in blockHeaderData: lowest=%d, base=%d", rnd, lowest, dcc.oldBase)
		}
		t.tailMu.RUnlock()
		// update the dcc with the hash we'll need.
		dcc.txTailHash, err = t.recentTailHash(dcc.offset, proto.MaxTxnLife+proto.DeeperBlockHeaderHistory)
	}
	return
}

func (t *txTail) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) error {
	roundsData := make([][]byte, 0, dcc.offset)

	t.tailMu.RLock()
	for i := uint64(0); i < dcc.offset; i++ {
		roundsData = append(roundsData, t.roundTailSerializedDeltas[i])
	}
	// get the MaxTxnLife from the consensus params of the latest round in this commit range
	// preserve data for MaxTxnLife + DeeperBlockHeaderHistory
	rnd := dcc.oldBase + basics.Round(dcc.offset)
	proto, ok := config.Consensus[t.blockHeaderData[rnd].CurrentProtocol]
	if !ok {
		lowest := t.lowestBlockHeaderRound
		t.tailMu.RUnlock()
		return fmt.Errorf("round %d not found in blockHeaderData: lowest=%d, base=%d", rnd, lowest, dcc.oldBase)
	}
	retainSize := proto.MaxTxnLife + proto.DeeperBlockHeaderHistory
	t.tailMu.RUnlock()

	// determine the round to remove data
	// This is the similar formula to the committedUpTo: rnd + 1 - retain size
	forgetBeforeRound := (dcc.newBase + 1).SubSaturate(basics.Round(retainSize))
	baseRound := dcc.oldBase + 1
	if err := txtailNewRound(ctx, tx, baseRound, roundsData, forgetBeforeRound); err != nil {
		return fmt.Errorf("txTail: unable to persist new round %d : %w", baseRound, err)
	}
	return nil
}

func (t *txTail) postCommit(ctx context.Context, dcc *deferredCommitContext) {
	t.tailMu.Lock()
	newBase := dcc.newBase

	t.roundTailSerializedDeltas = t.roundTailSerializedDeltas[dcc.offset:]

	// get the MaxTxnLife from the consensus params of the latest round in this commit range
	// preserve data for MaxTxnLife + DeeperBlockHeaderHistory rounds
	proto := config.Consensus[t.blockHeaderData[newBase].CurrentProtocol]
	retainSize := proto.MaxTxnLife + proto.DeeperBlockHeaderHistory
	newLowestRound := (newBase + 1).SubSaturate(basics.Round(retainSize))
	for t.lowestBlockHeaderRound < newLowestRound {
		delete(t.blockHeaderData, t.lowestBlockHeaderRound)
		t.lowestBlockHeaderRound++
	}
	if enableTxTailHashes {
		newDeltaLength := len(t.roundTailSerializedDeltas)
		firstTailIdx := len(t.roundTailHashes) - newDeltaLength - int(retainSize)
		if firstTailIdx > 0 {
			t.roundTailHashes = t.roundTailHashes[firstTailIdx:]
		}
	}
	t.tailMu.Unlock()
}

func (t *txTail) postCommitUnlocked(ctx context.Context, dcc *deferredCommitContext) {
}

func (t *txTail) handleUnorderedCommit(*deferredCommitContext) {
}

func (t *txTail) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return dcr
}

// errTxTailMissingRound is returned by checkDup when requested for a round number below the low watermark
type errTxTailMissingRound struct {
	round basics.Round
}

// Error satisfies builtin interface `error`
func (t errTxTailMissingRound) Error() string {
	return fmt.Sprintf("txTail: tried to check for dup in missing round %d", t.round)
}

// checkDup test to see if the given transaction id/lease already exists. It returns nil if neither exists, or
// TransactionInLedgerError / LeaseInLedgerError respectively.
func (t *txTail) checkDup(proto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl ledgercore.Txlease) error {
	if lastValid < t.lowWaterMark {
		return &errTxTailMissingRound{round: lastValid}
	}

	if proto.SupportTransactionLeases && (txl.Lease != [32]byte{}) {
		firstChecked := firstValid
		lastChecked := lastValid
		if proto.FixTransactionLeases {
			firstChecked = current.SubSaturate(basics.Round(proto.MaxTxnLife))
			lastChecked = current
		}

		for rnd := firstChecked; rnd <= lastChecked; rnd++ {
			expires, ok := t.recent[rnd].txleases[txl]
			if ok && current <= expires {
				return ledgercore.MakeLeaseInLedgerError(txid, txl)
			}
		}
	}

	if _, confirmed := t.lastValid[lastValid][txid]; confirmed {
		return &ledgercore.TransactionInLedgerError{Txid: txid}
	}
	return nil
}

func (t *txTail) putLV(lastValid basics.Round, id transactions.Txid) {
	if _, ok := t.lastValid[lastValid]; !ok {
		t.lastValid[lastValid] = make(map[transactions.Txid]struct{})
	}
	t.lastValid[lastValid][id] = struct{}{}
}

func (t *txTail) recentTailHash(offset uint64, retainSize uint64) (crypto.Digest, error) {
	// prepare a buffer to hash.
	buffer := make([]byte, (retainSize)*crypto.DigestSize)
	bufIdx := 0
	t.tailMu.RLock()
	lastOffset := offset + retainSize // size of interval [offset, lastOffset) is retainSize
	if lastOffset > uint64(len(t.roundTailHashes)) {
		lastOffset = uint64(len(t.roundTailHashes))
	}
	for i := offset; i < lastOffset; i++ {
		copy(buffer[bufIdx:], t.roundTailHashes[i][:])
		bufIdx += crypto.DigestSize
	}
	t.tailMu.RUnlock()
	return crypto.Hash(buffer), nil
}

func (t *txTail) blockHeader(rnd basics.Round) (bookkeeping.BlockHeader, bool) {
	t.tailMu.RLock()
	defer t.tailMu.RUnlock()
	hdr, ok := t.blockHeaderData[rnd]
	return hdr, ok
}
