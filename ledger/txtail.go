// Copyright (C) 2019-2025 Algorand, Inc.
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
	"fmt"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
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
	// roundTailHashes is planned for catchpoints in order to include it into catchpoint file,
	// and currently disabled by enableTxTailHashes switch.
	roundTailHashes []crypto.Digest

	// blockHeaderData contains the recent (MaxTxnLife + DeeperBlockHeaderHistory + len(deltas)) block header data.
	// The oldest entry is lowestBlockHeaderRound = database round - (MaxTxnLife + DeeperBlockHeaderHistory) + 1
	blockHeaderData map[basics.Round]bookkeeping.BlockHeader
	// lowestBlockHeaderRound is the lowest round in blockHeaderData, used as a starting point for old entries removal
	lowestBlockHeaderRound basics.Round

	// tailMu is the synchronization mutex for accessing internal data including
	// lastValid, recent, lowWaterMark, roundTailHashes, roundTailSerializedDeltas and blockHeaderData.
	tailMu deadlock.RWMutex

	// lastValid allows looking up all of the transactions that expire in a given round.
	// The map for an expiration round gives the round the transaction was originally confirmed, so it can be found for the /pending endpoint.
	lastValid map[basics.Round]map[transactions.Txid]uint16 // map tx.LastValid -> tx confirmed map: txid -> (last valid - confirmed) delta

	// duplicate detection queries with LastValid before
	// lowWaterMark are not guaranteed to succeed
	lowWaterMark basics.Round // the last round known to be committed to disk

	// log copied from ledger
	log logging.Logger
}

func (t *txTail) loadFromDisk(l ledgerForTracker, dbRound basics.Round) error {
	t.tailMu.Lock()
	defer t.tailMu.Unlock()

	t.log = l.trackerLog()

	var roundData []*trackerdb.TxTailRound
	var roundTailHashes []crypto.Digest
	var baseRound basics.Round
	if dbRound > 0 {
		err := l.trackerDB().Snapshot(func(ctx context.Context, tx trackerdb.SnapshotScope) (err error) {
			ar, err := tx.MakeAccountsReader()
			if err != nil {
				return err
			}

			roundData, roundTailHashes, baseRound, err = ar.LoadTxTail(ctx, dbRound)
			return
		})
		if err != nil {
			return err
		}
	}

	t.lowWaterMark = l.Latest()
	t.lastValid = make(map[basics.Round]map[transactions.Txid]uint16)
	t.recent = make(map[basics.Round]roundLeases)

	// the lastValid is a temporary map used during the execution of
	// loadFromDisk, allowing us to construct the lastValid maps in their
	// optimal size. This would ensure that upon startup, we don't preallocate
	// more memory than we truly need.
	type lastValidEntry struct {
		rnd  basics.Round
		txid transactions.Txid
	}
	lastValid := make(map[basics.Round][]lastValidEntry)

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
			for _, rlease := range txTailRound.Leases {
				if rlease.Lease != [32]byte{} {
					key := ledgercore.Txlease{Sender: rlease.Sender, Lease: rlease.Lease}
					t.recent[old].txleases[key] = txTailRound.LastValid[rlease.TxnIdx]
				}
			}
		}

		for i := 0; i < len(txTailRound.LastValid); i++ {
			if txTailRound.LastValid[i] > t.lowWaterMark {
				list := lastValid[txTailRound.LastValid[i]]
				// if the list reached capacity, resize.
				if len(list) == cap(list) {
					var newList []lastValidEntry
					if cap(list) == 0 {
						newList = make([]lastValidEntry, 0, initialLastValidArrayLen)
					} else {
						newList = make([]lastValidEntry, len(list), len(list)*2)
					}
					copy(newList[:], list[:])
					list = newList
				}
				list = append(list, lastValidEntry{txTailRound.Hdr.Round, txTailRound.TxnIDs[i]})
				lastValid[txTailRound.LastValid[i]] = list
			}
		}

		blockHeaderData[old] = txTailRound.Hdr
		roundData = roundData[1:]
	}

	// add all the entries in roundsLastValids to their corresponding map entry in t.lastValid
	for lastValid, list := range lastValid {
		lastValidMap := make(map[transactions.Txid]uint16, len(list))
		for _, entry := range list {
			if lastValid < entry.rnd {
				return fmt.Errorf("txTail: invalid lastValid %d / rnd %d for txid %s", lastValid, entry.rnd, entry.txid)
			}
			deltaR := uint16(lastValid - entry.rnd)
			lastValidMap[entry.txid] = deltaR
		}
		t.lastValid[lastValid] = lastValidMap
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

	t.tailMu.Lock()
	defer t.tailMu.Unlock()

	if _, has := t.recent[rnd]; has {
		// Repeat, ignore
		return
	}

	var tail trackerdb.TxTailRound
	tail.TxnIDs = make([]transactions.Txid, len(delta.Txids))
	tail.LastValid = make([]basics.Round, len(delta.Txids))
	tail.Hdr = blk.BlockHeader

	for txid, txnInc := range delta.Txids {
		if _, ok := t.lastValid[txnInc.LastValid]; !ok {
			t.lastValid[txnInc.LastValid] = make(map[transactions.Txid]uint16)
		}
		deltaR := uint16(txnInc.LastValid - blk.BlockHeader.Round)
		t.lastValid[txnInc.LastValid][txid] = deltaR

		tail.TxnIDs[txnInc.Intra] = txid
		tail.LastValid[txnInc.Intra] = txnInc.LastValid
		if blk.Payset[txnInc.Intra].Txn.Lease != [32]byte{} {
			tail.Leases = append(tail.Leases, trackerdb.TxTailRoundLease{
				Sender: blk.Payset[txnInc.Intra].Txn.Sender,
				Lease:  blk.Payset[txnInc.Intra].Txn.Lease,
				TxnIdx: txnInc.Intra,
			})
		}
	}
	encodedTail, tailHash := tail.Encode()

	t.recent[rnd] = roundLeases{
		txleases: delta.Txleases,
		proto:    config.Consensus[blk.CurrentProtocol],
	}
	t.roundTailSerializedDeltas = append(t.roundTailSerializedDeltas, encodedTail)
	if enableTxTailHashes {
		t.roundTailHashes = append(t.roundTailHashes, tailHash)
	}
	t.blockHeaderData[rnd] = blk.BlockHeader
}

func (t *txTail) committedUpTo(rnd basics.Round) (retRound, lookback basics.Round) {
	t.tailMu.Lock()
	defer t.tailMu.Unlock()

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
	dcc.txTailDeltas = make([][]byte, 0, dcc.offset)
	t.tailMu.RLock()
	for i := uint64(0); i < dcc.offset; i++ {
		dcc.txTailDeltas = append(dcc.txTailDeltas, t.roundTailSerializedDeltas[i])
	}
	lowest := t.lowestBlockHeaderRound
	proto, ok := config.Consensus[t.blockHeaderData[dcc.newBase()].CurrentProtocol]
	t.tailMu.RUnlock()
	if !ok {
		return fmt.Errorf("round %d not found in blockHeaderData: lowest=%d, base=%d", dcc.newBase(), lowest, dcc.oldBase)
	}
	// get the MaxTxnLife from the consensus params of the latest round in this commit range
	// preserve data for MaxTxnLife + DeeperBlockHeaderHistory
	dcc.txTailRetainSize = proto.MaxTxnLife + proto.DeeperBlockHeaderHistory

	if !dcc.catchpointFirstStage {
		return nil
	}

	if enableTxTailHashes {
		// update the dcc with the hash we'll need.
		dcc.txTailHash, err = t.recentTailHash(dcc.offset, dcc.txTailRetainSize)
	}
	return
}

func (t *txTail) commitRound(ctx context.Context, tx trackerdb.TransactionScope, dcc *deferredCommitContext) error {
	aw, err := tx.MakeAccountsWriter()
	if err != nil {
		return err
	}

	// determine the round to remove data
	// the formula is similar to the committedUpTo: rnd + 1 - retain size
	forgetBeforeRound := (dcc.newBase() + 1).SubSaturate(basics.Round(dcc.txTailRetainSize))
	baseRound := dcc.oldBase + 1
	if err := aw.TxtailNewRound(ctx, baseRound, dcc.txTailDeltas, forgetBeforeRound); err != nil {
		return fmt.Errorf("txTail: unable to persist new round %d : %w", baseRound, err)
	}
	return nil
}

func (t *txTail) postCommit(ctx context.Context, dcc *deferredCommitContext) {
	t.tailMu.Lock()
	defer t.tailMu.Unlock()

	t.roundTailSerializedDeltas = t.roundTailSerializedDeltas[dcc.offset:]

	// get the MaxTxnLife from the consensus params of the latest round in this commit range
	// preserve data for MaxTxnLife + DeeperBlockHeaderHistory rounds
	newLowestRound := (dcc.newBase() + 1).SubSaturate(basics.Round(dcc.txTailRetainSize))
	for t.lowestBlockHeaderRound < newLowestRound {
		delete(t.blockHeaderData, t.lowestBlockHeaderRound)
		t.lowestBlockHeaderRound++
	}
	if enableTxTailHashes {
		newDeltaLength := len(t.roundTailSerializedDeltas)
		firstTailIdx := len(t.roundTailHashes) - newDeltaLength - int(dcc.txTailRetainSize)
		if firstTailIdx > 0 {
			t.roundTailHashes = t.roundTailHashes[firstTailIdx:]
		}
	}
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
	// txTail does not use l.trackerMu, instead uses t.tailMu to make it thread-safe
	// t.tailMu is sufficient because the state of txTail does not depend on any outside data field

	t.tailMu.RLock()
	defer t.tailMu.RUnlock()

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
				return ledgercore.MakeLeaseInLedgerError(txid, txl, false)
			}
		}
	}

	if _, confirmed := t.lastValid[lastValid][txid]; confirmed {
		return &ledgercore.TransactionInLedgerError{Txid: txid, InBlockEvaluator: false}
	}
	return nil
}

// checkConfirmed test to see if the given transaction id already exists.
func (t *txTail) checkConfirmed(txid transactions.Txid) (basics.Round, bool) {
	t.tailMu.RLock()
	defer t.tailMu.RUnlock()

	for lastValidRound, lastValid := range t.lastValid {
		if deltaR, confirmed := lastValid[txid]; confirmed {
			return lastValidRound - basics.Round(deltaR), true
		}
	}
	return 0, false
}

func (t *txTail) recentTailHash(offset uint64, retainSize uint64) (crypto.Digest, error) {
	// prepare a buffer to hash.
	buffer := make([]byte, (retainSize)*crypto.DigestSize)
	bufIdx := 0
	t.tailMu.RLock()
	// size of interval [offset, lastOffset) is retainSize
	lastOffset := min(offset+retainSize, uint64(len(t.roundTailHashes)))
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
