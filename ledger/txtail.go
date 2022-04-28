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

	// roundTailHashes contains the recent (MaxTxnLife + 1 + len(deltas)) hashes. The first entry matches that current tracker database round - MaxTxnLife
	// the second to tracker database round - (MaxTxnLife - 1), and so forth. See blockHeaderData description below for the indexing details.
	// not being used.
	roundTailHashes []crypto.Digest

	// blockHeaderData contains the recent (MaxTxnLife + 1 + len(deltas)) block header data. The first entry matches that current tracker database round - MaxTxnLife (tail size is MaxTxnLife + 1)
	// the second to tracker database round - (MaxTxnLife - 1), and so forth, and the last element is for the latest round. Deltas are in-memory not-committed-yet data.
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
	// Operations:
	// 1. Deltas offset to blockHeaderData offset:
	//   - Get the history start: len(blockHeaderData) - len(roundTailSerializedDeltas)
	//   - Add the offset. Zero offset points to the dbRound like in account updates tracker
	// 2. Round number to blockHeaderData offset:
	//   - Get the lastest: dbRound + len(roundTailSerializedDeltas)
	//   - Get the relative offset from the end of the slice: latest - rnd
	//   - The required position is len(blockHeaderData) - relOffset - 1
	//   - Error if rnd > latest or the pos < 0
	blockHeaderData []txTailBlockHeaderData

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
			roundData, roundTailHashes, baseRound, err = loadTxTail(context.Background(), tx, dbRound)
			return err
		})
		if err != nil {
			return err
		}
	}

	t.lowWaterMark = dbRound
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
	blockHeaderData := make([]txTailBlockHeaderData, 1, len(roundData)+1)

	for old := baseRound; old <= dbRound && dbRound > baseRound; old++ {
		txTailRound := roundData[0]
		consensusParams := config.Consensus[txTailRound.ConsensusVersion]

		t.recent[old] = roundLeases{
			txleases: make(map[ledgercore.Txlease]basics.Round, len(txTailRound.TxnIDs)),
			proto:    consensusParams,
		}

		for i := 0; i < len(txTailRound.Leases); i++ {
			if consensusParams.SupportTransactionLeases && (txTailRound.Leases[i].Lease != [32]byte{}) {
				t.recent[old].txleases[ledgercore.Txlease{Sender: txTailRound.Leases[i].Sender, Lease: txTailRound.Leases[i].Lease}] = txTailRound.LastValid[txTailRound.Leases[i].TxnIdx]
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

		blockHeaderData = append(blockHeaderData, txTailBlockHeaderData{
			TimeStamp:        txTailRound.TimeStamp,
			BlockSeed:        txTailRound.BlockSeed,
			ConsensusVersion: txTailRound.ConsensusVersion,
		})
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

	t.tailMu.Lock()
	if enableTxTailHashes {
		t.roundTailHashes = roundTailHashes
	}
	t.blockHeaderData = blockHeaderData
	t.roundTailSerializedDeltas = make([][]byte, 0)
	t.tailMu.Unlock()

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
	tail.TimeStamp = blk.TimeStamp
	tail.BlockSeed = blk.BlockHeader.Seed[:]
	tail.ConsensusVersion = blk.BlockHeader.CurrentProtocol

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

	t.recent[rnd] = roundLeases{
		txleases: delta.Txleases,
		proto:    config.Consensus[blk.CurrentProtocol],
	}
	t.tailMu.Lock()
	t.roundTailSerializedDeltas = append(t.roundTailSerializedDeltas, encodedTail)
	if enableTxTailHashes {
		t.roundTailHashes = append(t.roundTailHashes, tailHash)
	}
	t.blockHeaderData = append(t.blockHeaderData, txTailBlockHeaderData{
		TimeStamp:        blk.TimeStamp,
		BlockSeed:        blk.BlockHeader.Seed[:],
		ConsensusVersion: blk.BlockHeader.CurrentProtocol,
	})
	t.tailMu.Unlock()
}

func (t *txTail) committedUpTo(rnd basics.Round) (retRound, lookback basics.Round) {
	maxlife := basics.Round(t.recent[rnd].proto.MaxTxnLife)
	for r := range t.recent {
		if r+maxlife < rnd {
			delete(t.recent, r)
		}
	}
	for ; t.lowWaterMark < rnd; t.lowWaterMark++ {
		delete(t.lastValid, t.lowWaterMark)
	}

	// TODO: enable
	// preserve MaxTxnLife + 1 blocks in order to have
	// an access to a block out of the MaxTxnLife
	// return (rnd + 1).SubSaturate(maxlife + 1), basics.Round(0)
	return (rnd + 1).SubSaturate(maxlife), basics.Round(0)
}

// blockHeaderDataDeltasOffset converts deltas offset into blockHeaderData offset
func blockHeaderDataDeltasOffset(offset uint64, dataLen int, deltasLen int) int {
	if offset >= uint64(MaxInt) {
		panic(fmt.Sprintf("offset overflow %d", offset))
	}
	historyLength := dataLen - deltasLen
	historyLastIdx := historyLength - 1 // points to dbRound
	return historyLastIdx + int(offset)
}

// blockHeaderDataRoundOffset converts round number into the blockHeaderData offset
func blockHeaderDataRoundOffset(rnd basics.Round, dbRound basics.Round, dataLen int, deltasLen int) (int, error) {
	latest := dbRound + basics.Round(deltasLen)
	if rnd > latest {
		return 0, fmt.Errorf("txTail: round %d too new: cached %d, deltas %d", rnd, dbRound, deltasLen)
	}
	relOffset := latest - rnd
	offset := dataLen - int(relOffset) - 1
	if offset < 0 {
		return 0, fmt.Errorf("txTail: round %d too old: latest %d, history %d", rnd, latest, dataLen)
	}
	return offset, nil
}

func (t *txTail) prepareCommit(dcc *deferredCommitContext) (err error) {
	if !dcc.isCatchpointRound {
		return nil
	}

	t.tailMu.RLock()
	historyOffset := blockHeaderDataDeltasOffset(dcc.offset, len(t.blockHeaderData), len(t.roundTailSerializedDeltas))
	maxTxnLife := config.Consensus[t.blockHeaderData[historyOffset].ConsensusVersion].MaxTxnLife
	t.tailMu.RUnlock()

	if enableTxTailHashes {
		// update the dcc with the hash we'll need.
		dcc.txTailHash, err = t.recentTailHash(dcc.offset, maxTxnLife)
	}
	return
}

func (t *txTail) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) error {
	baseRound := dcc.oldBase + 1
	roundsData := make([][]byte, 0, dcc.offset)

	t.tailMu.RLock()
	for i := uint64(0); i < dcc.offset; i++ {
		roundsData = append(roundsData, t.roundTailSerializedDeltas[i])
	}
	// get the MaxTxnLife from the consensus params of the latest round in this commit range
	// preserve data for MaxTxnLife + 1
	historyOffset := blockHeaderDataDeltasOffset(dcc.offset, len(t.blockHeaderData), len(t.roundTailSerializedDeltas))
	retainSize := config.Consensus[t.blockHeaderData[historyOffset].ConsensusVersion].MaxTxnLife + 1
	t.tailMu.RUnlock()

	// determine the round to remove data
	// This is the similar formula to the committedUpTo: rnd + 1 - retain size
	forgetBeforeRound := (baseRound + basics.Round(dcc.offset)).SubSaturate(basics.Round(retainSize))
	if err := txtailNewRound(ctx, tx, baseRound, roundsData, forgetBeforeRound); err != nil {
		return fmt.Errorf("txTail: unable to persist new round %d : %w", baseRound, err)
	}
	return nil
}

func (t *txTail) postCommit(ctx context.Context, dcc *deferredCommitContext) {
	t.tailMu.Lock()
	historyOffset := blockHeaderDataDeltasOffset(dcc.offset, len(t.blockHeaderData), len(t.roundTailSerializedDeltas))

	t.roundTailSerializedDeltas = t.roundTailSerializedDeltas[dcc.offset:]
	// get the MaxTxnLife from the consensus params of the latest round in this commit range
	retainSize := config.Consensus[t.blockHeaderData[historyOffset].ConsensusVersion].MaxTxnLife + 1
	newDeltaLength := len(t.roundTailSerializedDeltas)
	// keep the latest 1001 entries on the hash and in cached bloch header data, before roundTailSerializedDeltas
	firstTailIdx := len(t.blockHeaderData) - newDeltaLength - int(retainSize)
	if firstTailIdx > 0 {
		t.blockHeaderData = t.blockHeaderData[firstTailIdx:]
		if enableTxTailHashes {
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

func (t *txTail) recentTailHash(offset uint64, maxTxnLife uint64) (crypto.Digest, error) {
	// prepare a buffer to hash.
	buffer := make([]byte, (maxTxnLife+1)*crypto.DigestSize)
	bufIdx := 0
	t.tailMu.RLock()
	lastOffset := offset + maxTxnLife
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

func (t *txTail) blockTimestamp(rnd basics.Round, dbRound basics.Round) (int64, error) {
	t.tailMu.Lock()
	defer t.tailMu.Lock()
	offset, err := blockHeaderDataRoundOffset(rnd, dbRound, len(t.blockHeaderData), len(t.roundTailSerializedDeltas))
	if err != nil {
		return 0, err
	}
	return t.blockHeaderData[offset].TimeStamp, nil
}

func (t *txTail) blockSeed(rnd basics.Round, dbRound basics.Round) ([]byte, error) {
	t.tailMu.Lock()
	defer t.tailMu.Lock()
	offset, err := blockHeaderDataRoundOffset(rnd, dbRound, len(t.blockHeaderData), len(t.roundTailSerializedDeltas))
	if err != nil {
		return nil, err
	}
	return t.blockHeaderData[offset].BlockSeed, nil
}
