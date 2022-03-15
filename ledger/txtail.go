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
	"github.com/algorand/go-algorand/protocol"
)

// txTailRoundLease is used as part of txTailRound for storing
// a single lease.
type txTailRoundLease struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sender basics.Address `codec:"s"`
	Lease  [32]byte       `codec:"l,allocbound=-"`
	TxnIdx uint64         `code:"i"` //!-- index of the entry in TxnIDs/LastValid
}

// TxTailRound contains the information about a single round of transactions.
// The TxnIDs and LastValid would both be of the same length, and are stored
// in that way for efficient message=pack encoding. The Leases would point to the
// respective transaction index. Note that this isn’t optimized for storing
// leases, as leases are extremely rare.
type txTailRound struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	TxnIDs    []transactions.Txid `codec:"t,allocbound=-"`
	LastValid []basics.Round      `codec:"v,allocbound=-"`
	Leases    []txTailRoundLease  `codec:"l,allocbound=-"`
	TimeStamp int64               `codec:"a"` //!-- timestamp from block header
}

// encode the transaction tail data into a serialized form, and return the serialized data
// as well as the hash of the data.
func (t *txTailRound) encode() ([]byte, crypto.Digest) {
	tailData := protocol.Encode(t)
	hash := crypto.Hash(tailData)
	return tailData, hash
}

const initialLastValidArrayLen = 256

type roundLeases struct {
	txleases map[ledgercore.Txlease]basics.Round // map of transaction lease to when it expires
	proto    config.ConsensusParams
}

type txTail struct {
	recent map[basics.Round]roundLeases

	// roundTailSerializedData contains the rounds that need to be flushed to disk.
	// It contain the serialized(encoded) form of the txTailRound. This field would remain
	// maintained in this data structure up until being cleared out by postCommit
	roundTailSerializedData [][]byte

	// roundTailHashes contains the recent 1001 hashes. The first entry matches that current tracker database round - 1001,
	// the second to tracker database round - 1000, and so forth. The roundTailHashes always has it's first array element
	// not being used.
	roundTailHashes []crypto.Digest

	// consensusVersions contains the recent 1001 consensus versions. The first entry matches that current tracker database round - 1001,
	// the second to tracker database round - 1000, and so forth.
	consensusVersions []protocol.ConsensusVersion

	// tailMu is the synchronization mutex for accessing roundTailHashes, roundTailSerializedData and consensusVersions.
	tailMu deadlock.RWMutex

	lastValid map[basics.Round]map[transactions.Txid]struct{} // map tx.LastValid -> tx confirmed set

	// duplicate detection queries with LastValid before
	// lowWaterMark are not guaranteed to succeed
	lowWaterMark basics.Round // the last round known to be committed to disk
}

// txTailRoundFromBlock is a temporary method until we can start loading the tail from the tracker database.
func (t *txTail) txTailRoundFromBlock(l ledgerForTracker, rnd basics.Round) (txTailRound, protocol.ConsensusVersion, error) {
	blk, err := l.Block(rnd)
	if err != nil {
		return txTailRound{}, "", err
	}

	payset, err := blk.DecodePaysetFlat()
	if err != nil {
		return txTailRound{}, "", err
	}

	var tail txTailRound
	tail.TxnIDs = make([]transactions.Txid, len(payset))
	tail.LastValid = make([]basics.Round, len(payset))
	tail.TimeStamp = blk.TimeStamp

	for txIdxtxid, txn := range payset {
		tail.TxnIDs[txIdxtxid] = txn.ID()
		tail.LastValid[txIdxtxid] = txn.Txn.LastValid
		if txn.Txn.Lease != [32]byte{} {
			tail.Leases = append(tail.Leases, txTailRoundLease{
				Sender: txn.Txn.Sender,
				Lease:  txn.Txn.Lease,
				TxnIdx: uint64(txIdxtxid),
			})
		}
	}

	return tail, blk.CurrentProtocol, nil

}

func (t *txTail) loadFromDisk(l ledgerForTracker, trackerRound basics.Round) error {
	latest := l.Latest()
	hdr, err := l.BlockHdr(latest)
	if err != nil {
		return fmt.Errorf("txTail: could not get latest block header: %v", err)
	}
	proto := config.Consensus[hdr.CurrentProtocol]

	// If the latest round is R, then any transactions from blocks strictly older than
	// R + 1 - proto.MaxTxnLife
	// could not be valid in the next round (R+1), and so are irrelevant.
	// Thus we load the txids from blocks R+1-maxTxnLife to R, inclusive
	old := (latest + 1).SubSaturate(basics.Round(proto.MaxTxnLife))

	t.lowWaterMark = latest
	t.lastValid = make(map[basics.Round]map[transactions.Txid]struct{})

	t.recent = make(map[basics.Round]roundLeases)

	// the roundsLastValids is a temporary map used during the execution of
	// loadFromDisk, allowing us to construct the lastValid maps in their
	// optimal size. This would ensure that upon startup, we don't preallocate
	// more memory than we truly need.
	roundsLastValids := make(map[basics.Round][]transactions.Txid)

	// allocate with size 0, just so that we can start from fresh.
	// the roundTailHashes and consensusVersions always has 1 extra element being unused, so preallocate that.
	roundTailHashes := make([]crypto.Digest, 1)
	consensusVersions := make([]protocol.ConsensusVersion, 1)
	roundTailSerializedData := make([][]byte, 0)

	for ; old <= latest; old++ {

		// the following section would need to be refactored later on.
		txTailRound, consensusVersion, err := t.txTailRoundFromBlock(l, old)
		if err != nil {
			return err
		}

		consensusParams := config.Consensus[consensusVersion]

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

		encodedTail, tailHash := txTailRound.encode()
		roundTailHashes = append(roundTailHashes, tailHash)
		consensusVersions = append(consensusVersions, consensusVersion)
		if old > trackerRound {
			roundTailSerializedData = append(roundTailSerializedData, encodedTail)
		}
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
	t.roundTailHashes = roundTailHashes
	t.consensusVersions = consensusVersions
	t.roundTailSerializedData = roundTailSerializedData
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
	t.roundTailSerializedData = append(t.roundTailSerializedData, encodedTail)
	t.roundTailHashes = append(t.roundTailHashes, tailHash)
	t.consensusVersions = append(t.consensusVersions, blk.CurrentProtocol)
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

	return (rnd + 1).SubSaturate(maxlife), basics.Round(0)
}

func (t *txTail) prepareCommit(dcc *deferredCommitContext) (err error) {
	if !dcc.isCatchpointRound {
		return nil
	}

	maxTxnLife := config.Consensus[t.consensusVersions[dcc.offset]].MaxTxnLife
	// update the dcc with the hash we'll need.
	dcc.txTailHash, err = t.recentTailHash(dcc.offset, maxTxnLife)
	return
}

func txtailNewRound(tx *sql.Tx, baseRound basics.Round, roundData [][]byte, forgetRound basics.Round) error {
	// todo - implement this.
	// step 1 :
	// insert all round data.
	// step 2:
	// delte all data before forgetRound
	return nil
}

func (t *txTail) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) error {
	baseRound := dcc.oldBase + 1
	roundsData := make([][]byte, 0, dcc.offset)

	t.tailMu.RLock()
	for i := uint64(0); i < dcc.offset; i++ {
		roundsData = append(roundsData, t.roundTailSerializedData[i])
	}
	// get the MaxTxnLife from the consensus params of the latest round in this commit range
	maxTxnLifeRound := basics.Round(config.Consensus[t.consensusVersions[dcc.offset]].MaxTxnLife) + 1
	t.tailMu.RUnlock()

	forgetRound := (baseRound + basics.Round(dcc.offset)).SubSaturate(maxTxnLifeRound)
	if err := txtailNewRound(tx, baseRound, roundsData, forgetRound); err != nil {
		return fmt.Errorf("txTail: unable to persist new round %d : %w", baseRound, err)
	}
	return nil
}

func (t *txTail) postCommit(ctx context.Context, dcc *deferredCommitContext) {
	t.tailMu.Lock()
	t.roundTailSerializedData = t.roundTailSerializedData[dcc.offset:]
	// get the MaxTxnLife from the consensus params of the latest round in this commit range
	maxTxnLife := config.Consensus[t.consensusVersions[dcc.offset]].MaxTxnLife
	// keep the latest 1001 entries on the hash, before roundTailSerializedData
	firstTailIdx := len(t.roundTailHashes) - len(t.roundTailSerializedData) - int(maxTxnLife)
	if firstTailIdx > 0 {
		t.roundTailHashes = t.roundTailHashes[firstTailIdx:]
		t.consensusVersions = t.consensusVersions[firstTailIdx:]
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

// errTxtailMissingRound is returned by checkDup when requested for a round number below the low watermark
type errTxtailMissingRound struct {
	round basics.Round
}

// Error satisfies builtin interface `error`
func (t errTxtailMissingRound) Error() string {
	return fmt.Sprintf("txTail: tried to check for dup in missing round %d", t.round)
}

// checkDup test to see if the given transaction id/lease already exists. It returns nil if neither exists, or
// TransactionInLedgerError / LeaseInLedgerError respectively.
func (t *txTail) checkDup(proto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl ledgercore.Txlease) error {
	if lastValid < t.lowWaterMark {
		return &errTxtailMissingRound{round: lastValid}
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
	// preapare a buffer to hash.
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
