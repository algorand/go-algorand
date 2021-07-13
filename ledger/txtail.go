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
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

const initialLastValidArrayLen = 256

type roundTxMembers struct {
	txleases map[ledgercore.Txlease]basics.Round // map of transaction lease to when it expires
	proto    config.ConsensusParams
}

type txTail struct {
	recent map[basics.Round]roundTxMembers

	lastValid map[basics.Round]map[transactions.Txid]struct{} // map tx.LastValid -> tx confirmed set

	// duplicate detection queries with LastValid before
	// lowWaterMark are not guaranteed to succeed
	lowWaterMark basics.Round // the last round known to be committed to disk
}

func (t *txTail) loadFromDisk(l ledgerForTracker) error {
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

	t.recent = make(map[basics.Round]roundTxMembers)

	// the roundsLastValids is a temporary map used during the exection of
	// loadFromDisk, allowing us to construct the lastValid maps in their
	// optimal size. This would ensure that upon startup, we don't preallocate
	// more memory than we truely need.
	roundsLastValids := make(map[basics.Round][]transactions.Txid)

	for ; old <= latest; old++ {
		blk, err := l.Block(old)
		if err != nil {
			return err
		}

		payset, err := blk.DecodePaysetFlat()
		if err != nil {
			return err
		}

		consensusParams := config.Consensus[blk.CurrentProtocol]
		t.recent[old] = roundTxMembers{
			txleases: make(map[ledgercore.Txlease]basics.Round, len(payset)),
			proto:    consensusParams,
		}

		for _, txad := range payset {
			tx := txad.SignedTxn
			if consensusParams.SupportTransactionLeases && (tx.Txn.Lease != [32]byte{}) {
				t.recent[old].txleases[ledgercore.Txlease{Sender: tx.Txn.Sender, Lease: tx.Txn.Lease}] = tx.Txn.LastValid
			}
			if tx.Txn.LastValid > t.lowWaterMark {
				list := roundsLastValids[tx.Txn.LastValid]
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
				list = append(list, tx.ID())
				roundsLastValids[tx.Txn.LastValid] = list
			}
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

	t.recent[rnd] = roundTxMembers{
		txleases: delta.Txleases,
		proto:    config.Consensus[blk.CurrentProtocol],
	}

	for txid, lv := range delta.Txids {
		t.putLV(lv, txid)
	}
}

func (t *txTail) committedUpTo(rnd basics.Round) basics.Round {
	maxlife := basics.Round(t.recent[rnd].proto.MaxTxnLife)
	for r := range t.recent {
		if r+maxlife < rnd {
			delete(t.recent, r)
		}
	}
	for ; t.lowWaterMark < rnd; t.lowWaterMark++ {
		delete(t.lastValid, t.lowWaterMark)
	}

	return (rnd + 1).SubSaturate(maxlife)
}

// txtailMissingRound is returned by checkDup when requested for a round number below the low watermark
type txtailMissingRound struct {
	round basics.Round
}

// Error satisfies builtin interface `error`
func (t txtailMissingRound) Error() string {
	return fmt.Sprintf("txTail: tried to check for dup in missing round %d", t.round)
}

// checkDup test to see if the given transaction id/lease already exists. It returns nil if neither exists, or
// TransactionInLedgerError / LeaseInLedgerError respectively.
func (t *txTail) checkDup(proto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl ledgercore.Txlease) error {
	if lastValid < t.lowWaterMark {
		return &txtailMissingRound{round: lastValid}
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
