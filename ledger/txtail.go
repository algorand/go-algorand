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
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
)

type roundTxMembers struct {
	txids    map[transactions.Txid]basics.Round
	txleases map[txlease]basics.Round // map of transaction lease to when it expires
	proto    config.ConsensusParams
}

type txTail struct {
	recent    map[basics.Round]roundTxMembers
	lastValid map[basics.Round]map[transactions.Txid]struct{} // map tx.LastValid -> tx confirmed set
}

func (t *txTail) loadFromDisk(l ledgerForTracker) error {
	latest := l.Latest()
	hdr, err := l.BlockHdr(latest)
	if err != nil {
		return fmt.Errorf("txTail: could not get latest block header: %v", err)
	}
	proto := config.Consensus[hdr.CurrentProtocol]

	t.lastValid = make(map[basics.Round]map[transactions.Txid]struct{})
	for i := uint64(0); i <= proto.MaxTxnLife+1; i++ {
		lv := latest + basics.Round(i)
		t.lastValid[lv] = make(map[transactions.Txid]struct{})
	}

	// If the latest round is R, then any transactions from blocks strictly older than
	// R + 1 - proto.MaxTxnLife
	// could not be valid in the next round (R+1), and so are irrelevant.
	// Thus we load the txids from blocks R+1-maxTxnLife to R, inclusive
	old := (latest + 1).SubSaturate(basics.Round(proto.MaxTxnLife))

	t.recent = make(map[basics.Round]roundTxMembers)
	for ; old <= latest; old++ {
		blk, err := l.Block(old)
		if err != nil {
			return err
		}

		payset, err := blk.DecodePaysetFlat()
		if err != nil {
			return err
		}

		t.recent[old] = roundTxMembers{
			txids:    make(map[transactions.Txid]basics.Round),
			txleases: make(map[txlease]basics.Round),
			proto:    config.Consensus[blk.CurrentProtocol],
		}
		for _, txad := range payset {
			tx := txad.SignedTxn
			t.recent[old].txids[tx.ID()] = tx.Txn.LastValid
			if _, ok := t.lastValid[tx.Txn.LastValid]; ok {
				t.lastValid[tx.Txn.LastValid][tx.ID()] = struct{}{}
			}
			t.recent[old].txleases[txlease{sender: tx.Txn.Sender, lease: tx.Txn.Lease}] = tx.Txn.LastValid
		}
	}

	return nil
}

func (t *txTail) close() {
}

func (t *txTail) newBlock(blk bookkeeping.Block, delta StateDelta) {
	rnd := blk.Round()

	if t.recent[rnd].txids != nil {
		// Repeat, ignore
		return
	}

	t.recent[rnd] = roundTxMembers{
		txids:    delta.Txids,
		txleases: delta.txleases,
		proto:    config.Consensus[blk.CurrentProtocol],
	}

	proto := config.Consensus[blk.CurrentProtocol]
	if _, ok := t.lastValid[rnd+basics.Round(proto.MaxTxnLife)+1]; !ok {
		t.lastValid[rnd+basics.Round(proto.MaxTxnLife)+1] = make(map[transactions.Txid]struct{})
	}
	for txid, lv := range delta.Txids {
		t.lastValid[lv][txid] = struct{}{}
	}
}

func (t *txTail) committedUpTo(rnd basics.Round) basics.Round {
	maxlife := basics.Round(t.recent[rnd].proto.MaxTxnLife)
	for r := range t.recent {
		if r+maxlife < rnd {
			delete(t.recent, r)
		}
	}
	for lv := range t.lastValid {
		if lv < rnd {
			delete(t.lastValid, lv)
		}
	}

	return (rnd + 1).SubSaturate(maxlife)
}

func (t *txTail) isDup(proto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl txlease) (bool, error) {
	if proto.SupportTransactionLeases && (txl.lease != [32]byte{}) {
		for rnd := firstValid; rnd <= lastValid; rnd++ {
			expires, ok := t.recent[rnd].txleases[txl]
			if ok && current <= expires {
				return true, nil
			}
		}
	}

	set, ok := t.lastValid[lastValid]
	if !ok {
		return true, fmt.Errorf("txTail: tried to check for dup in missing round %d", lastValid)
	}
	_, confirmed := set[txid]
	return confirmed, nil
}

func (t *txTail) getRoundTxIds(rnd basics.Round) (txMap map[transactions.Txid]bool) {
	rndtxs := t.recent[rnd].txids
	txMap = make(map[transactions.Txid]bool, len(rndtxs))
	for txid := range rndtxs {
		txMap[txid] = true
	}
	return
}
