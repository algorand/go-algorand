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
	txids    map[transactions.Txid]struct{}
	txleases map[txlease]basics.Round // map of transaction lease to when it expires
	proto    config.ConsensusParams
}

type txTail struct {
	recent map[basics.Round]roundTxMembers
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
			txids:    make(map[transactions.Txid]struct{}),
			txleases: make(map[txlease]basics.Round),
			proto:    config.Consensus[blk.CurrentProtocol],
		}
		for _, txad := range payset {
			tx := txad.SignedTxn
			t.recent[old].txids[tx.ID()] = struct{}{}
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
}

func (t *txTail) committedUpTo(rnd basics.Round) basics.Round {
	maxlife := basics.Round(t.recent[rnd].proto.MaxTxnLife)
	for r := range t.recent {
		if r+maxlife < rnd {
			delete(t.recent, r)
		}
	}

	return (rnd + 1).SubSaturate(maxlife)
}

func (t *txTail) isDup(proto config.ConsensusParams, current basics.Round, firstValid basics.Round, lastValid basics.Round, txid transactions.Txid, txl txlease) (bool, error) {
	for rnd := firstValid; rnd <= lastValid; rnd++ {
		rndtxs := t.recent[rnd].txids
		if rndtxs == nil {
			return true, fmt.Errorf("txTail: tried to check for dup in missing round %d", rnd)
		}

		_, present := rndtxs[txid]
		if present {
			return true, nil
		}

		if proto.SupportTransactionLeases && (txl.lease != [32]byte{}) {
			expires, ok := t.recent[rnd].txleases[txl]
			if ok && current <= expires {
				return true, nil
			}
		}

	}

	return false, nil
}

func (t *txTail) getRoundTxIds(rnd basics.Round) (txMap map[transactions.Txid]bool) {
	rndtxs := t.recent[rnd].txids
	txMap = make(map[transactions.Txid]bool, len(rndtxs))
	for txid := range rndtxs {
		txMap[txid] = true
	}
	return
}
