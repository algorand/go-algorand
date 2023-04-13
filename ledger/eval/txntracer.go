// Copyright (C) 2019-2023 Algorand, Inc.
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

package eval

import (
	"bytes"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

var txnGroupDeltaTracer *TxnGroupDeltaTracer

// TODO do we want something like this?
type txnGroupDeltas struct {
	// Ids contains all the associated IDs for these changes (group and txn IDs)
	Ids []crypto.Digest
	ledgercore.StateDelta
}

// TxnGroupDeltaTracer collects groups of StateDelta objects covering groups of txns
type TxnGroupDeltaTracer struct {
	// lookback is the number of rounds stored at any given time
	Lookback uint64
	// no-op methods we don't care about
	logic.NullEvalTracer
	// txnGroupDeltas stores the StateDelta objects for each round, indexed by all the IDs within the group
	txnGroupDeltas []map[crypto.Digest]*ledgercore.StateDelta
}

// makeTxnGroupDeltaTracer creates a TxnGroupDeltaTracer
func makeTxnGroupDeltaTracer(lookback uint64) *TxnGroupDeltaTracer {
	return &TxnGroupDeltaTracer{
		Lookback:       lookback,
		txnGroupDeltas: []map[crypto.Digest]*ledgercore.StateDelta{},
	}
}

// TxnGroupDeltaTracerForConfig retrieves the TxnGroupDeltaTracer or creates it if it does not already exist
func TxnGroupDeltaTracerForConfig(cfg config.Local) *TxnGroupDeltaTracer {
	if txnGroupDeltaTracer == nil {
		txnGroupDeltaTracer = makeTxnGroupDeltaTracer(cfg.MaxAcctLookback)
	}
	return txnGroupDeltaTracer
}

// AfterTxnGroup implements the EvalTracer interface for txn group boundaries
func (tracer TxnGroupDeltaTracer) AfterTxnGroup(ep *logic.EvalParams, deltas *ledgercore.StateDelta, evalError error) {
	var round basics.Round
	if ep.Ledger != nil {
		round = ep.Ledger.Round()
	} else if ep.GetCaller() != nil {
		round = ep.GetCaller().Ledger.Round()
	} else {
		return
	}
	// Remove old data if it exists
	// delete(tracer.txnGroupDeltas, round-basics.Round(tracer.Lookback))
	var txnDeltaMap = make(map[crypto.Digest]*ledgercore.StateDelta)
	for _, txn := range ep.TxnGroup {
		// Add Group ID
		if !txn.Txn.Group.IsZero() {
			txnDeltaMap[txn.Txn.Group] = deltas
		}
		// Add Txn ID
		txnDeltaMap[crypto.Digest(txn.ID())] = deltas
		for innerIndex, innerTxn := range txn.ApplyData.EvalDelta.InnerTxns {
			// TODO which one of these is correct?
			// Add Inner Txn IDs
			txnDeltaMap[crypto.Digest(innerTxn.Txn.InnerID(txn.ID(), innerIndex))] = deltas
			txnDeltaMap[crypto.Digest(innerTxn.ID())] = deltas
		}
	}
	tracer.txnGroupDeltas[round] = txnDeltaMap
}

// GetDeltasForRound supplies all StateDelta objects for txn groups in a given rnd
func (tracer *TxnGroupDeltaTracer) GetDeltasForRound(rnd basics.Round) ([]ledgercore.StateDelta, error) {
	rndEntries := tracer.txnGroupDeltas[rnd]
	// Dedupe entries in our map
	var deltas = map[*ledgercore.StateDelta]bool{}
	var entries []ledgercore.StateDelta
	for _, delta := range rndEntries {
		if _, present := deltas[delta]; !present {
			deltas[delta] = true
			entries = append(entries, *delta)
		}
	}
	return entries, nil
}

// GetDeltaForID retruns the StateDelta associated with the group of transaction executed for the supplied ID (txn or group)
func (tracer *TxnGroupDeltaTracer) GetDeltaForID(id crypto.Digest) (ledgercore.StateDelta, error) {
	for _, deltasForRound := range tracer.txnGroupDeltas {
		for idKey, deltaVal := range deltasForRound {
			if bytes.Equal(idKey[:], id[:]) {
				return *deltaVal, nil
			}
		}
	}
	return ledgercore.StateDelta{}, fmt.Errorf("unable to find delta for id: %s", id)
}
