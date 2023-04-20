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
	"github.com/algorand/go-algorand/data/bookkeeping"

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
	txnGroupDeltas map[basics.Round]map[crypto.Digest]*ledgercore.StateDelta
	// latestRound is the most recent round seen via the BeforeBlock hdr
	latestRound basics.Round
}

// makeTxnGroupDeltaTracer creates a TxnGroupDeltaTracer
func makeTxnGroupDeltaTracer(lookback uint64) *TxnGroupDeltaTracer {
	return &TxnGroupDeltaTracer{
		Lookback:       lookback,
		txnGroupDeltas: make(map[basics.Round]map[crypto.Digest]*ledgercore.StateDelta),
	}
}

// TxnGroupDeltaTracerForConfig retrieves the TxnGroupDeltaTracer or creates it if it does not already exist
func TxnGroupDeltaTracerForConfig(cfg config.Local) *TxnGroupDeltaTracer {
	if txnGroupDeltaTracer == nil {
		txnGroupDeltaTracer = makeTxnGroupDeltaTracer(cfg.MaxAcctLookback)
	}
	return txnGroupDeltaTracer
}

// BeforeBlock implements the EvalTracer interface for pre-block evaluation
func (tracer *TxnGroupDeltaTracer) BeforeBlock(hdr *bookkeeping.BlockHeader) {
	// Drop older rounds based on the Lookback parameter
	delete(tracer.txnGroupDeltas, hdr.Round-basics.Round(tracer.Lookback))
	tracer.latestRound = hdr.Round
}

// AfterTxnGroup implements the EvalTracer interface for txn group boundaries
func (tracer *TxnGroupDeltaTracer) AfterTxnGroup(ep *logic.EvalParams, deltas *ledgercore.StateDelta, evalError error) {
	var txnDeltaMap = make(map[crypto.Digest]*ledgercore.StateDelta)
	for _, txn := range ep.TxnGroup {
		// Add Group ID
		if !txn.Txn.Group.IsZero() {
			txnDeltaMap[txn.Txn.Group] = deltas
		}
		// Add Txn ID
		txnDeltaMap[crypto.Digest(txn.ID())] = deltas
		for innerIndex, innerTxn := range txn.ApplyData.EvalDelta.InnerTxns {
			// Add Inner Txn IDs
			txnDeltaMap[crypto.Digest(innerTxn.Txn.InnerID(txn.ID(), innerIndex))] = deltas
		}
	}
	tracer.txnGroupDeltas[tracer.latestRound] = txnDeltaMap
}

// GetDeltasForRound supplies all StateDelta objects for txn groups in a given rnd
func (tracer *TxnGroupDeltaTracer) GetDeltasForRound(rnd basics.Round) ([]ledgercore.StateDelta, error) {
	rndEntries, exists := tracer.txnGroupDeltas[rnd]
	if !exists {
		return nil, fmt.Errorf("round %d not found in txnGroupDeltaTracer", rnd)
	}
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
