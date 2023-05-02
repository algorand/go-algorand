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
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// TxnGroupDeltaWithIds associates all the Ids (group and Txn) with a single state delta object
type TxnGroupDeltaWithIds struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	Ids     []string
	Delta   StateDeltaSubset
}

// StateDeltaSubset exports a subset of ledgercore.StateDelta fields for a sparse encoding
type StateDeltaSubset struct {
	_struct    struct{} `codec:",omitempty,omitemptyarray"`
	Accts      ledgercore.AccountDeltas
	KvMods     map[string]ledgercore.KvValueDelta
	Txids      map[transactions.Txid]ledgercore.IncludedTransactions
	Txleases   map[ledgercore.Txlease]basics.Round
	Creatables map[basics.CreatableIndex]ledgercore.ModifiedCreatable
	Hdr        *bookkeeping.BlockHeader
}

func convertStateDelta(delta ledgercore.StateDelta) TxnGroupDeltaWithIds {
	return TxnGroupDeltaWithIds{
		Delta: StateDeltaSubset{
			Accts:      delta.Accts,
			KvMods:     delta.KvMods,
			Txids:      delta.Txids,
			Txleases:   delta.Txleases,
			Creatables: delta.Creatables,
			Hdr:        delta.Hdr,
		},
	}
}

// TxnGroupDeltaTracer collects groups of StateDelta objects covering groups of txns
type TxnGroupDeltaTracer struct {
	// lookback is the number of rounds stored at any given time
	lookback uint64
	// no-op methods we don't care about
	logic.NullEvalTracer
	// txnGroupDeltas stores the StateDelta objects for each round, indexed by all the IDs within the group
	txnGroupDeltas map[basics.Round]map[crypto.Digest]*ledgercore.StateDelta
	// latestRound is the most recent round seen via the BeforeBlock hdr
	latestRound basics.Round
}

// MakeTxnGroupDeltaTracer creates a TxnGroupDeltaTracer
func MakeTxnGroupDeltaTracer(lookback uint64) *TxnGroupDeltaTracer {
	return &TxnGroupDeltaTracer{
		lookback:       lookback,
		txnGroupDeltas: make(map[basics.Round]map[crypto.Digest]*ledgercore.StateDelta),
	}
}

// BeforeBlock implements the EvalTracer interface for pre-block evaluation
func (tracer *TxnGroupDeltaTracer) BeforeBlock(hdr *bookkeeping.BlockHeader) {
	// Drop older rounds based on the lookback parameter
	delete(tracer.txnGroupDeltas, hdr.Round-basics.Round(tracer.lookback))
	tracer.latestRound = hdr.Round
	// Initialize the delta map for the round
	tracer.txnGroupDeltas[tracer.latestRound] = make(map[crypto.Digest]*ledgercore.StateDelta)
}

// AfterTxnGroup implements the EvalTracer interface for txn group boundaries
func (tracer *TxnGroupDeltaTracer) AfterTxnGroup(ep *logic.EvalParams, deltas *ledgercore.StateDelta, evalError error) {
	if deltas == nil {
		return
	}
	txnDeltaMap := tracer.txnGroupDeltas[tracer.latestRound]
	for _, txn := range ep.TxnGroup {
		// Add Group ID
		if !txn.Txn.Group.IsZero() {
			txnDeltaMap[txn.Txn.Group] = deltas
		}
		// Add Txn ID
		txnDeltaMap[crypto.Digest(txn.ID())] = deltas
	}
}

// GetDeltasForRound supplies all StateDelta objects for txn groups in a given rnd
func (tracer *TxnGroupDeltaTracer) GetDeltasForRound(rnd basics.Round) ([]TxnGroupDeltaWithIds, error) {
	rndEntries, exists := tracer.txnGroupDeltas[rnd]
	if !exists {
		return nil, fmt.Errorf("round %d not found in txnGroupDeltaTracer", rnd)
	}
	// Dedupe entries in our map and collect Ids
	var deltas = map[*ledgercore.StateDelta][]string{}
	for id, delta := range rndEntries {
		if _, present := deltas[delta]; !present {
			deltas[delta] = append(deltas[delta], id.String())
		}
	}
	var deltasForRound []TxnGroupDeltaWithIds
	for delta, ids := range deltas {
		deltaForGroup := convertStateDelta(*delta)
		deltaForGroup.Ids = ids
		deltasForRound = append(deltasForRound, deltaForGroup)
	}
	return deltasForRound, nil
}

// GetDeltaForID retruns the StateDelta associated with the group of transaction executed for the supplied ID (txn or group)
func (tracer *TxnGroupDeltaTracer) GetDeltaForID(id crypto.Digest) (ledgercore.StateDelta, error) {
	for _, deltasForRound := range tracer.txnGroupDeltas {
		if delta, exists := deltasForRound[id]; exists {
			return *delta, nil
		}
	}
	return ledgercore.StateDelta{}, fmt.Errorf("unable to find delta for id: %s", id)
}
