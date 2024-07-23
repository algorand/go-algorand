// Copyright (C) 2019-2024 Algorand, Inc.
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

	"github.com/algorand/go-deadlock"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// TxnGroupDeltaWithIds associates all the Ids (group and Txn) with a single state delta object
//
//revive:disable:var-naming
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

func convertStateDelta(delta ledgercore.StateDelta) StateDeltaSubset {
	// The StateDelta object returned through the EvalTracer has its values deleted between txn groups to avoid
	// reallocation during evaluation.
	// This means the map values need to be copied (to avoid deletion) since they are all passed by reference.
	kvmods := maps.Clone(delta.KvMods)
	txids := maps.Clone(delta.Txids)
	txleases := maps.Clone(delta.Txleases)
	creatables := maps.Clone(delta.Creatables)

	var accR []ledgercore.BalanceRecord
	var appR []ledgercore.AppResourceRecord
	var assetR []ledgercore.AssetResourceRecord
	if len(delta.Accts.Accts) > 0 {
		accR = slices.Clone(delta.Accts.Accts)
	}
	if len(delta.Accts.AppResources) > 0 {
		appR = slices.Clone(delta.Accts.AppResources)
	}
	if len(delta.Accts.AssetResources) > 0 {
		assetR = slices.Clone(delta.Accts.AssetResources)
	}
	return StateDeltaSubset{
		Accts: ledgercore.AccountDeltas{
			Accts:          accR,
			AppResources:   appR,
			AssetResources: assetR,
		},
		KvMods:     kvmods,
		Txids:      txids,
		Txleases:   txleases,
		Creatables: creatables,
		Hdr:        delta.Hdr,
	}
}

// TxnGroupDeltaTracer collects groups of StateDelta objects covering groups of txns
type TxnGroupDeltaTracer struct {
	deltasLock deadlock.RWMutex
	// lookback is the number of rounds stored at any given time
	lookback uint64
	// no-op methods we don't care about
	logic.NullEvalTracer
	// txnGroupDeltas stores the StateDeltaSubset objects for each round, indexed by all the IDs within the group
	txnGroupDeltas map[basics.Round]map[crypto.Digest]*StateDeltaSubset
	// latestRound is the most recent round seen via the BeforeBlock hdr
	latestRound basics.Round
}

// MakeTxnGroupDeltaTracer creates a TxnGroupDeltaTracer
func MakeTxnGroupDeltaTracer(lookback uint64) *TxnGroupDeltaTracer {
	return &TxnGroupDeltaTracer{
		lookback:       lookback,
		txnGroupDeltas: make(map[basics.Round]map[crypto.Digest]*StateDeltaSubset),
	}
}

// BeforeBlock implements the EvalTracer interface for pre-block evaluation
func (tracer *TxnGroupDeltaTracer) BeforeBlock(hdr *bookkeeping.BlockHeader) {
	tracer.deltasLock.Lock()
	defer tracer.deltasLock.Unlock()
	// Drop older rounds based on the lookback parameter
	delete(tracer.txnGroupDeltas, hdr.Round-basics.Round(tracer.lookback))
	tracer.latestRound = hdr.Round
	// Initialize the delta map for the round
	tracer.txnGroupDeltas[tracer.latestRound] = make(map[crypto.Digest]*StateDeltaSubset)
}

// AfterTxnGroup implements the EvalTracer interface for txn group boundaries
func (tracer *TxnGroupDeltaTracer) AfterTxnGroup(ep *logic.EvalParams, deltas *ledgercore.StateDelta, evalError error) {
	if deltas == nil {
		return
	}
	deltaSub := convertStateDelta(*deltas)
	tracer.deltasLock.Lock()
	defer tracer.deltasLock.Unlock()
	txnDeltaMap := tracer.txnGroupDeltas[tracer.latestRound]
	for _, txn := range ep.TxnGroup {
		// Add Group ID
		if !txn.Txn.Group.IsZero() {
			txnDeltaMap[txn.Txn.Group] = &deltaSub
		}
		// Add Txn ID
		txnDeltaMap[crypto.Digest(txn.ID())] = &deltaSub
	}
}

// GetDeltasForRound supplies all StateDelta objects for txn groups in a given rnd
func (tracer *TxnGroupDeltaTracer) GetDeltasForRound(rnd basics.Round) ([]TxnGroupDeltaWithIds, error) {
	tracer.deltasLock.RLock()
	defer tracer.deltasLock.RUnlock()
	rndEntries, exists := tracer.txnGroupDeltas[rnd]
	if !exists {
		return nil, fmt.Errorf("round %d not found in txnGroupDeltaTracer", rnd)
	}
	// Dedupe entries in our map and collect Ids
	var deltas = map[*StateDeltaSubset][]string{}
	for id, delta := range rndEntries {
		if _, present := deltas[delta]; !present {
			deltas[delta] = append(deltas[delta], id.String())
		}
	}
	var deltasForRound []TxnGroupDeltaWithIds
	for delta, ids := range deltas {
		deltasForRound = append(deltasForRound, TxnGroupDeltaWithIds{
			Ids:   ids,
			Delta: *delta,
		})
	}
	return deltasForRound, nil
}

// GetDeltaForID returns the StateDelta associated with the group of transaction executed for the supplied ID (txn or group)
func (tracer *TxnGroupDeltaTracer) GetDeltaForID(id crypto.Digest) (StateDeltaSubset, error) {
	tracer.deltasLock.RLock()
	defer tracer.deltasLock.RUnlock()
	for _, deltasForRound := range tracer.txnGroupDeltas {
		if delta, exists := deltasForRound[id]; exists {
			return *delta, nil
		}
	}
	return StateDeltaSubset{}, fmt.Errorf("unable to find delta for id: %s", id)
}
