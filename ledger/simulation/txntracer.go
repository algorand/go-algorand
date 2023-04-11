package simulation

import (
	"bytes"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

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
}

// AfterTxnGroup implements the EvalTracer interface for txn group boundaries
func (tracer *TxnGroupDeltaTracer) AfterTxnGroup(ep *logic.EvalParams, deltas *ledgercore.StateDelta, evalError error) {
	round := ep.Ledger.Round()
	// Remove old data if it exists
	delete(tracer.txnGroupDeltas, round-basics.Round(tracer.Lookback))
	for _, txn := range ep.TxnGroup {
		// Add Group ID
		if !txn.Txn.Group.IsZero() {
			tracer.txnGroupDeltas[round][txn.Txn.Group] = deltas
		}
		// Add Txn ID
		tracer.txnGroupDeltas[round][crypto.Digest(txn.ID())] = deltas
		for innerIndex, innerTxn := range txn.ApplyData.EvalDelta.InnerTxns {
			// TODO which one of these is correct?
			// Add Inner Txn IDs
			tracer.txnGroupDeltas[round][crypto.Digest(innerTxn.Txn.InnerID(txn.ID(), innerIndex))] = deltas
			tracer.txnGroupDeltas[round][crypto.Digest(innerTxn.ID())] = deltas
		}
	}
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
