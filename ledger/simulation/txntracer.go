package simulation

import (
	"bytes"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

type txnGroupDeltaTracer struct {
	// lookback is the number of rounds stored at any given time
	lookback uint64
	// no-op methods we don't care about
	logic.NullEvalTracer
	// txnGroupDeltas stores the StateDelta objects for each round, indexed by all the IDs within the group
	txnGroupDeltas map[basics.Round]map[crypto.Digest]*ledgercore.StateDelta
}

func (tracer *txnGroupDeltaTracer) AfterTxnGroup(ep *logic.EvalParams, deltas *ledgercore.StateDelta, evalError error) {
	round := ep.Ledger.Round()
	// Remove old data if it exists
	delete(tracer.txnGroupDeltas, round-basics.Round(tracer.lookback))
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

func (tracer *txnGroupDeltaTracer) GetDeltasForRound(rnd basics.Round) ([]ledgercore.StateDelta, error) {
	rndEntries, exists := tracer.txnGroupDeltas[rnd]
	if !exists {
		return nil, fmt.Errorf("round %d not found in txnGroupDeltaTracer", rnd)
	}
	// Dedupe entries in our map
	var deltas map[*ledgercore.StateDelta]bool
	var entries []ledgercore.StateDelta
	for _, delta := range rndEntries {
		if _, present := deltas[delta]; !present {
			deltas[delta] = true
			entries = append(entries, *delta)
		}
	}
	return entries, nil
}

func (tracer *txnGroupDeltaTracer) GetDeltaForId(id crypto.Digest) (ledgercore.StateDelta, error) {
	for _, deltasForRound := range tracer.txnGroupDeltas {
		for idKey, deltaVal := range deltasForRound {
			if bytes.Compare(idKey[:], id[:]) == 0 {
				return *deltaVal, nil
			}
		}
	}
	return ledgercore.StateDelta{}, fmt.Errorf("unable to find delta for id: %s", id)
}
