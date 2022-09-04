package ledger

import (
	"context"
	"database/sql"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

type StateProofVerificationData struct {
	VotersCommitment crypto.GenericDigest
	ProvenWeight     basics.MicroAlgos
}

type stateProofTracker struct {
	trackedData map[basics.Round]StateProofVerificationData
}

func (spt *stateProofTracker) loadFromDisk(ledgerForTracker, basics.Round) error {
	spt.trackedData = make(map[basics.Round]StateProofVerificationData)
	return nil
}

func (spt *stateProofTracker) newBlock(blk bookkeeping.Block, _ ledgercore.StateDelta) {
	if uint64(blk.Round())%blk.ConsensusProtocol().StateProofInterval == 0 {
		verificationData := StateProofVerificationData{
			VotersCommitment: blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
			ProvenWeight:     blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
		}
		spt.trackedData[blk.Round()] = verificationData
	}
}

func (spt *stateProofTracker) committedUpTo(round basics.Round) (minRound, lookback basics.Round) {
	return round, 0
}

func (spt *stateProofTracker) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return nil
}

func (spt *stateProofTracker) prepareCommit(*deferredCommitContext) error {
	return nil
}

func (spt *stateProofTracker) commitRound(context.Context, *sql.Tx, *deferredCommitContext) error {
	return nil
}

func (spt *stateProofTracker) postCommit(context.Context, *deferredCommitContext) {

}

func (spt *stateProofTracker) postCommitUnlocked(context.Context, *deferredCommitContext) {

}

func (spt *stateProofTracker) handleUnorderedCommit(*deferredCommitContext) {

}

func (spt *stateProofTracker) close() {

}
