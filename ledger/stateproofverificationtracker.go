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

type stateProofVerificationTracker struct {
	trackedData map[basics.Round]StateProofVerificationData
}

func (spt *stateProofVerificationTracker) loadFromDisk(ledgerForTracker, basics.Round) error {
	spt.trackedData = make(map[basics.Round]StateProofVerificationData)
	return nil
}

func (spt *stateProofVerificationTracker) newBlock(blk bookkeeping.Block, _ ledgercore.StateDelta) {
	if uint64(blk.Round())%blk.ConsensusProtocol().StateProofInterval == 0 {
		verificationData := StateProofVerificationData{
			VotersCommitment: blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
			ProvenWeight:     blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
		}
		spt.trackedData[blk.Round()] = verificationData
	}
}

func (spt *stateProofVerificationTracker) committedUpTo(round basics.Round) (minRound, lookback basics.Round) {
	return round, 0
}

func (spt *stateProofVerificationTracker) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return nil
}

func (spt *stateProofVerificationTracker) prepareCommit(*deferredCommitContext) error {
	return nil
}

func (spt *stateProofVerificationTracker) commitRound(context.Context, *sql.Tx, *deferredCommitContext) error {
	return nil
}

func (spt *stateProofVerificationTracker) postCommit(context.Context, *deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) postCommitUnlocked(context.Context, *deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) handleUnorderedCommit(*deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) close() {

}
