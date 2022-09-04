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

// newBlock informs the tracker of a new block along with
// a given ledgercore.StateDelta as produced by BlockEvaluator.
func (spt *stateProofTracker) newBlock(blk bookkeeping.Block, _ ledgercore.StateDelta) {
	if uint64(blk.Round())%blk.ConsensusProtocol().StateProofInterval == 0 {
		verificationData := StateProofVerificationData{
			VotersCommitment: blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
			ProvenWeight:     blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
		}
		spt.trackedData[blk.Round()] = verificationData
	}
}

// committedUpTo informs the tracker that the block database has
// committed all blocks up to and including rnd to persistent
// storage.  This can allow the tracker
// to garbage-collect state that will not be needed.
//
// committedUpTo() returns the round number of the earliest
// block that this tracker needs to be stored in the block
// database for subsequent calls to loadFromDisk().
// All blocks with round numbers before that may be deleted to
// save space, and the tracker is expected to still function
// after a restart and a call to loadFromDisk().
// For example, returning 0 means that no blocks can be deleted.
// Separetly, the method returns the lookback that is being
// maintained by the tracker.
func (spt *stateProofTracker) committedUpTo(round basics.Round) (minRound, lookback basics.Round) {
	return round, 0
}

// produceCommittingTask prepares a deferredCommitRange; Preparing a deferredCommitRange is a joint
// effort, and all the trackers contribute to that effort. All the trackers are being handed a
// pointer to the deferredCommitRange, and have the ability to either modify it, or return a
// nil. If nil is returned, the commit would be skipped.
// The contract:
// offset must not be greater than the received dcr.offset value of non zero
// oldBase must not be modifed if non zero
func (spt *stateProofTracker) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return nil
}

// prepareCommit, commitRound and postCommit are called when it is time to commit tracker's data.
// If an error returned the process is aborted.

// prepareCommit aligns the data structures stored in the deferredCommitContext with the current
// state of the tracker. It allows the tracker to decide what data is going to be persisted
// on the coming commitRound.
func (spt *stateProofTracker) prepareCommit(*deferredCommitContext) error {
	return nil
}

// commitRound is called for each of the trackers after a deferredCommitContext was agreed upon
// by all the prepareCommit calls. The commitRound is being executed within a single transactional
// context, and so, if any of the tracker's commitRound calls fails, the transaction is rolled back.
func (spt *stateProofTracker) commitRound(context.Context, *sql.Tx, *deferredCommitContext) error {
	return nil
}

// postCommit is called only on a successful commitRound. In that case, each of the trackers have
// the chance to update it's internal data structures, knowing that the given deferredCommitContext
// has completed. An optional context is provided for long-running operations.
func (spt *stateProofTracker) postCommit(context.Context, *deferredCommitContext) {

}

// postCommitUnlocked is called only on a successful commitRound. In that case, each of the trackers have
// the chance to make changes that aren't state-dependent.
// An optional context is provided for long-running operations.
func (spt *stateProofTracker) postCommitUnlocked(context.Context, *deferredCommitContext) {

}

// handleUnorderedCommit is a special method for handling deferred commits that are out of order.
// Tracker might update own state in this case. For example, account updates tracker cancels
// scheduled catchpoint writing that deferred commit.
func (spt *stateProofTracker) handleUnorderedCommit(*deferredCommitContext) {

}

// close terminates the tracker, reclaiming any resources
// like open database connections or goroutines.  close may
// be called even if loadFromDisk() is not called or does
// not succeed.
func (spt *stateProofTracker) close() {

}
