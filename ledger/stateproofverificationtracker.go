// Copyright (C) 2019-2022 Algorand, Inc.
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
	"context"
	"database/sql"
	"errors"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errStateProofVerificationDataNotYetGenerated = errors.New("requested state proof verification data is too far in the future")
)

// TODO: Handle state proofs not being enabled
// TODO: Add locks where needed
// TODO: renaming

type stateProofFlushData struct {
	stateProofLastAttestedRound basics.Round
	stateProofTransactionRound  basics.Round
}

type stateProofVerificationTracker struct {
	dbQueries stateProofVerificationDbQueries

	trackedData []ledgercore.StateProofVerificationData

	stateProofsToFlush []stateProofFlushData
}

// TODO: Should use binary search
func (spt *stateProofVerificationTracker) roundToPrunedStateProof(round basics.Round) basics.Round {
	latestStateProofRound := basics.Round(0)
	for _, flushData := range spt.stateProofsToFlush {
		if flushData.stateProofTransactionRound < round {
			latestStateProofRound = flushData.stateProofLastAttestedRound
		}
	}

	return latestStateProofRound
}

// TODO: Should use binary search
func (spt *stateProofVerificationTracker) roundToTrackedIndex(round basics.Round) uint64 {
	for index, verificationData := range spt.trackedData {
		if verificationData.TargetStateProofRound > round {
			return uint64(index)
		}
	}

	return uint64(len(spt.trackedData))
}

func (spt *stateProofVerificationTracker) loadFromDisk(ledgerForTracker, basics.Round) error {
	// TODO: Decide on slice size
	spt.trackedData = make([]ledgercore.StateProofVerificationData, 0, 1000)
	return nil
}

func (spt *stateProofVerificationTracker) newBlock(blk bookkeeping.Block, _ ledgercore.StateDelta) {
	if blk.ConsensusProtocol().StateProofInterval == 0 {
		return
	}

	if uint64(blk.Round())%blk.ConsensusProtocol().StateProofInterval == 0 {
		verificationData := ledgercore.StateProofVerificationData{
			VotersCommitment:      blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
			ProvenWeight:          blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
			TargetStateProofRound: blk.Round() + basics.Round(blk.ConsensusProtocol().StateProofInterval),
		}
		spt.trackedData = append(spt.trackedData, verificationData)
	}

	lastAttestedRound := blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound.SubSaturate(
		basics.Round(blk.ConsensusProtocol().StateProofInterval))
	// TODO: What about the first state proof transaction?
	// TODO: Bigger than?
	if lastAttestedRound != spt.stateProofsToFlush[len(spt.stateProofsToFlush)-1].stateProofLastAttestedRound {
		flushData := stateProofFlushData{
			stateProofLastAttestedRound: lastAttestedRound,
			stateProofTransactionRound:  blk.Round(),
		}
		spt.stateProofsToFlush = append(spt.stateProofsToFlush, flushData)
	}
}

func (spt *stateProofVerificationTracker) committedUpTo(round basics.Round) (minRound, lookback basics.Round) {
	return round, 0
}

// We do not need to influence the chosen offset or db round.
func (spt *stateProofVerificationTracker) produceCommittingTask(_ basics.Round, _ basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return dcr
}

// TODO: maybe be clever and remove from memory before flushing to DB?
func (spt *stateProofVerificationTracker) prepareCommit(dcc *deferredCommitContext) error {
	lastDataToCommitIndex := spt.roundToTrackedIndex(basics.Round(dcc.offset))
	dcc.committedStateProofVerificationData = make([]ledgercore.StateProofVerificationData, lastDataToCommitIndex)
	copy(dcc.committedStateProofVerificationData, spt.trackedData[:lastDataToCommitIndex])

	dcc.staleStateProofRound = spt.roundToPrunedStateProof(dcc.newBase)
	return nil
}

func (spt *stateProofVerificationTracker) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) (err error) {
	err = insertStateProofVerificationData(ctx, tx, &dcc.committedStateProofVerificationData)
	if err != nil {
		return err
	}

	// TODO: can this in postCommitUnlocked?
	err = pruneOldStateProofVerificationData(ctx, tx, dcc.staleStateProofRound)

	// TODO: caching mechanism for oldest data
	return err

}

func (spt *stateProofVerificationTracker) postCommit(_ context.Context, dcc *deferredCommitContext) {
	// TODO: can this be in postCommitUnlocked?
	spt.trackedData = spt.trackedData[len(dcc.committedStateProofVerificationData):]
	// TODO: empty flushed data
}

func (spt *stateProofVerificationTracker) postCommitUnlocked(context.Context, *deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) handleUnorderedCommit(*deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) close() {
}

// TODO: must lock here

func (spt *stateProofVerificationTracker) LookupVerificationData(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationData, error) {
	if len(spt.trackedData) == 0 || stateProofLastAttestedRound < spt.trackedData[0].TargetStateProofRound {
		// TODO: bound check here too, for descriptive errors
		return spt.dbQueries.lookupData(stateProofLastAttestedRound)
	}

	if stateProofLastAttestedRound > spt.trackedData[len(spt.trackedData)-1].TargetStateProofRound {
		return &ledgercore.StateProofVerificationData{}, errStateProofVerificationDataNotYetGenerated
	}

	return &spt.trackedData[spt.roundToTrackedIndex(stateProofLastAttestedRound)], nil
}
