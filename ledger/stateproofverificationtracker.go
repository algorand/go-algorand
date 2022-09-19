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

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errStateProofVerificationDataNotFound        = errors.New("requested state proof verification data not found in memory")
	errStateProofVerificationDataNotYetGenerated = errors.New("requested state proof verification data is in a future block")
)

// TODO: Add locks where needed

type verificationDeletionData struct {
	stateProofTransactionRound  basics.Round
	stateProofLastAttestedRound basics.Round
}

type stateProofVerificationTracker struct {
	dbQueries stateProofVerificationDbQueries

	trackedData []ledgercore.StateProofVerificationData

	trackedDeletionData []verificationDeletionData

	stateProofVerificationMu deadlock.RWMutex
}

// TODO: Should use binary search
func (spt *stateProofVerificationTracker) roundToLatestDeletionIndex(round basics.Round) int {
	latestDeletionIndex := -1

	for index, deletionData := range spt.trackedDeletionData {
		if deletionData.stateProofTransactionRound <= round {
			latestDeletionIndex = index
		}
	}

	return latestDeletionIndex
}

// TODO: Should use binary search
func (spt *stateProofVerificationTracker) roundToLatestDataIndex(round basics.Round) uint64 {
	for index, verificationData := range spt.trackedData {
		if verificationData.GeneratedRound > round {
			return uint64(index)
		}
	}

	return uint64(len(spt.trackedData))
}

func (spt *stateProofVerificationTracker) lookupDataInTrackedMemory(stateProofLastAttestedRound basics.Round) (ledgercore.StateProofVerificationData, error) {
	for _, verificationData := range spt.trackedData {
		if verificationData.TargetStateProofRound == stateProofLastAttestedRound {
			return verificationData, nil
		}
	}

	return ledgercore.StateProofVerificationData{}, errStateProofVerificationDataNotFound
}

func (spt *stateProofVerificationTracker) loadFromDisk(l ledgerForTracker, _ basics.Round) error {
	preparedDbQueries, err := stateProofVerificationInitDbQueries(l.trackerDB().Rdb.Handle)
	if err != nil {
		return err
	}

	spt.dbQueries = *preparedDbQueries

	latestRoundInLedger := l.Latest()
	latestBlockHeader, err := l.BlockHdr(latestRoundInLedger)

	if err != nil {
		return err
	}

	proto := config.Consensus[latestBlockHeader.CurrentProtocol]

	// Starting from StateProofMaxRecoveryIntervals provides the order of magnitude for expected state proof chain delay,
	// and is thus a good size to start from.
	spt.trackedData = make([]ledgercore.StateProofVerificationData, 0, proto.StateProofMaxRecoveryIntervals)
	spt.trackedDeletionData = make([]verificationDeletionData, 0, proto.StateProofMaxRecoveryIntervals)

	return nil
}

func (spt *stateProofVerificationTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	if blk.ConsensusProtocol().StateProofInterval == 0 {
		return
	}

	currentStateProofInterval := basics.Round(blk.ConsensusProtocol().StateProofInterval)
	if blk.Round()%currentStateProofInterval == 0 {
		verificationData := ledgercore.StateProofVerificationData{
			VotersCommitment:      blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
			ProvenWeight:          blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
			TargetStateProofRound: blk.Round() + currentStateProofInterval,
			GeneratedRound:        blk.Round(),
		}
		spt.trackedData = append(spt.trackedData, verificationData)
	}

	if delta.StateProofNext != 0 {
		deletionData := verificationDeletionData{
			stateProofLastAttestedRound: delta.StateProofNext.SubSaturate(currentStateProofInterval),
			stateProofTransactionRound:  blk.Round(),
		}
		spt.trackedDeletionData = append(spt.trackedDeletionData, deletionData)
	}
}

func (spt *stateProofVerificationTracker) committedUpTo(round basics.Round) (minRound, lookback basics.Round) {
	return round, 0
}

func (spt *stateProofVerificationTracker) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	if committedRound < dcr.lookback {
		return nil
	}

	newBase := committedRound - dcr.lookback
	if newBase <= dbRound {
		// Already forgotten
		return nil
	}

	// TODO: warn on what basically amounts to interval change?
	offset := uint64(newBase - dbRound)

	dcr.oldBase = dbRound
	dcr.offset = offset
	return dcr
}

func (spt *stateProofVerificationTracker) prepareCommit(dcc *deferredCommitContext) error {
	lastDataToCommitIndex := spt.roundToLatestDataIndex(dcc.newBase)
	dcc.committedStateProofVerificationData = make([]ledgercore.StateProofVerificationData, lastDataToCommitIndex)
	copy(dcc.committedStateProofVerificationData, spt.trackedData[:lastDataToCommitIndex])

	dcc.latestStateProofVerificationDeletionDataIndex = spt.roundToLatestDeletionIndex(dcc.newBase)
	if dcc.latestStateProofVerificationDeletionDataIndex > 0 {
		dcc.latestStateProofVerificationDeletionData = spt.trackedDeletionData[dcc.latestStateProofVerificationDeletionDataIndex]
	}

	return nil
}

func (spt *stateProofVerificationTracker) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) (err error) {
	err = insertStateProofVerificationData(ctx, tx, &dcc.committedStateProofVerificationData)
	if err != nil {
		return err
	}

	// TODO: can this be in postCommitUnlocked?
	if dcc.latestStateProofVerificationDeletionDataIndex > 0 {
		err = deleteOldStateProofVerificationData(ctx, tx, dcc.latestStateProofVerificationDeletionData.stateProofLastAttestedRound)
	}

	// TODO: caching mechanism for oldest data?
	return err

}

func (spt *stateProofVerificationTracker) postCommit(_ context.Context, dcc *deferredCommitContext) {
	// TODO: can this be in postCommitUnlocked?
	spt.trackedData = spt.trackedData[len(dcc.committedStateProofVerificationData):]
	spt.trackedDeletionData = spt.trackedDeletionData[dcc.latestStateProofVerificationDeletionDataIndex+1:]
}

func (spt *stateProofVerificationTracker) postCommitUnlocked(context.Context, *deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) handleUnorderedCommit(*deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) close() {
}

// TODO: must lock here
// TODO: additional data in error messages

func (spt *stateProofVerificationTracker) LookupVerificationData(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationData, error) {
	if len(spt.trackedData) == 0 || stateProofLastAttestedRound < spt.trackedData[0].TargetStateProofRound {
		return spt.dbQueries.lookupData(stateProofLastAttestedRound)
	}

	if stateProofLastAttestedRound <= spt.trackedData[len(spt.trackedData)-1].TargetStateProofRound {
		verificationData, err := spt.lookupDataInTrackedMemory(stateProofLastAttestedRound)
		return &verificationData, err
	}

	return &ledgercore.StateProofVerificationData{}, errStateProofVerificationDataNotYetGenerated
}
