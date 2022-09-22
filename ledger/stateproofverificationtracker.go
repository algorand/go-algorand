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

type verificationDeleteData struct {
	generatedRound      basics.Round
	stateProofNextRound basics.Round
}

type verificationCommitData struct {
	generatedRound   basics.Round
	verificationData ledgercore.StateProofVerificationData
}

type stateProofVerificationTracker struct {
	dbQueries stateProofVerificationDbQueries

	trackedCommitData []verificationCommitData
	trackedDeleteData []verificationDeleteData

	stateProofVerificationMu deadlock.RWMutex
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

	spt.stateProofVerificationMu.Lock()
	defer spt.stateProofVerificationMu.Unlock()

	// Starting from StateProofMaxRecoveryIntervals provides the order of magnitude for expected state proof chain delay,
	// and is thus a good size to start from.
	spt.trackedCommitData = make([]verificationCommitData, 0, proto.StateProofMaxRecoveryIntervals)
	spt.trackedDeleteData = make([]verificationDeleteData, 0, proto.StateProofMaxRecoveryIntervals)

	return nil
}

func (spt *stateProofVerificationTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	currentStateProofInterval := basics.Round(blk.ConsensusProtocol().StateProofInterval)

	if currentStateProofInterval == 0 {
		return
	}

	spt.stateProofVerificationMu.Lock()
	defer spt.stateProofVerificationMu.Unlock()

	if blk.Round()%currentStateProofInterval == 0 {
		spt.insertCommitData(&blk)
	}

	if delta.StateProofNext != 0 {
		spt.insertDeleteData(&blk, &delta)
	}
}

func (spt *stateProofVerificationTracker) committedUpTo(round basics.Round) (minRound, lookback basics.Round) {
	return round, 0
}

func (spt *stateProofVerificationTracker) produceCommittingTask(_ basics.Round, _ basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return dcr
}

func (spt *stateProofVerificationTracker) prepareCommit(dcc *deferredCommitContext) error {
	spt.stateProofVerificationMu.RLock()
	defer spt.stateProofVerificationMu.RUnlock()

	lastDataToCommitIndex := spt.committedRoundToLatestCommitDataIndex(dcc.newBase)
	dcc.stateProofVerificationCommitData = make([]verificationCommitData, lastDataToCommitIndex+1)
	copy(dcc.stateProofVerificationCommitData, spt.trackedCommitData[:lastDataToCommitIndex+1])

	dcc.stateProofVerificationLatestDeleteDataIndex = spt.committedRoundToLatestDeleteDataIndex(dcc.newBase)
	if dcc.stateProofVerificationLatestDeleteDataIndex > 0 {
		dcc.stateProofVerificationDeleteData = spt.trackedDeleteData[dcc.stateProofVerificationLatestDeleteDataIndex]
	}

	return nil
}

func (spt *stateProofVerificationTracker) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) (err error) {
	err = insertStateProofVerificationData(ctx, tx, &dcc.stateProofVerificationCommitData)
	if err != nil {
		return err
	}

	if dcc.stateProofVerificationLatestDeleteDataIndex > 0 {
		err = deleteOldStateProofVerificationData(ctx, tx, dcc.stateProofVerificationDeleteData.stateProofNextRound)
	}

	return err

}

func (spt *stateProofVerificationTracker) postCommit(_ context.Context, dcc *deferredCommitContext) {
	spt.stateProofVerificationMu.Lock()
	defer spt.stateProofVerificationMu.Unlock()

	spt.trackedCommitData = spt.trackedCommitData[len(dcc.stateProofVerificationCommitData):]
	spt.trackedDeleteData = spt.trackedDeleteData[dcc.stateProofVerificationLatestDeleteDataIndex+1:]
}

func (spt *stateProofVerificationTracker) postCommitUnlocked(context.Context, *deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) handleUnorderedCommit(*deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) close() {
	spt.dbQueries.lookupStateProofVerificationData.Close()
}

// TODO: additional data in error messages
// TODO: caching mechanism for oldest data?

func (spt *stateProofVerificationTracker) LookupVerificationData(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationData, error) {
	spt.stateProofVerificationMu.RLock()
	defer spt.stateProofVerificationMu.RUnlock()

	if len(spt.trackedCommitData) == 0 || stateProofLastAttestedRound < spt.trackedCommitData[0].verificationData.TargetStateProofRound {
		return spt.dbQueries.lookupData(stateProofLastAttestedRound)
	}

	if stateProofLastAttestedRound <= spt.trackedCommitData[len(spt.trackedCommitData)-1].verificationData.TargetStateProofRound {
		verificationData, err := spt.lookupDataInTrackedMemory(stateProofLastAttestedRound)
		return &verificationData, err
	}

	return &ledgercore.StateProofVerificationData{}, errStateProofVerificationDataNotYetGenerated
}

// TODO: How to combine these two functions using interfaces?
func (spt *stateProofVerificationTracker) committedRoundToLatestCommitDataIndex(committedRound basics.Round) int {
	latestCommittedDataIndex := -1

	for index, data := range spt.trackedCommitData {
		if data.generatedRound <= committedRound {
			latestCommittedDataIndex = index
		}
	}

	return latestCommittedDataIndex
}

func (spt *stateProofVerificationTracker) committedRoundToLatestDeleteDataIndex(committedRound basics.Round) int {
	latestCommittedDataIndex := -1

	for index, data := range spt.trackedDeleteData {
		if data.generatedRound <= committedRound {
			latestCommittedDataIndex = index
		}
	}

	return latestCommittedDataIndex
}

func (spt *stateProofVerificationTracker) lookupDataInTrackedMemory(stateProofLastAttestedRound basics.Round) (ledgercore.StateProofVerificationData, error) {
	for _, commitData := range spt.trackedCommitData {
		if commitData.verificationData.TargetStateProofRound == stateProofLastAttestedRound {
			return commitData.verificationData, nil
		}
	}

	return ledgercore.StateProofVerificationData{}, errStateProofVerificationDataNotFound
}

func (spt *stateProofVerificationTracker) insertCommitData(blk *bookkeeping.Block) {
	verificationData := ledgercore.StateProofVerificationData{
		VotersCommitment:      blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		ProvenWeight:          blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
		TargetStateProofRound: blk.Round() + basics.Round(blk.ConsensusProtocol().StateProofInterval),
	}

	commitData := verificationCommitData{
		generatedRound:   blk.Round(),
		verificationData: verificationData,
	}
	spt.trackedCommitData = append(spt.trackedCommitData, commitData)
}

func (spt *stateProofVerificationTracker) insertDeleteData(blk *bookkeeping.Block, delta *ledgercore.StateDelta) {
	deletionData := verificationDeleteData{
		generatedRound:      blk.Round(),
		stateProofNextRound: delta.StateProofNext,
	}
	spt.trackedDeleteData = append(spt.trackedDeleteData, deletionData)
}
