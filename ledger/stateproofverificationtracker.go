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
	"fmt"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errStateProofVerificationDataNotFound = errors.New("requested state proof verification data not found")
)

type verificationDeleteData struct {
	confirmedRound      basics.Round
	stateProofNextRound basics.Round
}

type verificationCommitData struct {
	confirmedRound             basics.Round
	firstStageVerificationData ledgercore.StateProofFirstStageVerificationData
}

type verificationCommitUpdateData struct {
	confirmedRound              basics.Round
	secondStageVerificationData ledgercore.StateProofSecondStageVerificationData
}

// stateProofVerificationTracker is in charge of tracking data required to verify state proofs until such a time
// as the data is no longer needed.
type stateProofVerificationTracker struct {
	// dbQueries are the pre-generated queries used to query the database, if needed,
	// to lookup state proof verification data.
	dbQueries stateProofVerificationDbQueries

	// trackedFirstStageData represents the part of the tracked verification data currently in memory. Each element in this
	// array contains both the data required to verify a single state proof and data to decide whether it's possible to
	// commit the verification data to the database.
	trackedFirstStageData []verificationCommitData

	// trackedDeleteData represents the data required to delete committed state proof verification data from the
	// database.
	trackedDeleteData []verificationDeleteData

	// trackedSecondStageData represents additional data that needs to be added to the commitment verification data.
	trackedSecondStageData []verificationCommitUpdateData

	// stateProofVerificationMu protects trackedFirstStageData and trackedDeleteData.
	stateProofVerificationMu deadlock.RWMutex

	// log copied from ledger
	log logging.Logger
}

func (spt *stateProofVerificationTracker) loadFromDisk(l ledgerForTracker, _ basics.Round) error {
	preparedDbQueries, err := stateProofVerificationInitDbQueries(l.trackerDB().Rdb.Handle)
	if err != nil {
		return err
	}

	spt.dbQueries = *preparedDbQueries

	spt.log = l.trackerLog()

	spt.stateProofVerificationMu.Lock()
	defer spt.stateProofVerificationMu.Unlock()

	const initialDataArraySize = 10
	spt.trackedFirstStageData = make([]verificationCommitData, 0, initialDataArraySize)
	spt.trackedDeleteData = make([]verificationDeleteData, 0, initialDataArraySize)
	spt.trackedSecondStageData = make([]verificationCommitUpdateData, 0, initialDataArraySize)

	return nil
}

func (spt *stateProofVerificationTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	currentStateProofInterval := basics.Round(blk.ConsensusProtocol().StateProofInterval)

	if currentStateProofInterval == 0 {
		return
	}

	if blk.Round()%currentStateProofInterval == 0 {
		spt.insertFirstStageCommitData(&blk)
		spt.insertSecondStageCommitData(&blk)
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
	dcc.stateProofFirstStageCommitData = make([]verificationCommitData, lastDataToCommitIndex+1)
	copy(dcc.stateProofFirstStageCommitData, spt.trackedFirstStageData[:lastDataToCommitIndex+1])

	lastDataToUpdateIndex := spt.committedRoundToLatestSecondStageDataIndex(dcc.newBase)
	dcc.stateProofSecondStageCommitData = make([]verificationCommitUpdateData, lastDataToUpdateIndex+1)
	copy(dcc.stateProofSecondStageCommitData, spt.trackedSecondStageData[:lastDataToUpdateIndex+1])

	dcc.stateProofVerificationLatestDeleteDataIndex = spt.committedRoundToLatestDeleteDataIndex(dcc.newBase)
	if dcc.stateProofVerificationLatestDeleteDataIndex > -1 {
		dcc.stateProofVerificationEarliestTrackStateProofRound = spt.trackedDeleteData[dcc.stateProofVerificationLatestDeleteDataIndex].stateProofNextRound
	}

	return nil
}

func (spt *stateProofVerificationTracker) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) (err error) {
	err = insertFirstStageStateProofVerificationData(ctx, tx, dcc.stateProofFirstStageCommitData)
	if err != nil {
		return err
	}

	err = insertSecondStageStateProofVerificationData(ctx, tx, dcc.stateProofSecondStageCommitData)
	if err != nil {
		return err
	}

	if dcc.stateProofVerificationLatestDeleteDataIndex > -1 {
		err = deleteOldStateProofVerificationData(ctx, tx, dcc.stateProofVerificationEarliestTrackStateProofRound)
	}

	return err

}

func (spt *stateProofVerificationTracker) postCommit(_ context.Context, dcc *deferredCommitContext) {
	spt.stateProofVerificationMu.Lock()
	defer spt.stateProofVerificationMu.Unlock()

	spt.trackedFirstStageData = spt.trackedFirstStageData[len(dcc.stateProofFirstStageCommitData):]
	spt.trackedSecondStageData = spt.trackedSecondStageData[len(dcc.stateProofSecondStageCommitData):]
	spt.trackedDeleteData = spt.trackedDeleteData[dcc.stateProofVerificationLatestDeleteDataIndex+1:]
}

func (spt *stateProofVerificationTracker) postCommitUnlocked(context.Context, *deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) handleUnorderedCommit(*deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) close() {
	if spt.dbQueries.lookupStateProofFirstStageData != nil {
		spt.dbQueries.lookupStateProofFirstStageData.Close()
	}

	if spt.dbQueries.lookupStateProofSecondStageData != nil {
		spt.dbQueries.lookupStateProofSecondStageData.Close()
	}
}

func (spt *stateProofVerificationTracker) LookupVerificationData(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationData, error) {
	spt.stateProofVerificationMu.RLock()
	defer spt.stateProofVerificationMu.RUnlock()

	firstStage, err := spt.lookupFirstStage(stateProofLastAttestedRound)
	if err != nil {
		return nil, err
	}

	secondStage, err := spt.lookupSecondStage(stateProofLastAttestedRound)
	if err != nil {
		return nil, err
	}

	return &ledgercore.StateProofVerificationData{
		StateProofFirstStageVerificationData:  *firstStage,
		StateProofSecondStageVerificationData: *secondStage,
	}, nil

}

func (spt *stateProofVerificationTracker) lookupFirstStage(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofFirstStageVerificationData, error) {
	if len(spt.trackedFirstStageData) > 0 && stateProofLastAttestedRound >= spt.trackedFirstStageData[0].firstStageVerificationData.TargetStateProofRound &&
		stateProofLastAttestedRound <= spt.trackedFirstStageData[len(spt.trackedFirstStageData)-1].firstStageVerificationData.TargetStateProofRound {
		return spt.lookupFirstStageDataInTrackedMemory(stateProofLastAttestedRound)
	}

	if len(spt.trackedFirstStageData) == 0 || stateProofLastAttestedRound < spt.trackedFirstStageData[0].firstStageVerificationData.TargetStateProofRound {
		verificationData, err := spt.dbQueries.lookupFirstStageStateProofVerification(stateProofLastAttestedRound)
		if err != nil {
			return &ledgercore.StateProofFirstStageVerificationData{}, fmt.Errorf("%w for round %d: %s", errStateProofVerificationDataNotFound, stateProofLastAttestedRound, err)
		}
		return verificationData, nil
	}

	return &ledgercore.StateProofFirstStageVerificationData{}, fmt.Errorf("requested data for round %d, greater than maximum data round %d: %w",
		stateProofLastAttestedRound,
		spt.trackedFirstStageData[len(spt.trackedFirstStageData)-1].firstStageVerificationData.TargetStateProofRound,
		errStateProofVerificationDataNotFound)
}

func (spt *stateProofVerificationTracker) lookupSecondStage(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofSecondStageVerificationData, error) {
	if len(spt.trackedSecondStageData) > 0 && stateProofLastAttestedRound >= spt.trackedSecondStageData[0].confirmedRound &&
		stateProofLastAttestedRound <= spt.trackedSecondStageData[len(spt.trackedSecondStageData)-1].confirmedRound {
		return spt.lookupSecondStageDataInTrackedMemory(stateProofLastAttestedRound)
	}

	if len(spt.trackedSecondStageData) == 0 || stateProofLastAttestedRound < spt.trackedSecondStageData[0].confirmedRound {
		secondStageData, err := spt.dbQueries.lookupSecondStageStateProofVerification(stateProofLastAttestedRound)
		if err != nil {
			return &ledgercore.StateProofSecondStageVerificationData{}, fmt.Errorf("%w for round %d: %s", errStateProofVerificationDataNotFound, stateProofLastAttestedRound, err)
		}
		return secondStageData, nil
	}

	return &ledgercore.StateProofSecondStageVerificationData{}, fmt.Errorf("requested second stage data for round %d could not be found: %w",
		stateProofLastAttestedRound,
		errStateProofVerificationDataNotFound)
}

func (spt *stateProofVerificationTracker) lookupFirstStageDataInTrackedMemory(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofFirstStageVerificationData, error) {
	for _, commitData := range spt.trackedFirstStageData {
		if commitData.firstStageVerificationData.TargetStateProofRound == stateProofLastAttestedRound {
			verificationDataCopy := commitData.firstStageVerificationData
			return &verificationDataCopy, nil
		}
	}

	return &ledgercore.StateProofFirstStageVerificationData{}, fmt.Errorf("%w for round %d: memory lookup failed",
		errStateProofVerificationDataNotFound, stateProofLastAttestedRound)
}

func (spt *stateProofVerificationTracker) lookupSecondStageDataInTrackedMemory(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofSecondStageVerificationData, error) {
	for _, commitData := range spt.trackedSecondStageData {
		if commitData.confirmedRound == stateProofLastAttestedRound {
			secondStageDataCopy := commitData.secondStageVerificationData
			return &secondStageDataCopy, nil
		}
	}

	return &ledgercore.StateProofSecondStageVerificationData{}, fmt.Errorf("%w for round %d: second stage memory lookup failed",
		errStateProofVerificationDataNotFound, stateProofLastAttestedRound)
}

func (spt *stateProofVerificationTracker) committedRoundToLatestSecondStageDataIndex(committedRound basics.Round) int {
	latestCommittedUpdateIndex := -1

	for index, data := range spt.trackedSecondStageData {
		if data.confirmedRound <= committedRound {
			latestCommittedUpdateIndex = index
		} else {
			break
		}
	}

	return latestCommittedUpdateIndex
}

func (spt *stateProofVerificationTracker) committedRoundToLatestCommitDataIndex(committedRound basics.Round) int {
	latestCommittedDataIndex := -1

	for index, data := range spt.trackedFirstStageData {
		if data.confirmedRound <= committedRound {
			latestCommittedDataIndex = index
		} else {
			break
		}
	}

	return latestCommittedDataIndex
}

func (spt *stateProofVerificationTracker) committedRoundToLatestDeleteDataIndex(committedRound basics.Round) int {
	latestCommittedDataIndex := -1

	for index, data := range spt.trackedDeleteData {
		if data.confirmedRound <= committedRound {
			latestCommittedDataIndex = index
		} else {
			break
		}
	}

	return latestCommittedDataIndex
}

func (spt *stateProofVerificationTracker) insertFirstStageCommitData(blk *bookkeeping.Block) {
	spt.stateProofVerificationMu.Lock()
	defer spt.stateProofVerificationMu.Unlock()

	if len(spt.trackedFirstStageData) > 0 {
		lastCommitConfirmedRound := spt.trackedFirstStageData[len(spt.trackedFirstStageData)-1].confirmedRound
		if blk.Round() <= lastCommitConfirmedRound {
			spt.log.Panicf("state proof verification: attempted to insert commit data confirmed earlier than latest"+
				"commit data, round: %d, last confirmed commit data round: %d", blk.Round(), lastCommitConfirmedRound)
		}
	}

	verificationData := ledgercore.StateProofFirstStageVerificationData{
		VotersCommitment:      blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		OnlineTotalWeight:     blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
		TargetStateProofRound: blk.Round() + basics.Round(blk.ConsensusProtocol().StateProofInterval),
	}

	commitData := verificationCommitData{
		confirmedRound:             blk.Round(),
		firstStageVerificationData: verificationData,
	}

	spt.trackedFirstStageData = append(spt.trackedFirstStageData, commitData)
}

func (spt *stateProofVerificationTracker) insertSecondStageCommitData(blk *bookkeeping.Block) {
	spt.stateProofVerificationMu.Lock()
	defer spt.stateProofVerificationMu.Unlock()

	if len(spt.trackedSecondStageData) > 0 {
		lastUpdateRound := spt.trackedSecondStageData[len(spt.trackedSecondStageData)-1].confirmedRound
		if blk.Round() <= lastUpdateRound {
			spt.log.Panicf("stateProofVerificationTracker: attempted to update commit data related to earlier than latest"+
				"update, round: %d, last update round: %d", blk.Round(), lastUpdateRound)
		}
	}

	update := verificationCommitUpdateData{
		confirmedRound:              blk.Round(),
		secondStageVerificationData: ledgercore.StateProofSecondStageVerificationData{Version: blk.CurrentProtocol},
	}

	spt.trackedSecondStageData = append(spt.trackedSecondStageData, update)
}

func (spt *stateProofVerificationTracker) insertDeleteData(blk *bookkeeping.Block, delta *ledgercore.StateDelta) {
	spt.stateProofVerificationMu.Lock()
	defer spt.stateProofVerificationMu.Unlock()

	if len(spt.trackedDeleteData) > 0 {
		lastDeleteConfirmedRound := spt.trackedDeleteData[len(spt.trackedDeleteData)-1].confirmedRound
		if blk.Round() <= lastDeleteConfirmedRound {
			spt.log.Panicf("state proof verification: attempted to insert delete data confirmed earlier than latest"+
				"delete data, round: %d, last confirmed delete data round: %d", blk.Round(), lastDeleteConfirmedRound)
		}
	}

	deletionData := verificationDeleteData{
		confirmedRound:      blk.Round(),
		stateProofNextRound: delta.StateProofNext,
	}

	spt.trackedDeleteData = append(spt.trackedDeleteData, deletionData)
}
