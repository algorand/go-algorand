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
	confirmedRound   basics.Round
	verificationData ledgercore.SPVerificationContext
}

// stateProofVerificationTracker is in charge of tracking data required to verify state proofs until such a time
// as the data is no longer needed.
type stateProofVerificationTracker struct {
	// dbQueries are the pre-generated queries used to query the database, if needed,
	// to lookup state proof verification data.
	dbQueries *stateProofVerificationDbQueries

	// trackedCommitData represents the part of the tracked verification data currently in memory. Each element in this
	// array contains both the data required to verify a single state proof and data to decide whether it's possible to
	// commit the verification data to the database.
	trackedCommitData []verificationCommitData

	// trackedDeleteData represents the data required to delete committed state proof verification data from the
	// database.
	trackedDeleteData []verificationDeleteData

	// mu protects trackedCommitData and trackedDeleteData.
	mu deadlock.RWMutex

	// log copied from ledger
	log logging.Logger
}

func (spt *stateProofVerificationTracker) loadFromDisk(l ledgerForTracker, _ basics.Round) error {
	preparedDbQueries, err := stateProofVerificationInitDbQueries(l.trackerDB().Rdb.Handle)
	if err != nil {
		return err
	}

	spt.dbQueries = preparedDbQueries

	spt.log = l.trackerLog()

	spt.mu.Lock()
	defer spt.mu.Unlock()

	const initialDataArraySize = 10
	spt.trackedCommitData = make([]verificationCommitData, 0, initialDataArraySize)
	spt.trackedDeleteData = make([]verificationDeleteData, 0, initialDataArraySize)

	return nil
}

func (spt *stateProofVerificationTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	currentStateProofInterval := basics.Round(blk.ConsensusProtocol().StateProofInterval)

	if currentStateProofInterval == 0 {
		return
	}

	if blk.Round()%currentStateProofInterval == 0 {
		spt.appendCommitData(&blk)
	}

	if delta.StateProofNext != 0 {
		spt.appendDeleteData(&blk, &delta)
	}
}

func (spt *stateProofVerificationTracker) committedUpTo(round basics.Round) (minRound, lookback basics.Round) {
	return round, 0
}

func (spt *stateProofVerificationTracker) produceCommittingTask(_ basics.Round, _ basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return dcr
}

func (spt *stateProofVerificationTracker) prepareCommit(dcc *deferredCommitContext) error {
	spt.mu.RLock()
	defer spt.mu.RUnlock()

	lastDataToCommitIndex := spt.committedRoundToLatestCommitDataIndex(dcc.newBase)
	dcc.stateProofVerification.CommitData = make([]verificationCommitData, lastDataToCommitIndex+1)
	copy(dcc.stateProofVerification.CommitData, spt.trackedCommitData[:lastDataToCommitIndex+1])

	dcc.stateProofVerification.LatestDeleteDataIndex = spt.committedRoundToLatestDeleteDataIndex(dcc.newBase)
	if dcc.stateProofVerification.LatestDeleteDataIndex > -1 {
		dcc.stateProofVerification.EarliestTrackStateProofRound = spt.trackedDeleteData[dcc.stateProofVerification.LatestDeleteDataIndex].stateProofNextRound
	}

	return nil
}

func (spt *stateProofVerificationTracker) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) (err error) {
	err = insertStateProofVerificationData(ctx, tx, dcc.stateProofVerification.CommitData)
	if err != nil {
		return err
	}

	if dcc.stateProofVerification.LatestDeleteDataIndex > -1 {
		err = deleteOldStateProofVerificationData(ctx, tx, dcc.stateProofVerification.EarliestTrackStateProofRound)
	}

	return err

}

func (spt *stateProofVerificationTracker) postCommit(_ context.Context, dcc *deferredCommitContext) {
	spt.mu.Lock()
	defer spt.mu.Unlock()

	spt.trackedCommitData = spt.trackedCommitData[len(dcc.stateProofVerification.CommitData):]
	spt.trackedDeleteData = spt.trackedDeleteData[dcc.stateProofVerification.LatestDeleteDataIndex+1:]
}

func (spt *stateProofVerificationTracker) postCommitUnlocked(context.Context, *deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) handleUnorderedCommit(*deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) close() {
	if spt.dbQueries != nil {
		spt.dbQueries.lookupStateProofVerificationData.Close()
		spt.dbQueries = nil
	}
}

func (spt *stateProofVerificationTracker) LookupVerificationData(stateProofLastAttestedRound basics.Round) (*ledgercore.SPVerificationContext, error) {
	spt.mu.RLock()
	defer spt.mu.RUnlock()

	if len(spt.trackedCommitData) > 0 && stateProofLastAttestedRound >= spt.trackedCommitData[0].verificationData.LastAttestedRound &&
		stateProofLastAttestedRound <= spt.trackedCommitData[len(spt.trackedCommitData)-1].verificationData.LastAttestedRound {
		return spt.lookupDataInTrackedMemory(stateProofLastAttestedRound)
	}

	if len(spt.trackedCommitData) == 0 || stateProofLastAttestedRound < spt.trackedCommitData[0].verificationData.LastAttestedRound {
		return spt.lookupDataInDB(stateProofLastAttestedRound)
	}

	return &ledgercore.SPVerificationContext{}, fmt.Errorf("requested data for round %d, greater than maximum data round %d: %w",
		stateProofLastAttestedRound,
		spt.trackedCommitData[len(spt.trackedCommitData)-1].verificationData.LastAttestedRound,
		errStateProofVerificationDataNotFound)
}

func (spt *stateProofVerificationTracker) lookupDataInTrackedMemory(stateProofLastAttestedRound basics.Round) (*ledgercore.SPVerificationContext, error) {
	for _, commitData := range spt.trackedCommitData {
		if commitData.verificationData.LastAttestedRound == stateProofLastAttestedRound {
			verificationDataCopy := commitData.verificationData
			return &verificationDataCopy, nil
		}
	}

	return &ledgercore.SPVerificationContext{}, fmt.Errorf("%w for round %d: memory lookup failed",
		errStateProofVerificationDataNotFound, stateProofLastAttestedRound)
}

func (spt *stateProofVerificationTracker) lookupDataInDB(stateProofLastAttestedRound basics.Round) (*ledgercore.SPVerificationContext, error) {
	verificationData, err := spt.dbQueries.lookupData(stateProofLastAttestedRound)
	if err != nil {
		err = fmt.Errorf("%w for round %d: %s", errStateProofVerificationDataNotFound, stateProofLastAttestedRound, err)
	}

	return verificationData, err
}

func (spt *stateProofVerificationTracker) committedRoundToLatestCommitDataIndex(committedRound basics.Round) int {
	latestCommittedDataIndex := -1

	for index, data := range spt.trackedCommitData {
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

func (spt *stateProofVerificationTracker) appendCommitData(blk *bookkeeping.Block) {
	spt.mu.Lock()
	defer spt.mu.Unlock()

	if len(spt.trackedCommitData) > 0 {
		lastCommitConfirmedRound := spt.trackedCommitData[len(spt.trackedCommitData)-1].confirmedRound
		if blk.Round() <= lastCommitConfirmedRound {
			spt.log.Panicf("state proof verification: attempted to append commit data confirmed earlier than latest"+
				"commit data, round: %d, last confirmed commit data round: %d", blk.Round(), lastCommitConfirmedRound)
		}
	}

	verificationData := ledgercore.SPVerificationContext{
		VotersCommitment:  blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		OnlineTotalWeight: blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
		LastAttestedRound: blk.Round() + basics.Round(blk.ConsensusProtocol().StateProofInterval),
		Version:           blk.CurrentProtocol,
	}

	commitData := verificationCommitData{
		confirmedRound:   blk.Round(),
		verificationData: verificationData,
	}

	spt.trackedCommitData = append(spt.trackedCommitData, commitData)
}

func (spt *stateProofVerificationTracker) appendDeleteData(blk *bookkeeping.Block, delta *ledgercore.StateDelta) {
	spt.mu.Lock()
	defer spt.mu.Unlock()

	if len(spt.trackedDeleteData) > 0 {
		lastDeleteConfirmedRound := spt.trackedDeleteData[len(spt.trackedDeleteData)-1].confirmedRound
		if blk.Round() <= lastDeleteConfirmedRound {
			spt.log.Panicf("state proof verification: attempted to append delete data confirmed earlier than latest"+
				"delete data, round: %d, last confirmed delete data round: %d", blk.Round(), lastDeleteConfirmedRound)
		}
	}

	deletionData := verificationDeleteData{
		confirmedRound:      blk.Round(),
		stateProofNextRound: delta.StateProofNext,
	}

	spt.trackedDeleteData = append(spt.trackedDeleteData, deletionData)
}
