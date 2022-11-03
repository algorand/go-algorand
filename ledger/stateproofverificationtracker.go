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
	verificationData ledgercore.StateProofVerificationData
}

// stateProofVerificationTracker is in charge of tracking data required to verify state proofs until such a time
// as the data is no longer needed.
type stateProofVerificationTracker struct {
	// dbQueries are the pre-generated queries used to query the database, if needed,
	// to lookup state proof verification data.
	dbQueries stateProofVerificationDbQueries

	// trackedCommitData represents the part of the tracked verification data currently in memory. Each element in this
	// array contains both the data required to verify a single state proof and data to decide whether it's possible to
	// commit the verification data to the database.
	trackedCommitData []verificationCommitData

	// trackedDeleteData represents the data required to delete committed state proof verification data from the
	// database.
	trackedDeleteData []verificationDeleteData

	// stateProofVerificationMu protects trackedCommitData and trackedDeleteData.
	stateProofVerificationMu deadlock.RWMutex

	// log copied from ledger
	log logging.Logger

	// latestStateProof stores the last state proof verification data seen by the tracker.
	latestStateProofVerificationData ledgercore.StateProofVerificationData
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
	spt.trackedCommitData = make([]verificationCommitData, 0, initialDataArraySize)
	spt.trackedDeleteData = make([]verificationDeleteData, 0, initialDataArraySize)

	// todo load latest from the DB.

	return nil
}

func (spt *stateProofVerificationTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	currentStateProofInterval := basics.Round(blk.ConsensusProtocol().StateProofInterval)

	if currentStateProofInterval == 0 {
		return
	}

	if blk.Round()%currentStateProofInterval == 0 {
		spt.insertCommitData(&blk)
		spt.cacheVerificationData(&blk)
	}

	if delta.StateProofNext != 0 {
		spt.insertDeleteData(&blk, &delta)
	}
}

func (spt *stateProofVerificationTracker) cacheVerificationData(blk *bookkeeping.Block) {
	spt.stateProofVerificationMu.Lock()
	spt.latestStateProofVerificationData = getVerificationData(blk)
	spt.stateProofVerificationMu.Unlock()
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
	if dcc.stateProofVerificationLatestDeleteDataIndex > -1 {
		dcc.stateProofVerificationEarliestTrackStateProofRound = spt.trackedDeleteData[dcc.stateProofVerificationLatestDeleteDataIndex].stateProofNextRound
	}

	return nil
}

func (spt *stateProofVerificationTracker) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) (err error) {
	err = insertStateProofVerificationData(ctx, tx, dcc.stateProofVerificationCommitData)
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

	spt.trackedCommitData = spt.trackedCommitData[len(dcc.stateProofVerificationCommitData):]
	spt.trackedDeleteData = spt.trackedDeleteData[dcc.stateProofVerificationLatestDeleteDataIndex+1:]
}

func (spt *stateProofVerificationTracker) postCommitUnlocked(context.Context, *deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) handleUnorderedCommit(*deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) close() {
	if spt.dbQueries.lookupStateProofVerificationData != nil {
		spt.dbQueries.lookupStateProofVerificationData.Close()
	}
}

func (spt *stateProofVerificationTracker) LookupVerificationData(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationData, error) {
	spt.stateProofVerificationMu.RLock()
	defer spt.stateProofVerificationMu.RUnlock()

	if len(spt.trackedCommitData) > 0 && stateProofLastAttestedRound >= spt.trackedCommitData[0].verificationData.TargetStateProofRound &&
		stateProofLastAttestedRound <= spt.trackedCommitData[len(spt.trackedCommitData)-1].verificationData.TargetStateProofRound {
		return spt.lookupDataInTrackedMemory(stateProofLastAttestedRound)
	}

	if len(spt.trackedCommitData) == 0 || stateProofLastAttestedRound < spt.trackedCommitData[0].verificationData.TargetStateProofRound {
		return spt.lookupDataInDB(stateProofLastAttestedRound)
	}

	return &ledgercore.StateProofVerificationData{}, fmt.Errorf("requested data for round %d, greater than maximum data round %d: %w",
		stateProofLastAttestedRound,
		spt.trackedCommitData[len(spt.trackedCommitData)-1].verificationData.TargetStateProofRound,
		errStateProofVerificationDataNotFound)
}

func (spt *stateProofVerificationTracker) lookupDataInTrackedMemory(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationData, error) {
	if spt.latestStateProofVerificationData.TargetStateProofRound == stateProofLastAttestedRound {
		return &spt.latestStateProofVerificationData, nil
	}

	for _, commitData := range spt.trackedCommitData {
		if commitData.verificationData.TargetStateProofRound == stateProofLastAttestedRound {
			verificationDataCopy := commitData.verificationData
			return &verificationDataCopy, nil
		}
	}

	return &ledgercore.StateProofVerificationData{}, fmt.Errorf("%w for round %d: memory lookup failed",
		errStateProofVerificationDataNotFound, stateProofLastAttestedRound)
}

func (spt *stateProofVerificationTracker) lookupDataInDB(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationData, error) {
	verificationData, err := spt.dbQueries.lookupData(stateProofLastAttestedRound)
	if err != nil {
		err = fmt.Errorf("%w for round %d: %s", errStateProofVerificationDataNotFound, stateProofLastAttestedRound, err)
	}

	return verificationData, err
}

func (spt *stateProofVerificationTracker) committedRoundToLatestCommitDataIndex(committedRound basics.Round) int {
	latestCommittedDataIndex := -1

	for index, data := range spt.trackedCommitData {
		if data.confirmedRound > committedRound {
			break
		}

		latestCommittedDataIndex = index
	}

	return latestCommittedDataIndex
}

func (spt *stateProofVerificationTracker) committedRoundToLatestDeleteDataIndex(committedRound basics.Round) int {
	latestCommittedDataIndex := -1

	for index, data := range spt.trackedDeleteData {
		if data.confirmedRound > committedRound {
			break
		}

		latestCommittedDataIndex = index
	}

	return latestCommittedDataIndex
}

func getVerificationData(blk *bookkeeping.Block) ledgercore.StateProofVerificationData {
	return ledgercore.StateProofVerificationData{
		VotersCommitment:      blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		OnlineTotalWeight:     blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
		TargetStateProofRound: blk.Round() + basics.Round(blk.ConsensusProtocol().StateProofInterval),
	}
}

func (spt *stateProofVerificationTracker) insertCommitData(blk *bookkeeping.Block) {
	spt.stateProofVerificationMu.Lock()
	defer spt.stateProofVerificationMu.Unlock()

	if len(spt.trackedCommitData) > 0 {
		lastCommitConfirmedRound := spt.trackedCommitData[len(spt.trackedCommitData)-1].confirmedRound
		if blk.Round() <= lastCommitConfirmedRound {
			spt.log.Panicf("state proof verification: attempted to insert commit data confirmed earlier than latest"+
				"commit data, round: %d, last confirmed commit data round: %d", blk.Round(), lastCommitConfirmedRound)
		}
	}

	commitData := verificationCommitData{
		confirmedRound:   blk.Round(),
		verificationData: getVerificationData(blk),
	}

	spt.trackedCommitData = append(spt.trackedCommitData, commitData)
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
