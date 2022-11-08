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
	errStateProofVerificationContextNotFound = errors.New("requested state proof verification context not found")
)

type verificationDeleteContext struct {
	confirmedRound      basics.Round
	stateProofNextRound basics.Round
}

type verificationCommitContext struct {
	confirmedRound      basics.Round
	verificationContext ledgercore.StateProofVerificationContext
}

// stateProofVerificationTracker is in charge of tracking context required to verify state proofs until such a time
// as the context is no longer needed.
type stateProofVerificationTracker struct {
	// dbQueries are the pre-generated queries used to query the database, if needed,
	// to lookup state proof verification context.
	dbQueries *stateProofVerificationDbQueries

	// trackedCommitContext represents the part of the tracked verification context currently in memory. Each element in this
	// array contains both the context required to verify a single state proof and context to decide whether it's possible to
	// commit the verification context to the database.
	trackedCommitContext []verificationCommitContext

	// trackedDeleteContext represents the context required to delete committed state proof verification context from the
	// database.
	trackedDeleteContext []verificationDeleteContext

	// mu protects trackedCommitContext and trackedDeleteContext.
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

	const initialContextArraySize = 10
	spt.trackedCommitContext = make([]verificationCommitContext, 0, initialContextArraySize)
	spt.trackedDeleteContext = make([]verificationDeleteContext, 0, initialContextArraySize)

	return nil
}

func (spt *stateProofVerificationTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
	currentStateProofInterval := basics.Round(blk.ConsensusProtocol().StateProofInterval)

	if currentStateProofInterval == 0 {
		return
	}

	if blk.Round()%currentStateProofInterval == 0 {
		spt.appendCommitContext(&blk)
	}

	if delta.StateProofNext != 0 {
		spt.appendDeleteContext(&blk, &delta)
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

	lastContextToCommitIndex := spt.committedRoundToLatestCommitContextIndex(dcc.newBase)
	dcc.spVerification.CommitContext = make([]verificationCommitContext, lastContextToCommitIndex+1)
	copy(dcc.spVerification.CommitContext, spt.trackedCommitContext[:lastContextToCommitIndex+1])

	dcc.spVerification.LatestUsedDeleteContextIndex = spt.committedRoundToLatestDeleteContextIndex(dcc.newBase)
	if dcc.spVerification.LatestUsedDeleteContextIndex >= 0 {
		dcc.spVerification.EarliestTrackStateProofRound = spt.trackedDeleteContext[dcc.spVerification.LatestUsedDeleteContextIndex].stateProofNextRound
	}

	return nil
}

func (spt *stateProofVerificationTracker) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) (err error) {
	err = insertStateProofVerificationContext(ctx, tx, dcc.spVerification.CommitContext)
	if err != nil {
		return err
	}

	if dcc.spVerification.LatestUsedDeleteContextIndex >= 0 {
		err = deleteOldStateProofVerificationContext(ctx, tx, dcc.spVerification.EarliestTrackStateProofRound)
	}

	return err

}

func (spt *stateProofVerificationTracker) postCommit(_ context.Context, dcc *deferredCommitContext) {
	spt.mu.Lock()
	defer spt.mu.Unlock()

	spt.trackedCommitContext = spt.trackedCommitContext[len(dcc.spVerification.CommitContext):]
	spt.trackedDeleteContext = spt.trackedDeleteContext[dcc.spVerification.LatestUsedDeleteContextIndex+1:]
}

func (spt *stateProofVerificationTracker) postCommitUnlocked(context.Context, *deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) handleUnorderedCommit(*deferredCommitContext) {

}

func (spt *stateProofVerificationTracker) close() {
	if spt.dbQueries != nil {
		spt.dbQueries.lookupStateProofVerificationContext.Close()
		spt.dbQueries = nil
	}
}

func (spt *stateProofVerificationTracker) LookupVerificationContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	spt.mu.RLock()
	defer spt.mu.RUnlock()

	if len(spt.trackedCommitContext) > 0 && stateProofLastAttestedRound >= spt.trackedCommitContext[0].verificationContext.LastAttestedRound &&
		stateProofLastAttestedRound <= spt.trackedCommitContext[len(spt.trackedCommitContext)-1].verificationContext.LastAttestedRound {
		return spt.lookupContextInTrackedMemory(stateProofLastAttestedRound)
	}

	if len(spt.trackedCommitContext) == 0 || stateProofLastAttestedRound < spt.trackedCommitContext[0].verificationContext.LastAttestedRound {
		return spt.lookupContextInDB(stateProofLastAttestedRound)
	}

	return &ledgercore.StateProofVerificationContext{}, fmt.Errorf("requested context for round %d, greater than maximum context round %d: %w",
		stateProofLastAttestedRound,
		spt.trackedCommitContext[len(spt.trackedCommitContext)-1].verificationContext.LastAttestedRound,
		errStateProofVerificationContextNotFound)
}

func (spt *stateProofVerificationTracker) lookupContextInTrackedMemory(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	for _, commitContext := range spt.trackedCommitContext {
		if commitContext.verificationContext.LastAttestedRound == stateProofLastAttestedRound {
			verificationContextCopy := commitContext.verificationContext
			return &verificationContextCopy, nil
		}
	}

	return &ledgercore.StateProofVerificationContext{}, fmt.Errorf("%w for round %d: memory lookup failed",
		errStateProofVerificationContextNotFound, stateProofLastAttestedRound)
}

func (spt *stateProofVerificationTracker) lookupContextInDB(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	verificationContext, err := spt.dbQueries.lookupContext(stateProofLastAttestedRound)
	if err != nil {
		err = fmt.Errorf("%w for round %d: %s", errStateProofVerificationContextNotFound, stateProofLastAttestedRound, err)
	}

	return verificationContext, err
}

func (spt *stateProofVerificationTracker) committedRoundToLatestCommitContextIndex(committedRound basics.Round) int {
	latestCommittedContextIndex := -1

	for index, ctx := range spt.trackedCommitContext {
		if ctx.confirmedRound <= committedRound {
			latestCommittedContextIndex = index
		} else {
			break
		}
	}

	return latestCommittedContextIndex
}

func (spt *stateProofVerificationTracker) committedRoundToLatestDeleteContextIndex(committedRound basics.Round) int {
	latestCommittedContextIndex := -1

	for index, ctx := range spt.trackedDeleteContext {
		if ctx.confirmedRound <= committedRound {
			latestCommittedContextIndex = index
		} else {
			break
		}
	}

	return latestCommittedContextIndex
}

func (spt *stateProofVerificationTracker) appendCommitContext(blk *bookkeeping.Block) {
	spt.mu.Lock()
	defer spt.mu.Unlock()

	if len(spt.trackedCommitContext) > 0 {
		lastCommitConfirmedRound := spt.trackedCommitContext[len(spt.trackedCommitContext)-1].confirmedRound
		if blk.Round() <= lastCommitConfirmedRound {
			spt.log.Panicf("state proof verification: attempted to append commit context confirmed earlier than latest"+
				"commit context, round: %d, last confirmed commit context round: %d", blk.Round(), lastCommitConfirmedRound)
		}
	}

	verificationContext := ledgercore.StateProofVerificationContext{
		VotersCommitment:  blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		OnlineTotalWeight: blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
		LastAttestedRound: blk.Round() + basics.Round(blk.ConsensusProtocol().StateProofInterval),
		Version:           blk.CurrentProtocol,
	}

	commitContext := verificationCommitContext{
		confirmedRound:      blk.Round(),
		verificationContext: verificationContext,
	}

	spt.trackedCommitContext = append(spt.trackedCommitContext, commitContext)
}

func (spt *stateProofVerificationTracker) appendDeleteContext(blk *bookkeeping.Block, delta *ledgercore.StateDelta) {
	spt.mu.Lock()
	defer spt.mu.Unlock()

	if len(spt.trackedDeleteContext) > 0 {
		lastDeleteConfirmedRound := spt.trackedDeleteContext[len(spt.trackedDeleteContext)-1].confirmedRound
		if blk.Round() <= lastDeleteConfirmedRound {
			spt.log.Panicf("state proof verification: attempted to append delete context confirmed earlier than latest"+
				"delete context, round: %d, last confirmed delete context round: %d", blk.Round(), lastDeleteConfirmedRound)
		}
	}

	deletionContext := verificationDeleteContext{
		confirmedRound:      blk.Round(),
		stateProofNextRound: delta.StateProofNext,
	}

	spt.trackedDeleteContext = append(spt.trackedDeleteContext, deletionContext)
}
