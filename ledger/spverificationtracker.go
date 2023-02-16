// Copyright (C) 2019-2023 Algorand, Inc.
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
	"github.com/algorand/go-algorand/ledger/store"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errSPVerificationContextNotFound = errors.New("requested state proof verification context not found")
)

type verificationDeleteContext struct {
	confirmedRound      basics.Round
	stateProofNextRound basics.Round
}

type verificationCommitContext struct {
	confirmedRound      basics.Round
	verificationContext ledgercore.StateProofVerificationContext
}

// spVerificationTracker is in charge of tracking context required to verify state proofs until such a time
// as the context is no longer needed.
type spVerificationTracker struct {
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

	l ledgerForTracker

	// lastLookedUpVerificationContext should store the last verification context that was looked up.
	lastLookedUpVerificationContext ledgercore.StateProofVerificationContext
}

func (spt *spVerificationTracker) loadFromDisk(l ledgerForTracker, _ basics.Round) error {
	spt.log = l.trackerLog()
	spt.l = l

	spt.mu.Lock()
	defer spt.mu.Unlock()

	const initialContextArraySize = 10
	spt.trackedCommitContext = make([]verificationCommitContext, 0, initialContextArraySize)
	spt.trackedDeleteContext = make([]verificationDeleteContext, 0, initialContextArraySize)

	return nil
}

func (spt *spVerificationTracker) newBlock(blk bookkeeping.Block, delta ledgercore.StateDelta) {
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

func (spt *spVerificationTracker) committedUpTo(round basics.Round) (minRound, lookback basics.Round) {
	return round, 0
}

func (spt *spVerificationTracker) produceCommittingTask(_ basics.Round, _ basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return dcr
}

func (spt *spVerificationTracker) prepareCommit(dcc *deferredCommitContext) error {
	spt.mu.RLock()
	defer spt.mu.RUnlock()

	lastContextToCommitIndex := spt.roundToLatestCommitContextIndex(dcc.newBase())
	dcc.spVerification.CommitContext = make([]verificationCommitContext, lastContextToCommitIndex+1)
	copy(dcc.spVerification.CommitContext, spt.trackedCommitContext[:lastContextToCommitIndex+1])

	dcc.spVerification.LastDeleteIndex = spt.roundToLatestDeleteContextIndex(dcc.newBase())
	if dcc.spVerification.LastDeleteIndex >= 0 {
		dcc.spVerification.EarliestLastAttestedRound = spt.trackedDeleteContext[dcc.spVerification.LastDeleteIndex].stateProofNextRound
	}

	return nil
}

func (spt *spVerificationTracker) commitRound(ctx context.Context, tx *sql.Tx, dcc *deferredCommitContext) (err error) {
	if len(dcc.spVerification.CommitContext) != 0 {
		err = commitSPContexts(ctx, tx, dcc.spVerification.CommitContext)
		if err != nil {
			return err
		}
	}

	if dcc.spVerification.LastDeleteIndex >= 0 {
		err = store.CreateSPVerificationAccessor(tx).DeleteOldSPContexts(ctx, dcc.spVerification.EarliestLastAttestedRound)
	}

	return err
}

func commitSPContexts(ctx context.Context, tx *sql.Tx, commitData []verificationCommitContext) error {
	ptrToCtxs := make([]*ledgercore.StateProofVerificationContext, len(commitData))
	for i := 0; i < len(commitData); i++ {
		ptrToCtxs[i] = &commitData[i].verificationContext
	}

	return store.CreateSPVerificationAccessor(tx).StoreSPContexts(ctx, ptrToCtxs)
}

func (spt *spVerificationTracker) postCommit(_ context.Context, dcc *deferredCommitContext) {
	spt.mu.Lock()
	defer spt.mu.Unlock()

	spt.trackedCommitContext = spt.trackedCommitContext[len(dcc.spVerification.CommitContext):]
	spt.trackedDeleteContext = spt.trackedDeleteContext[dcc.spVerification.LastDeleteIndex+1:]
}

func (spt *spVerificationTracker) postCommitUnlocked(context.Context, *deferredCommitContext) {
}

func (spt *spVerificationTracker) handleUnorderedCommit(*deferredCommitContext) {
}

func (spt *spVerificationTracker) close() {
}

func (spt *spVerificationTracker) LookupVerificationContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	if lstlookup := spt.retrieveFromCache(stateProofLastAttestedRound); lstlookup != nil {
		return lstlookup, nil
	}

	verificationContext, err := spt.lookupVerificationContext(stateProofLastAttestedRound)
	if err != nil {
		return nil, err
	}

	// before return, update the cache
	spt.mu.Lock()
	spt.lastLookedUpVerificationContext = *verificationContext
	spt.mu.Unlock()

	return verificationContext, nil
}

func (spt *spVerificationTracker) retrieveFromCache(stateProofLastAttestedRound basics.Round) *ledgercore.StateProofVerificationContext {
	spt.mu.RLock()
	defer spt.mu.RUnlock()

	if spt.lastLookedUpVerificationContext.LastAttestedRound == stateProofLastAttestedRound &&
		!spt.lastLookedUpVerificationContext.MsgIsZero() {
		cpy := spt.lastLookedUpVerificationContext

		return &cpy
	}

	return nil
}

func (spt *spVerificationTracker) lookupVerificationContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	spt.mu.RLock()
	defer spt.mu.RUnlock()

	if len(spt.trackedCommitContext) > 0 &&
		stateProofLastAttestedRound >= spt.trackedCommitContext[0].verificationContext.LastAttestedRound &&
		stateProofLastAttestedRound <= spt.trackedCommitContext[len(spt.trackedCommitContext)-1].verificationContext.LastAttestedRound {
		return spt.lookupContextInTrackedMemory(stateProofLastAttestedRound)
	}

	if len(spt.trackedCommitContext) == 0 || stateProofLastAttestedRound < spt.trackedCommitContext[0].verificationContext.LastAttestedRound {
		return spt.lookupContextInDB(stateProofLastAttestedRound)
	}

	return &ledgercore.StateProofVerificationContext{}, fmt.Errorf("requested context for round %d, greater than maximum context round %d: %w",
		stateProofLastAttestedRound,
		spt.trackedCommitContext[len(spt.trackedCommitContext)-1].verificationContext.LastAttestedRound,
		errSPVerificationContextNotFound)
}

func (spt *spVerificationTracker) lookupContextInTrackedMemory(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	for _, commitContext := range spt.trackedCommitContext {
		if commitContext.verificationContext.LastAttestedRound == stateProofLastAttestedRound {
			verificationContextCopy := commitContext.verificationContext
			return &verificationContextCopy, nil
		}
	}

	return &ledgercore.StateProofVerificationContext{}, fmt.Errorf("%w for round %d: memory lookup failed",
		errSPVerificationContextNotFound, stateProofLastAttestedRound)
}

func (spt *spVerificationTracker) lookupContextInDB(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error) {
	var spContext *ledgercore.StateProofVerificationContext
	err := spt.l.trackerDB().Snapshot(func(ctx context.Context, tx *sql.Tx) (err error) {
		spContext, err = store.CreateSPVerificationAccessor(tx).LookupSPContext(stateProofLastAttestedRound)
		if err != nil {
			err = fmt.Errorf("%w for round %d: %s", errSPVerificationContextNotFound, stateProofLastAttestedRound, err)
		}

		return err
	})

	return spContext, err
}

func (spt *spVerificationTracker) roundToLatestCommitContextIndex(committedRound basics.Round) int {
	latestCommittedContextIndex := -1

	for index, ctx := range spt.trackedCommitContext {
		if ctx.confirmedRound > committedRound {
			break
		}

		latestCommittedContextIndex = index
	}

	return latestCommittedContextIndex
}

func (spt *spVerificationTracker) roundToLatestDeleteContextIndex(committedRound basics.Round) int {
	latestCommittedContextIndex := -1

	for index, ctx := range spt.trackedDeleteContext {
		if ctx.confirmedRound > committedRound {
			break
		}

		latestCommittedContextIndex = index
	}

	return latestCommittedContextIndex
}

func getVerificationContext(blk *bookkeeping.Block) ledgercore.StateProofVerificationContext {
	return ledgercore.StateProofVerificationContext{
		VotersCommitment:  blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		OnlineTotalWeight: blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
		LastAttestedRound: blk.Round() + basics.Round(blk.ConsensusProtocol().StateProofInterval),
		Version:           blk.CurrentProtocol,
	}
}

func (spt *spVerificationTracker) appendCommitContext(blk *bookkeeping.Block) {
	spt.mu.Lock()
	defer spt.mu.Unlock()

	if len(spt.trackedCommitContext) > 0 {
		lastCommitConfirmedRound := spt.trackedCommitContext[len(spt.trackedCommitContext)-1].confirmedRound
		if blk.Round() <= lastCommitConfirmedRound {
			spt.log.Panicf("state proof verification: attempted to append commit context confirmed earlier than latest"+
				"commit context, round: %d, last confirmed commit context round: %d", blk.Round(), lastCommitConfirmedRound)
		}
	}

	commitContext := verificationCommitContext{
		confirmedRound:      blk.Round(),
		verificationContext: getVerificationContext(blk),
	}

	spt.trackedCommitContext = append(spt.trackedCommitContext, commitContext)
}

func (spt *spVerificationTracker) appendDeleteContext(blk *bookkeeping.Block, delta *ledgercore.StateDelta) {
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
