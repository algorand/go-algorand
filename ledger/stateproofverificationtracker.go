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
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

type stateProofVerificationData struct {
	VotersCommitment crypto.GenericDigest
	ProvenWeight     basics.MicroAlgos
}

type stateProofVerificationTracker struct {
	earliestLastAttestedRound basics.Round
	trackedData               []stateProofVerificationData
}

// TODO: What if the interval changes?
func (spt *stateProofVerificationTracker) roundToTrackedIndex(round basics.Round) uint64 {
	return uint64(round.SubSaturate(spt.earliestLastAttestedRound)) / config.Consensus[protocol.ConsensusCurrentVersion].StateProofInterval
}

func (spt *stateProofVerificationTracker) removeOlder(lastAttestedRound basics.Round) {
	if lastAttestedRound <= spt.earliestLastAttestedRound {
		return
	}

	// TODO: zero some elements?
	trackedIndex := spt.roundToTrackedIndex(lastAttestedRound)

	spt.trackedData = spt.trackedData[trackedIndex:]
	spt.earliestLastAttestedRound = lastAttestedRound
}

func (spt *stateProofVerificationTracker) loadFromDisk(ledgerForTracker, basics.Round) error {
	// TODO: Decide on slice size
	spt.trackedData = make([]stateProofVerificationData, 0, 1000)
	return nil
}

func (spt *stateProofVerificationTracker) newBlock(blk bookkeeping.Block, _ ledgercore.StateDelta) {
	if blk.ConsensusProtocol().StateProofInterval == 0 {
		return
	}

	if uint64(blk.Round())%blk.ConsensusProtocol().StateProofInterval == 0 {
		verificationData := stateProofVerificationData{
			VotersCommitment: blk.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
			ProvenWeight:     blk.StateProofTracking[protocol.StateProofBasic].StateProofOnlineTotalWeight,
		}
		spt.trackedData = append(spt.trackedData, verificationData)
	}

	lastAttestedRound := blk.StateProofTracking[protocol.StateProofBasic].StateProofNextRound.SubSaturate(
		basics.Round(blk.ConsensusProtocol().StateProofInterval))

	spt.removeOlder(lastAttestedRound)
}

func (spt *stateProofVerificationTracker) committedUpTo(round basics.Round) (minRound, lookback basics.Round) {
	return round, 0
}

func (spt *stateProofVerificationTracker) produceCommittingTask(committedRound basics.Round, dbRound basics.Round, dcr *deferredCommitRange) *deferredCommitRange {
	return dcr
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
