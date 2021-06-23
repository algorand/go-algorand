// Copyright (C) 2019-2021 Algorand, Inc.
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

package logspec

import (
	"encoding/json"
	"errors"
)

// AgreementType is an enum identifying a specific type of AgreementEvent
// TODO Maybe this should be called AgreementEventType, since these are not actually types of agreements
//go:generate stringer -type=AgreementType
type AgreementType int

const (
	// The Clock

	// RoundConcluded is emitted whenever
	// (1) the player receives a block B, and
	// (2) the player obtains proof of consensus on H(B).
	RoundConcluded AgreementType = iota
	// PeriodConcluded is emitted whenever a player receives a
	// threshold of soft- or next-votes for a hash H(B).
	PeriodConcluded
	// StepTimeout is emitted when a filtering, certifying, or recovery step times out.
	StepTimeout
	// RoundStart is emitted when a round starts
	RoundStart

	// External - Ledger

	// RoundInterrupted is emitted when the source is on round r,
	// and its ledger observes a block B and a proof of consensus on H(B) at r
	// independently of the agreement service.
	RoundInterrupted
	// RoundWaiting is emitted when the source receives a proof of
	// consensus on H(B) at round r but has not yet received B.
	RoundWaiting

	// Committability

	// ThresholdReached is emitted when the source observes that a threshold of votes
	// has been reached for a given value during some (round, period, step).
	ThresholdReached
	// BlockAssembled is emitted when the source receives all parts of a block.
	BlockAssembled
	// BlockCommittable is emitted when the source observes a
	// block B and a threshold of soft-votes for H(B).  It is
	// emitted at most once per period.
	BlockCommittable

	// Messages

	// ProposalAssembled is emitted when the source node finishes making proposals
	ProposalAssembled

	// ProposalBroadcast is emitted when the source creates a
	// proposal to be broadcasted during initial block proposal
	// (and not partition recovery).
	ProposalBroadcast
	// ProposalFrozen is emitted when the source fixes a leader credential.
	ProposalFrozen
	// ProposalAccepted is emitted when the source accepts a leader proposal.
	ProposalAccepted
	// ProposalRejected is emitted when the source rejects a leader proposal.
	ProposalRejected

	// BlockRejected is emitted when a block is rejected.
	// (Since fragmentation is not implemented currently,
	// BlockAssembled carries the same meaning as BlockAccepted.)
	BlockRejected
	// BlockResent is emitted when a whole proposal is relayed for partition recovery.
	BlockResent
	// BlockPipelined is emitted when a block is pipelined for
	// further processing.
	BlockPipelined

	// VoteAttest is emitted when the source commits to a vote.
	VoteAttest
	// VoteBroadcast is emitted when the source creates a set of
	// votes to be broadcasted.
	VoteBroadcast
	// VoteAccepted is emitted when the source accepts a vote.
	VoteAccepted
	// VoteRejected is emitted when the source rejects a vote.
	VoteRejected

	// BundleBroadcast is emitted when the source broadcasts a bundle.
	BundleBroadcast
	// BundleAccepted is emitted when the source accepts a bundle.
	BundleAccepted
	// BundleRejected is emitted when the source rejects a bundle.
	BundleRejected

	// Crashes

	// Restored is emitted after the source successfully restores state from disk.
	// This happens once during initialization.
	Restored
	// Persisted is emitted after the source persists state to disk.
	// This happens before any vote is (possibly) emitted.
	Persisted

	numAgreementTypes // keep this last
)

// AgreementEvent represents data corresponding to an event occurring during our agreement processing
type AgreementEvent struct {
	Event

	Type AgreementType

	// Round represents the current round of the source.
	Round uint64

	// Period represents the current period of the source.
	Period uint64

	// Step represents the current period of the source.
	Step uint64

	// Branch represents the digest of the previous block committed in the previous round.
	Branch string

	// Hash represents a context-dependent value.git
	// - RoundConcluded: the block hash on which consensus was reached
	// - PeriodConcluded: the starting value of the next round
	// - ThresholdReached: the hash for which a vote threshold was reached
	// - ProposalFrozen: the hash on which a proposal was frozen
	// - BlockAssembled: the hash of the block (proposal) that was assembled
	// - ProposalBroadcast/Accepted/Rejected/Resent: the hash of the proposal
	// - VoteBroadcast/Accepted/Rejected: the hash a vote endorses
	// - BundleBroadcast/Accepted/Rejected: the hash a bundle endorses
	// - RoundInterrupted: the bottom value
	// - AccountRegistered: the address of the account that was registered
	Hash string

	// Sender is set if this event relates directly to a proposal or vote.
	// It contains the address of the sender.
	Sender string

	// ObjectRound contains the (alleged) round of the sender
	// or the round at which a value obtained a threshold.
	// It is set when Sender is set or when a threshold is met.
	ObjectRound uint64

	// ObjectBranch contains the (alleged) prev branch of the sender.
	ObjectBranch string

	// ObjectPeriod contains the (alleged) period of the sender.
	// or the period at which a value obtained a threshold.
	// It is set when Sender is set or when a threshold is met.
	ObjectPeriod uint64

	// ObjectStep contains the (alleged) step of the sender.
	// or the step at which a value obtained a threshold.
	// It is set when Sender is set or when a threshold is met.
	ObjectStep uint64

	// Weight is only set on receiving a vote.
	// It contains the weight of the vote (given its credentials).
	Weight uint64

	// WeightTotal is only set on receiving a vote.
	// It contains the cumulative weight of the all votes received
	// for the (round, period, step) of the given vote.
	WeightTotal uint64
}

func agreementTypeFromString(s string) (AgreementType, bool) {
	for i := 0; i < int(numAgreementTypes); i++ {
		t := AgreementType(i)
		if t.String() == s {
			return t, true
		}
	}
	return 0, false
}

// UnmarshalJSON initializes the AgreementType from a JSON string contained in a byte buffer.
// An error is returned if a valid AgreementType can't be parsed from the buffer.
func (t *AgreementType) UnmarshalJSON(b []byte) error {
	var raw string
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	typeConst, ok := agreementTypeFromString(raw)
	if !ok {
		return errors.New("invalid AgreementType field")
	}

	*t = typeConst
	return nil
}
