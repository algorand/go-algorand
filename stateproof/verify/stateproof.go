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

package verify

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errStateProofCrypto                 = errors.New("state proof crypto error")
	errStateProofParamCreation          = errors.New("state proof param creation error")
	errStateProofNotEnabled             = errors.New("state proofs are not enabled")
	errNotAtRightMultiple               = errors.New("state proof is not in a valid round multiple")
	errInvalidVotersRound               = errors.New("invalid voters round")
	errExpectedDifferentStateProofRound = errors.New("expected different state proof round")
	errInsufficientWeight               = errors.New("insufficient state proof weight")
)

// AcceptableStateProofWeight computes the acceptable signed weight
// of a state proof if it were to appear in a transaction with a
// particular firstValid round.  Earlier rounds require a smaller proof.
// votersHdr specifies the block that contains the vector commitment of
// the voters for this state proof (and thus the state proof is for the interval
// (votersHdr.Round(), votersHdr.Round()+StateProofInterval].
//
// logger must not be nil; use at least logging.Base()
func AcceptableStateProofWeight(votersHdr bookkeeping.BlockHeader, firstValid basics.Round, logger logging.Logger) uint64 {
	proto := config.Consensus[votersHdr.CurrentProtocol]
	latestRoundInProof := votersHdr.Round + basics.Round(proto.StateProofInterval)
	total := votersHdr.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight

	// The acceptable weight depends on the elapsed time (in rounds)
	// from the block we are trying to construct a proof for.
	// Start by subtracting the latest round number in the state proof interval.
	// If that round hasn't even passed yet, require 100% votes in proof.
	offset := firstValid.SubSaturate(latestRoundInProof)
	if offset == 0 {
		return total.ToUint64()
	}

	// During the first proto.StateProofInterval/2 blocks, the
	// signatures are still being broadcast, so, continue requiring
	// 100% votes.
	offset = offset.SubSaturate(basics.Round(proto.StateProofInterval / 2))
	if offset == 0 {
		return total.ToUint64()
	}

	// In the next proto.StateProofInterval/2 blocks, linearly scale
	// the acceptable weight from 100% to StateProofWeightThreshold.
	// If we are outside of that window, accept any weight at or above
	// StateProofWeightThreshold.
	provenWeight, overflowed := basics.Muldiv(total.ToUint64(), uint64(proto.StateProofWeightThreshold), 1<<32)
	if overflowed || provenWeight > total.ToUint64() {
		// Shouldn't happen, but a safe fallback is to accept a larger proof.
		logger.Warnf("AcceptableStateProofWeight(%d, %d, %d, %d) overflow provenWeight",
			total, proto.StateProofInterval, latestRoundInProof, firstValid)
		return 0
	}

	if offset >= basics.Round(proto.StateProofInterval/2) {
		return provenWeight
	}

	scaledWeight, overflowed := basics.Muldiv(total.ToUint64()-provenWeight, proto.StateProofInterval/2-uint64(offset), proto.StateProofInterval/2)
	if overflowed {
		// Shouldn't happen, but a safe fallback is to accept a larger state proof.
		logger.Warnf("AcceptableStateProofWeight(%d, %d, %d, %d) overflow scaledWeight",
			total, proto.StateProofInterval, latestRoundInProof, firstValid)
		return 0
	}

	w, overflowed := basics.OAdd(provenWeight, scaledWeight)
	if overflowed {
		// Shouldn't happen, but a safe fallback is to accept a larger state proof.
		logger.Warnf("AcceptableStateProofWeight(%d, %d, %d, %d) overflow provenWeight (%d) + scaledWeight (%d)",
			total, proto.StateProofInterval, latestRoundInProof, firstValid, provenWeight, scaledWeight)
		return 0
	}

	return w
}

// GetProvenWeight computes the parameters for building or verifying
// a state proof for the interval (votersHdr, latestRoundInProofHdr], using voters from block votersHdr.
func GetProvenWeight(votersHdr bookkeeping.BlockHeader, latestRoundInProofHdr bookkeeping.BlockHeader) (uint64, error) {
	proto := config.Consensus[votersHdr.CurrentProtocol]

	if proto.StateProofInterval == 0 {
		return 0, errStateProofNotEnabled
	}

	if votersHdr.Round%basics.Round(proto.StateProofInterval) != 0 {
		err := fmt.Errorf("votersHdr %d not a multiple of %d",
			votersHdr.Round, proto.StateProofInterval)
		return 0, err
	}

	if latestRoundInProofHdr.Round != votersHdr.Round+basics.Round(proto.StateProofInterval) {
		err := fmt.Errorf("certifying block %d not %d ahead of voters %d",
			latestRoundInProofHdr.Round, proto.StateProofInterval, votersHdr.Round)
		return 0, err
	}

	totalWeight := votersHdr.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight.ToUint64()
	provenWeight, overflowed := basics.Muldiv(totalWeight, uint64(proto.StateProofWeightThreshold), 1<<32)
	if overflowed {
		err := fmt.Errorf("overflow computing provenWeight[%d]: %d * %d / (1<<32)",
			latestRoundInProofHdr.Round, totalWeight, proto.StateProofWeightThreshold)
		return 0, err
	}

	return provenWeight, nil
}

// ValidateStateProof checks that a state proof is valid.
func ValidateStateProof(latestRoundInIntervalHdr *bookkeeping.BlockHeader, stateProof *stateproof.StateProof, votersHdr *bookkeeping.BlockHeader, nextStateProofRnd basics.Round, atRound basics.Round, msg *stateproofmsg.Message) error {
	proto := config.Consensus[latestRoundInIntervalHdr.CurrentProtocol]

	if proto.StateProofInterval == 0 {
		return fmt.Errorf("rounds = %d: %w", proto.StateProofInterval, errStateProofNotEnabled)
	}

	if latestRoundInIntervalHdr.Round%basics.Round(proto.StateProofInterval) != 0 {
		return fmt.Errorf("state proof at %d for non-multiple of %d: %w", latestRoundInIntervalHdr.Round, proto.StateProofInterval, errNotAtRightMultiple)
	}

	votersRound := latestRoundInIntervalHdr.Round.SubSaturate(basics.Round(proto.StateProofInterval))
	if votersRound != votersHdr.Round {
		return fmt.Errorf("new state proof is for %d (voters %d), but votersHdr from %d: %w",
			latestRoundInIntervalHdr.Round, votersRound, votersHdr.Round, errInvalidVotersRound)
	}

	if nextStateProofRnd == 0 || nextStateProofRnd != latestRoundInIntervalHdr.Round {
		return fmt.Errorf("expecting state proof for %d, but new state proof is for %d (voters %d):%w",
			nextStateProofRnd, latestRoundInIntervalHdr.Round, votersRound, errExpectedDifferentStateProofRound)
	}

	acceptableWeight := AcceptableStateProofWeight(*votersHdr, atRound, logging.Base())
	if stateProof.SignedWeight < acceptableWeight {
		return fmt.Errorf("insufficient weight at round %d: %d < %d: %w",
			atRound, stateProof.SignedWeight, acceptableWeight, errInsufficientWeight)
	}

	provenWeight, err := GetProvenWeight(*votersHdr, *latestRoundInIntervalHdr)
	if err != nil {
		return fmt.Errorf("%v: %w", err, errStateProofParamCreation)
	}

	verifier, err := stateproof.MkVerifier(votersHdr.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		provenWeight,
		config.Consensus[votersHdr.CurrentProtocol].StateProofStrengthTarget)
	if err != nil {
		return err
	}

	err = verifier.Verify(uint64(latestRoundInIntervalHdr.Round), msg.Hash(), stateProof)
	if err != nil {
		return fmt.Errorf("%v: %w", err, errStateProofCrypto)
	}
	return nil
}
