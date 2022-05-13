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

package internal

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// AcceptableCompactCertWeight computes the acceptable signed weight
// of a compact cert if it were to appear in a transaction with a
// particular firstValid round.  Earlier rounds require a smaller cert.
// votersHdr specifies the block that contains the Merkle commitment of
// the voters for this compact cert (and thus the compact cert is for
// votersHdr.Round() + StateProofInterval).
//
// logger must not be nil; use at least logging.Base()
func AcceptableCompactCertWeight(votersHdr bookkeeping.BlockHeader, firstValid basics.Round, logger logging.Logger) uint64 {
	proto := config.Consensus[votersHdr.CurrentProtocol]
	certRound := votersHdr.Round + basics.Round(proto.StateProofInterval)
	total := votersHdr.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight

	// The acceptable weight depends on the elapsed time (in rounds)
	// from the block we are trying to construct a certificate for.
	// Start by subtracting the round number of the block being certified.
	// If that round hasn't even passed yet, require 100% votes in cert.
	offset := firstValid.SubSaturate(certRound)
	if offset == 0 {
		return total.ToUint64()
	}

	// During the first proto.CompactCertRound/2 blocks, the
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
		// Shouldn't happen, but a safe fallback is to accept a larger cert.
		logger.Warnf("AcceptableCompactCertWeight(%d, %d, %d, %d) overflow provenWeight",
			total, proto.StateProofInterval, certRound, firstValid)
		return 0
	}

	if offset >= basics.Round(proto.StateProofInterval/2) {
		return provenWeight
	}

	scaledWeight, overflowed := basics.Muldiv(total.ToUint64()-provenWeight, proto.StateProofInterval/2-uint64(offset), proto.StateProofInterval/2)
	if overflowed {
		// Shouldn't happen, but a safe fallback is to accept a larger cert.
		logger.Warnf("AcceptableCompactCertWeight(%d, %d, %d, %d) overflow scaledWeight",
			total, proto.StateProofInterval, certRound, firstValid)
		return 0
	}

	w, overflowed := basics.OAdd(provenWeight, scaledWeight)
	if overflowed {
		// Shouldn't happen, but a safe fallback is to accept a larger cert.
		logger.Warnf("AcceptableCompactCertWeight(%d, %d, %d, %d) overflow provenWeight (%d) + scaledWeight (%d)",
			total, proto.StateProofInterval, certRound, firstValid, provenWeight, scaledWeight)
		return 0
	}

	return w
}

// GetProvenWeight computes the parameters for building or verifying
// a compact cert for block hdr, using voters from block votersHdr.
func GetProvenWeight(votersHdr bookkeeping.BlockHeader, hdr bookkeeping.BlockHeader) (uint64, error) {
	proto := config.Consensus[votersHdr.CurrentProtocol]

	if proto.StateProofInterval == 0 {
		err := fmt.Errorf("compact certs not enabled")
		return 0, err
	}

	if votersHdr.Round%basics.Round(proto.StateProofInterval) != 0 {
		err := fmt.Errorf("votersHdr %d not a multiple of %d",
			votersHdr.Round, proto.StateProofInterval)
		return 0, err
	}

	if hdr.Round != votersHdr.Round+basics.Round(proto.StateProofInterval) {
		err := fmt.Errorf("certifying block %d not %d ahead of voters %d",
			hdr.Round, proto.StateProofInterval, votersHdr.Round)
		return 0, err
	}

	totalWeight := votersHdr.StateProofTracking[protocol.StateProofBasic].StateProofVotersTotalWeight.ToUint64()
	provenWeight, overflowed := basics.Muldiv(totalWeight, uint64(proto.StateProofWeightThreshold), 1<<32)
	if overflowed {
		err := fmt.Errorf("overflow computing provenWeight[%d]: %d * %d / (1<<32)",
			hdr.Round, totalWeight, proto.StateProofWeightThreshold)
		return 0, err
	}

	return provenWeight, nil
}

var (
	errCompCertCrypto             = errors.New("compactcert crypto error")
	errCompactCertParamCreation   = errors.New("compactcert param creation error")
	errCompCertNotEnabled         = errors.New("compact certs not enabled")
	errNotAtRightMultiple         = errors.New("cert is not in a valid round multiple")
	errInvalidVotersRound         = errors.New("invalid voters round")
	errExpectedDifferentCertRound = errors.New("expected different cert round")
	errInsufficientWeight         = errors.New("insufficient cert weight")
)

// validateCompactCert checks that a compact cert is valid.
func validateCompactCert(certHdr bookkeeping.BlockHeader, cert compactcert.Cert, votersHdr bookkeeping.BlockHeader, nextCertRnd basics.Round, atRound basics.Round, msg stateproofmsg.Message) error {
	proto := config.Consensus[certHdr.CurrentProtocol]

	if proto.StateProofInterval == 0 {
		return fmt.Errorf("rounds = %d: %w", proto.StateProofInterval, errCompCertNotEnabled)
	}

	if certHdr.Round%basics.Round(proto.StateProofInterval) != 0 {
		return fmt.Errorf("cert at %d for non-multiple of %d: %w", certHdr.Round, proto.StateProofInterval, errNotAtRightMultiple)
	}

	votersRound := certHdr.Round.SubSaturate(basics.Round(proto.StateProofInterval))
	if votersRound != votersHdr.Round {
		return fmt.Errorf("new cert is for %d (voters %d), but votersHdr from %d: %w",
			certHdr.Round, votersRound, votersHdr.Round, errInvalidVotersRound)
	}

	if nextCertRnd == 0 || nextCertRnd != certHdr.Round {
		return fmt.Errorf("expecting cert for %d, but new cert is for %d (voters %d):%w",
			nextCertRnd, certHdr.Round, votersRound, errExpectedDifferentCertRound)
	}

	acceptableWeight := AcceptableCompactCertWeight(votersHdr, atRound, logging.Base())
	if cert.SignedWeight < acceptableWeight {
		return fmt.Errorf("insufficient weight at round %d: %d < %d: %w",
			atRound, cert.SignedWeight, acceptableWeight, errInsufficientWeight)
	}

	provenWeight, err := GetProvenWeight(votersHdr, certHdr)
	if err != nil {
		return fmt.Errorf("%v: %w", err, errCompactCertParamCreation)
	}

	verifier, err := compactcert.MkVerifier(votersHdr.StateProofTracking[protocol.StateProofBasic].StateProofVotersCommitment,
		provenWeight,
		config.Consensus[votersHdr.CurrentProtocol].StateProofStrengthTarget)
	if err != nil {
		return err
	}

	err = verifier.Verify(uint64(certHdr.Round), msg.IntoStateProofMessageHash(), &cert)
	if err != nil {
		return fmt.Errorf("%v: %w", err, errCompCertCrypto)
	}
	return nil
}
