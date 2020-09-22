// Copyright (C) 2019-2020 Algorand, Inc.
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
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
)

// AcceptableCompactCertWeight computes the acceptable signed weight
// of a compact cert if it were to appear in a transaction with a
// particular firstValid round.  Earlier rounds require a smaller cert.
// votersHdr specifies the block that contains the Merkle commitment of
// the voters for this compact cert (and thus the compact cert is for
// votersHdr.Round() + CompactCertRounds).
func AcceptableCompactCertWeight(votersHdr bookkeeping.BlockHeader, firstValid basics.Round) uint64 {
	proto := config.Consensus[votersHdr.CurrentProtocol]
	certRound := votersHdr.Round + basics.Round(proto.CompactCertRounds)
	total := votersHdr.CompactCertVotersTotal

	// The acceptable weight depends on the elapsed time (in rounds)
	// from the block we are trying to construct a certificate for.
	// Start by subtracting the round number of the block being certified.
	// If that round hasn't even passed yet, require 100% votes in cert.
	offset := firstValid.SubSaturate(certRound)
	if offset == 0 {
		return total.ToUint64()
	}

	// During the first proto.CompactCertRound/2 + 1 + 1 blocks, the
	// signatures are still being broadcast, so, continue requiring
	// 100% votes.
	//
	// The first +1 comes from CompactCertWorker.broadcastSigs: it only
	// broadcasts signatures for round R starting with round R+1, to
	// ensure nodes have the block for round R already in their ledger,
	// to check the sig.
	//
	// The second +1 comes from the fact that, if we are checking this
	// acceptable weight to decide whether to allow this transaction in
	// a block, the transaction was sent out one round ago.
	offset = offset.SubSaturate(basics.Round(proto.CompactCertRounds/2 + 2))
	if offset == 0 {
		return total.ToUint64()
	}

	// In the next proto.CompactCertRounds/2 blocks, linearly scale
	// the acceptable weight from 100% to 0%.  If we are outside of
	// that window, accept any weight.
	if offset >= basics.Round(proto.CompactCertRounds/2) {
		return 0
	}

	w, overflowed := basics.Muldiv(total.ToUint64(), proto.CompactCertRounds/2-uint64(offset), proto.CompactCertRounds/2)
	if overflowed {
		// Shouldn't happen, but a safe fallback is to accept a larger cert.
		logging.Base().Warnf("AcceptableCompactCertWeight(%d, %d, %d, %d) overflow",
			total, proto.CompactCertRounds, certRound, firstValid)
		return 0
	}

	return w
}

// CompactCertParams computes the parameters for building or verifying
// a compact cert for block hdr, using voters from block votersHdr.
func CompactCertParams(votersHdr bookkeeping.BlockHeader, hdr bookkeeping.BlockHeader) (res compactcert.Params, err error) {
	proto := config.Consensus[votersHdr.CurrentProtocol]

	if proto.CompactCertRounds == 0 {
		err = fmt.Errorf("compact certs not enabled")
		return
	}

	if votersHdr.Round%basics.Round(proto.CompactCertRounds) != 0 {
		err = fmt.Errorf("votersHdr %d not a multiple of %d",
			votersHdr.Round, proto.CompactCertRounds)
		return
	}

	if hdr.Round != votersHdr.Round+basics.Round(proto.CompactCertRounds) {
		err = fmt.Errorf("certifying block %d not %d ahead of voters %d",
			hdr.Round, proto.CompactCertRounds, votersHdr.Round)
		return
	}

	totalWeight := votersHdr.CompactCertVotersTotal.ToUint64()
	provenWeight, overflowed := basics.Muldiv(totalWeight, proto.CompactCertWeightThreshold, 100)
	if overflowed {
		err = fmt.Errorf("overflow computing provenWeight[%d]: %d * %d / 100",
			hdr.Round, totalWeight, proto.CompactCertWeightThreshold)
		return
	}

	res = compactcert.Params{
		Msg:          hdr,
		ProvenWeight: provenWeight,
		SigRound:     hdr.Round + 1,
		SecKQ:        proto.CompactCertSecKQ,
	}
	return
}

// validateCompactCert checks that a compact cert is valid.
func validateCompactCert(certHdr bookkeeping.BlockHeader, cert compactcert.Cert, votersHdr bookkeeping.BlockHeader, lastCertRnd basics.Round, atRound basics.Round) error {
	proto := config.Consensus[certHdr.CurrentProtocol]

	if proto.CompactCertRounds == 0 {
		return fmt.Errorf("compact certs not enabled: rounds = %d", proto.CompactCertRounds)
	}

	if certHdr.Round%basics.Round(proto.CompactCertRounds) != 0 {
		return fmt.Errorf("cert at %d for non-multiple of %d", certHdr.Round, proto.CompactCertRounds)
	}

	votersRound := certHdr.Round.SubSaturate(basics.Round(proto.CompactCertRounds))
	if votersRound != votersHdr.Round {
		return fmt.Errorf("new cert is for %d (voters %d), but votersHdr from %d",
			certHdr.Round, votersRound, votersHdr.Round)
	}

	if lastCertRnd != 0 && lastCertRnd != votersRound {
		return fmt.Errorf("last cert from %d, but new cert is for %d (voters %d)",
			lastCertRnd, certHdr.Round, votersRound)
	}

	acceptableWeight := AcceptableCompactCertWeight(votersHdr, atRound)
	if cert.SignedWeight < acceptableWeight {
		return fmt.Errorf("insufficient weight at %d: %d < %d",
			atRound, cert.SignedWeight, acceptableWeight)
	}

	ccParams, err := CompactCertParams(votersHdr, certHdr)
	if err != nil {
		return err
	}

	verif := compactcert.MkVerifier(ccParams, votersHdr.CompactCertVoters)
	return verif.Verify(&cert)
}
