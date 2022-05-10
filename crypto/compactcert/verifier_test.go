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

package compactcert

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestVerifyRevelForEachPosition(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	p := generateCertForTesting(a)
	cert := p.cc

	verifier, err := MkVerifier(p.partCommitment, p.provenWeight, compactCertStrengthTargetForTests)
	a.NoError(err)

	err = verifier.Verify(compactCertRoundsForTests, p.data, &cert)
	a.NoError(err)

	for i := uint64(0); i < p.numberOfParticipnets; i++ {
		_, ok := cert.Reveals[i]
		if !ok {
			cert.PositionsToReveal[0] = i
			break
		}
	}

	verifier, err = MkVerifier(p.partCommitment, p.provenWeight, compactCertStrengthTargetForTests)
	a.NoError(err)

	err = verifier.Verify(compactCertRoundsForTests, p.data, &cert)
	a.ErrorIs(err, ErrNoRevealInPos)

}

// TestVerifyWrongCoinSlot this test makes sure that the verifier uses PositionsToReveal array, and opens reveals in a specific order
// In order to and trick the verifier we need to swap two positions in the PositionsToReveal so the coins will not match.
func TestVerifyWrongCoinSlot(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	p := generateCertForTesting(a)
	cert := p.cc
	verifier, err := MkVerifier(p.partCommitment, p.provenWeight, compactCertStrengthTargetForTests)
	a.NoError(err)

	err = verifier.Verify(compactCertRoundsForTests, p.data, &cert)
	a.NoError(err)

	// we need to find a reveal that will not match the first coin.
	// In order to accomplish that we will extract the first coin and find a reveals ( > 1, since index 0 will satisfy the verifier)
	// that doesn't match
	coinAt0 := cert.PositionsToReveal[0]
	choice := coinChoiceSeed{
		partCommitment: verifier.participantsCommitment,
		lnProvenWeight: verifier.lnProvenWeight,
		sigCommitment:  cert.SigCommit,
		signedWeight:   cert.SignedWeight,
		data:           p.data,
	}
	coinHash := makeCoinGenerator(&choice)
	coin := coinHash.getNextCoin()
	j := 1
	for ; j < len(cert.PositionsToReveal); j++ {
		reveal := cert.Reveals[cert.PositionsToReveal[j]]
		if !(reveal.SigSlot.L <= coin && coin < reveal.SigSlot.L+reveal.Part.Weight) {
			break
		}
	}

	cert.PositionsToReveal[0] = cert.PositionsToReveal[j]
	cert.PositionsToReveal[j] = coinAt0

	verifier, err = MkVerifier(p.partCommitment, p.provenWeight, compactCertStrengthTargetForTests)
	a.NoError(err)

	err = verifier.Verify(compactCertRoundsForTests, p.data, &cert)
	a.ErrorIs(err, ErrCoinNotInRange)

}

func TestVerifyBadSignature(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	p := generateCertForTesting(a)
	cert := p.cc

	verifier, err := MkVerifier(p.partCommitment, p.provenWeight, compactCertStrengthTargetForTests)
	a.NoError(err)
	err = verifier.Verify(compactCertRoundsForTests, p.data, &cert)
	a.NoError(err)

	key := generateTestSigner(0, uint64(compactCertRoundsForTests)*20+1, compactCertRoundsForTests, a)
	signerInRound := key.GetSigner(compactCertRoundsForTests)
	newSig, err := signerInRound.SignBytes([]byte{0x1, 0x2})
	a.NoError(err)

	rev := cert.Reveals[0]
	rev.SigSlot.Sig = newSig
	cert.Reveals[0] = rev

	verifier, err = MkVerifier(p.partCommitment, p.provenWeight, compactCertStrengthTargetForTests)
	a.NoError(err)
	err = verifier.Verify(compactCertRoundsForTests, p.data, &cert)
	a.ErrorIs(err, merklesignature.ErrSignatureSchemeVerificationFailed)

}

func TestVerifyZeroProvenWeight(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	partcommit := crypto.GenericDigest{}
	_, err := MkVerifier(partcommit, 0, compactCertStrengthTargetForTests)
	a.ErrorIs(err, ErrIllegalInputForLnApprox)
}
