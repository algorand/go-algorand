// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package stateproof

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestVerifyRevelForEachPosition(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	p := generateProofForTesting(a, false)
	sProof := p.sp

	verifier, err := MkVerifier(p.partCommitment, p.provenWeight, stateProofStrengthTargetForTests)
	a.NoError(err)

	err = verifier.Verify(stateProofIntervalForTests, p.data, &sProof)
	a.NoError(err)

	for i := uint64(0); i < p.numberOfParticipnets; i++ {
		_, ok := sProof.Reveals[i]
		if !ok {
			sProof.PositionsToReveal[0] = i
			break
		}
	}

	verifier, err = MkVerifier(p.partCommitment, p.provenWeight, stateProofStrengthTargetForTests)
	a.NoError(err)

	err = verifier.Verify(stateProofIntervalForTests, p.data, &sProof)
	a.ErrorIs(err, ErrNoRevealInPos)

}

// TestVerifyWrongCoinSlot this test makes sure that the verifier uses PositionsToReveal array, and opens reveals in a specific order
// In order to and trick the verifier we need to swap two positions in the PositionsToReveal so the coins will not match.
func TestVerifyWrongCoinSlot(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	p := generateProofForTesting(a, false)
	sProof := p.sp
	verifier, err := MkVerifier(p.partCommitment, p.provenWeight, stateProofStrengthTargetForTests)
	a.NoError(err)

	err = verifier.Verify(stateProofIntervalForTests, p.data, &sProof)
	a.NoError(err)

	// we need to find a reveal that will not match the first coin.
	// In order to accomplish that we will extract the first coin and find a reveals ( > 1, since index 0 will satisfy the verifier)
	// that doesn't match
	coinAt0 := sProof.PositionsToReveal[0]
	choice := coinChoiceSeed{
		partCommitment: verifier.participantsCommitment,
		lnProvenWeight: verifier.lnProvenWeight,
		sigCommitment:  sProof.SigCommit,
		signedWeight:   sProof.SignedWeight,
		data:           p.data,
	}
	coinHash := makeCoinGenerator(&choice)
	coin := coinHash.getNextCoin()
	j := 1
	for ; j < len(sProof.PositionsToReveal); j++ {
		reveal := sProof.Reveals[sProof.PositionsToReveal[j]]
		if !(reveal.SigSlot.L <= coin && coin < reveal.SigSlot.L+reveal.Part.Weight) {
			break
		}
	}

	sProof.PositionsToReveal[0] = sProof.PositionsToReveal[j]
	sProof.PositionsToReveal[j] = coinAt0

	verifier, err = MkVerifier(p.partCommitment, p.provenWeight, stateProofStrengthTargetForTests)
	a.NoError(err)

	err = verifier.Verify(stateProofIntervalForTests, p.data, &sProof)
	a.ErrorIs(err, ErrCoinNotInRange)

}

func TestVerifyBadSignature(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	p := generateProofForTesting(a, false)
	sProof := p.sp

	verifier, err := MkVerifier(p.partCommitment, p.provenWeight, stateProofStrengthTargetForTests)
	a.NoError(err)
	err = verifier.Verify(stateProofIntervalForTests, p.data, &sProof)
	a.NoError(err)

	key := generateTestSigner(0, uint64(stateProofIntervalForTests)*20+1, stateProofIntervalForTests, a)
	signerInRound := key.GetSigner(stateProofIntervalForTests)
	newSig, err := signerInRound.SignBytes([]byte{0x1, 0x2})
	a.NoError(err)

	rev := sProof.Reveals[0]
	rev.SigSlot.Sig = newSig
	sProof.Reveals[0] = rev

	verifier, err = MkVerifier(p.partCommitment, p.provenWeight, stateProofStrengthTargetForTests)
	a.NoError(err)
	err = verifier.Verify(stateProofIntervalForTests, p.data, &sProof)
	a.ErrorIs(err, merklesignature.ErrSignatureSchemeVerificationFailed)

}

func TestVerifyZeroProvenWeight(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	partcommit := crypto.GenericDigest{}
	_, err := MkVerifier(partcommit, 0, stateProofStrengthTargetForTests)
	a.ErrorIs(err, ErrIllegalInputForLnApprox)
}

func TestEqualVerifiers(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	p := generateProofForTesting(a, false)
	sProof := p.sp

	verifier, err := MkVerifier(p.partCommitment, p.provenWeight, stateProofStrengthTargetForTests)
	a.NoError(err)
	err = verifier.Verify(stateProofIntervalForTests, p.data, &sProof)
	a.NoError(err)

	lnProvenWeight, err := LnIntApproximation(p.provenWeight)
	verifierLnP := MkVerifierWithLnProvenWeight(p.partCommitment, lnProvenWeight, stateProofStrengthTargetForTests)

	a.Equal(verifierLnP, verifier)
}

func TestTreeDepth(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	p := generateProofForTesting(a, false)
	sProof := p.sp

	verifier, err := MkVerifier(p.partCommitment, p.provenWeight, stateProofStrengthTargetForTests)
	a.NoError(err)

	tmp := sProof.PartProofs.TreeDepth
	sProof.PartProofs.TreeDepth = MaxTreeDepth + 1
	a.ErrorIs(verifier.Verify(stateProofIntervalForTests, p.data, &sProof), ErrTreeDepthTooLarge)
	sProof.PartProofs.TreeDepth = tmp

	tmp = sProof.SigProofs.TreeDepth
	sProof.SigProofs.TreeDepth = MaxTreeDepth + 1
	a.ErrorIs(verifier.Verify(stateProofIntervalForTests, p.data, &sProof), ErrTreeDepthTooLarge)
	sProof.SigProofs.TreeDepth = tmp

	a.NoError(verifier.Verify(stateProofIntervalForTests, p.data, &sProof))
}

func wellFormedAlgorithmProof() *StateProof {
	return &StateProof{
		SigCommit:  make(crypto.GenericDigest, HashSize),
		SigProofs:  merklearray.Proof{HashFactory: crypto.HashFactory{HashType: HashType}},
		PartProofs: merklearray.Proof{HashFactory: crypto.HashFactory{HashType: HashType}},
	}
}

// TestVerifyStateProofAlgorithms pins the hash algorithm and SigCommit size to
// the package constants.
func TestVerifyStateProofAlgorithms(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	require.NoError(t, verifyStateProofAlgorithms(wellFormedAlgorithmProof()))

	// SigProofs declaring a non-Sumhash algorithm is rejected.
	s := wellFormedAlgorithmProof()
	s.SigProofs.HashFactory.HashType = crypto.Sha256
	require.ErrorIs(t, verifyStateProofAlgorithms(s), ErrInvalidHashType)

	// PartProofs declaring a non-Sumhash algorithm is rejected.
	s = wellFormedAlgorithmProof()
	s.PartProofs.HashFactory.HashType = crypto.Sha512_256
	require.ErrorIs(t, verifyStateProofAlgorithms(s), ErrInvalidHashType)

	// A SigCommit sized for a 32-byte digest instead of Sumhash is rejected.
	s = wellFormedAlgorithmProof()
	s.SigCommit = make(crypto.GenericDigest, crypto.Sha256Size)
	require.ErrorIs(t, verifyStateProofAlgorithms(s), ErrInvalidSigCommitSize)

	// Each nested Merkle signature proof is also part of StateProofBasic and
	// must use the Merkle signature scheme's fixed Sumhash algorithm.
	s = wellFormedAlgorithmProof()
	reveal := Reveal{}
	reveal.SigSlot.Sig.Signature = crypto.FalconSignature{1, 2}
	reveal.SigSlot.Sig.Proof.HashFactory.HashType = merklesignature.MerkleSignatureSchemeHashFunction
	s.Reveals = map[uint64]Reveal{7: reveal}
	require.NoError(t, verifyStateProofAlgorithms(s))

	reveal.SigSlot.Sig.Proof.HashFactory.HashType = crypto.Sha256
	s.Reveals[7] = reveal
	require.ErrorIs(t, verifyStateProofAlgorithms(s), ErrInvalidHashType)
	require.ErrorIs(t, (&Verifier{}).Verify(0, MessageHash{}, s), ErrInvalidHashType)
}
