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

package stateproof

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"math/bits"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/falcon"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type testMessage []byte

func (m testMessage) IntoStateProofMessageHash() MessageHash {
	hsh := MessageHash{}
	copy(hsh[:], m)
	return hsh
}

type paramsForTest struct {
	sp                   StateProof
	provenWeight         uint64
	partCommitment       crypto.GenericDigest
	numberOfParticipnets uint64
	data                 MessageHash
	builder              *Prover
	sig                  merklesignature.Signature
}

const stateProofIntervalForTests = 256
const stateProofStrengthTargetForTests = 256

func hashBytes(hash hash.Hash, m []byte) []byte {
	hash.Reset()
	hash.Write(m)
	outhash := hash.Sum(nil)
	return outhash
}

func createParticipantSliceWithWeight(totalWeight, numberOfParticipant int, key *merklesignature.Verifier) []basics.Participant {
	parts := make([]basics.Participant, 0, numberOfParticipant)

	for i := 0; i < numberOfParticipant; i++ {
		part := basics.Participant{
			PK:     *key,
			Weight: uint64(totalWeight / 2 / numberOfParticipant),
		}

		parts = append(parts, part)
	}
	return parts
}

func generateTestSigner(firstValid uint64, lastValid uint64, interval uint64, a *require.Assertions) *merklesignature.Secrets {
	signer, err := merklesignature.New(firstValid, lastValid, interval)
	a.NoError(err)

	return signer
}

func generateProofForTesting(a *require.Assertions, doLargeTest bool) paramsForTest {

	totalWeight := 10000000
	npartHi := 2
	npartLo := 100
	stateproofIntervals := uint64(4) // affects the number of keys that will be generated

	if doLargeTest {
		npartHi *= 100
		npartLo *= 100
		stateproofIntervals = 20
	}

	npart := npartHi + npartLo

	data := testMessage("hello world").IntoStateProofMessageHash()
	provenWt := uint64(totalWeight / 2)

	// Share the key; we allow the same vote key to appear in multiple accounts..
	key := generateTestSigner(0, uint64(stateProofIntervalForTests)*stateproofIntervals+1, stateProofIntervalForTests, a)
	var parts []basics.Participant
	var sigs []merklesignature.Signature
	parts = append(parts, createParticipantSliceWithWeight(totalWeight, npartHi, key.GetVerifier())...)
	parts = append(parts, createParticipantSliceWithWeight(totalWeight, npartLo, key.GetVerifier())...)

	signerInRound := key.GetSigner(stateProofIntervalForTests)
	sig, err := signerInRound.SignBytes(data[:])
	a.NoError(err, "failed to create keys")

	for i := 0; i < npart; i++ {
		sigs = append(sigs, sig)
	}

	partcom, err := merklearray.BuildVectorCommitmentTree(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	a.NoError(err)

	b, err := MakeProver(data, stateProofIntervalForTests, uint64(totalWeight/2), parts, partcom, stateProofStrengthTargetForTests)
	a.NoError(err)

	for i := uint64(0); i < uint64(npart)/2+10; i++ { // leave some signature to be added later in the test (if needed)
		a.False(b.Present(i))
		a.NoError(b.IsValid(i, &sigs[i], !doLargeTest))
		b.Add(i, sigs[i])

		// sanity check that the builder add the signature
		isPresent, err := b.Present(i)
		a.NoError(err)
		a.True(isPresent)
	}

	proof, err := b.CreateProof()
	a.NoError(err)

	p := paramsForTest{
		sp:                   *proof,
		provenWeight:         provenWt,
		partCommitment:       partcom.Root(),
		numberOfParticipnets: uint64(npart),
		data:                 data,
		builder:              b,
		sig:                  sig,
	}
	return p
}

func TestBuildVerify(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	p := generateProofForTesting(a, true)
	sProof := p.sp

	var someReveal Reveal
	for _, rev := range sProof.Reveals {
		someReveal = rev
		break
	}

	proofEnc := protocol.Encode(&sProof)
	fmt.Printf("StateProof size:\n")
	fmt.Printf("  %6d elems sigproofs\n", len(sProof.SigProofs.Path))
	fmt.Printf("  %6d bytes sigproofs\n", len(protocol.EncodeReflect(sProof.SigProofs)))
	fmt.Printf("  %6d bytes partproofs\n", len(protocol.EncodeReflect(sProof.PartProofs)))
	fmt.Printf("  %6d bytes sigproof per reveal\n", len(protocol.EncodeReflect(sProof.SigProofs))/len(sProof.Reveals))
	fmt.Printf("  %6d reveals:\n", len(sProof.Reveals))
	fmt.Printf("    %6d bytes reveals[*] participant\n", len(protocol.Encode(&someReveal.Part)))
	fmt.Printf("    %6d bytes reveals[*] sigslot\n", len(protocol.Encode(&someReveal.SigSlot)))
	fmt.Printf("    %6d bytes reveals[*] total\n", len(protocol.Encode(&someReveal)))
	fmt.Printf("  %6d bytes total\n", len(proofEnc))

	verif, err := MkVerifier(p.partCommitment, p.provenWeight, stateProofStrengthTargetForTests)
	a.NoError(err)

	err = verif.Verify(stateProofIntervalForTests, p.data, &sProof)
	a.NoError(err, "failed to verify the state proof")
}

func generateRandomParticipant(a *require.Assertions) basics.Participant {
	key := generateTestSigner(0, 8, 1, a)

	p := basics.Participant{
		PK:     *key.GetVerifier(),
		Weight: crypto.RandUint64(),
	}
	return p
}

func calculateHashOnPartLeaf(part basics.Participant) []byte {
	binaryWeight := make([]byte, 8)
	binary.LittleEndian.PutUint64(binaryWeight, part.Weight)

	keyLifetimeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(keyLifetimeBytes, part.PK.KeyLifetime)

	publicKeyBytes := part.PK
	partCommitment := make([]byte, 0, len(protocol.StateProofPart)+len(binaryWeight)+len(publicKeyBytes.Commitment)+len(keyLifetimeBytes))
	partCommitment = append(partCommitment, protocol.StateProofPart...)
	partCommitment = append(partCommitment, binaryWeight...)
	partCommitment = append(partCommitment, keyLifetimeBytes...)
	partCommitment = append(partCommitment, publicKeyBytes.Commitment[:]...)

	factory := crypto.HashFactory{HashType: HashType}
	hashValue := hashBytes(factory.NewHash(), partCommitment)
	return hashValue
}

func calculateHashOnInternalNode(leftNode, rightNode []byte) []byte {
	buf := make([]byte, len(leftNode)+len(rightNode)+len(protocol.MerkleArrayNode))
	copy(buf[:], protocol.MerkleArrayNode)
	copy(buf[len(protocol.MerkleArrayNode):], leftNode[:])
	copy(buf[len(protocol.MerkleArrayNode)+len(leftNode):], rightNode[:])

	factory := crypto.HashFactory{HashType: HashType}
	hashValue := hashBytes(factory.NewHash(), buf)
	return hashValue
}

func TestParticipationCommitmentBinaryFormat(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	var parts []basics.Participant
	parts = append(parts, generateRandomParticipant(a))
	parts = append(parts, generateRandomParticipant(a))
	parts = append(parts, generateRandomParticipant(a))
	parts = append(parts, generateRandomParticipant(a))

	partcom, err := merklearray.BuildVectorCommitmentTree(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	a.NoError(err)

	partCommitmentRoot := partcom.Root()

	leaf0 := calculateHashOnPartLeaf(parts[0])
	leaf1 := calculateHashOnPartLeaf(parts[1])
	leaf2 := calculateHashOnPartLeaf(parts[2])
	leaf3 := calculateHashOnPartLeaf(parts[3])

	inner1 := calculateHashOnInternalNode(leaf0, leaf2)
	inner2 := calculateHashOnInternalNode(leaf1, leaf3)

	calcRoot := calculateHashOnInternalNode(inner1, inner2)

	a.Equal(partCommitmentRoot, crypto.GenericDigest(calcRoot))

}

func TestSignatureCommitmentBinaryFormat(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	totalWeight := 10000000
	numPart := 4

	data := testMessage("test!").IntoStateProofMessageHash()

	var parts []basics.Participant
	var sigs []merklesignature.Signature

	for i := 0; i < numPart; i++ {
		key := generateTestSigner(0, uint64(stateProofIntervalForTests)*8, stateProofIntervalForTests, a)

		part := basics.Participant{
			PK:     *key.GetVerifier(),
			Weight: uint64(totalWeight / 2 / numPart),
		}
		parts = append(parts, part)

		sig, err := key.GetSigner(stateProofIntervalForTests).SignBytes(data[:])
		require.NoError(t, err, "failed to create keys")
		sigs = append(sigs, sig)

	}

	partcom, err := merklearray.BuildVectorCommitmentTree(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	a.NoError(err)

	b, err := MakeProver(data, stateProofIntervalForTests, uint64(totalWeight/(2*numPart)), parts, partcom, stateProofStrengthTargetForTests)
	a.NoError(err)

	for i := 0; i < numPart; i++ {
		a.False(b.Present(uint64(i)))
		a.NoError(b.IsValid(uint64(i), &sigs[i], false))
		b.Add(uint64(i), sigs[i])
	}

	sProof, err := b.CreateProof()
	a.NoError(err)

	leaf0 := calculateHashOnSigLeaf(t, sigs[0], findLInProof(a, sigs[0], sProof))
	leaf1 := calculateHashOnSigLeaf(t, sigs[1], findLInProof(a, sigs[1], sProof))
	leaf2 := calculateHashOnSigLeaf(t, sigs[2], findLInProof(a, sigs[2], sProof))
	leaf3 := calculateHashOnSigLeaf(t, sigs[3], findLInProof(a, sigs[3], sProof))

	// hash internal node according to the vector commitment indices
	inner1 := calculateHashOnInternalNode(leaf0, leaf2)
	inner2 := calculateHashOnInternalNode(leaf1, leaf3)

	calcRoot := calculateHashOnInternalNode(inner1, inner2)

	a.Equal(sProof.SigCommit, crypto.GenericDigest(calcRoot))

}

// The aim of this test is to simulate how a SNARK circuit will verify a signature.(part of the overall stateproof verification)
// it includes parsing the signature's format (according to Algorand's spec) and binds it to a specific length.
// here we also expect the scheme to use Falcon signatures and nothing else.
func TestSimulateSignatureVerification(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	signer := generateTestSigner(50, 100, 1, a)
	sigRound := uint64(55)
	msg := testMessage("testMessage")
	sig, err := signer.GetSigner(sigRound).SignBytes(msg)
	a.NoError(err)

	genericKey := signer.GetVerifier()
	sigBytes, err := sig.GetFixedLengthHashableRepresentation()
	a.NoError(err)
	checkSignature(a, sigBytes, genericKey, sigRound, msg, 5, 6)
}

// The aim of this test is to simulate how a SNARK circuit will verify a signature.(part of the overall stateproof verification)
// it includes parsing the signature's format (according to Algorand's spec) and binds it to a specific length.
// here we also expect the scheme to use Falcon signatures and nothing else.
func TestSimulateSignatureVerificationOneEphemeralKey(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	// we create one ephemeral key so the signature's proof should be with len 0
	signer := generateTestSigner(1, stateProofIntervalForTests, stateProofIntervalForTests, a)

	sigRound := uint64(stateProofIntervalForTests)
	msg := testMessage("testMessage")
	sig, err := signer.GetSigner(sigRound).SignBytes(msg)
	a.NoError(err)

	genericKey := signer.GetVerifier()
	sigBytes, err := sig.GetFixedLengthHashableRepresentation()
	a.NoError(err)
	checkSignature(a, sigBytes, genericKey, sigRound, msg, 0, 0)
}

func checkSignature(a *require.Assertions, sigBytes []byte, verifier *merklesignature.Verifier, round uint64, message []byte, expectedIndex uint64, expectedPathLen uint8) {
	a.Equal(len(sigBytes), 4366)

	parsedBytes := 0
	// check schemeId
	schemeID := binary.LittleEndian.Uint16(sigBytes[parsedBytes : parsedBytes+2])
	parsedBytes += 2
	a.Equal(schemeID, uint16(0))

	parsedBytes, falconPK := verifyFalconSignature(a, sigBytes, parsedBytes, message)

	// check the public key commitment

	leafHash := hashEphemeralPublicKeyLeaf(round, falconPK)

	// parsing the merkle path index and the proof's len
	idx := binary.LittleEndian.Uint64(sigBytes[parsedBytes : parsedBytes+8])
	parsedBytes += 8
	pathLe := sigBytes[parsedBytes]
	parsedBytes++

	a.Equal(expectedIndex, idx)
	a.Equal(expectedPathLen, pathLe)

	leafHash = verifyMerklePath(idx, pathLe, sigBytes, parsedBytes, leafHash)

	a.Equal(leafHash, verifier.Commitment[:])
}

func verifyMerklePath(idx uint64, pathLe byte, sigBytes []byte, parsedBytes int, leafHash []byte) []byte {
	// idxDirection will indicate which sibling we should fetch MSB to LSB leaf-to-root
	idxDirection := bits.Reverse64(idx) >> (64 - pathLe)

	// use the verification path to hash siblings up to the root
	parsedBytes += (16 - int(pathLe)) * 64
	for i := uint8(0); i < pathLe; i++ {
		var innerNodeBytes []byte

		siblingHash := sigBytes[parsedBytes : parsedBytes+64]
		parsedBytes += 64

		innerNodeBytes = append(innerNodeBytes, []byte{'M', 'A'}...)
		if (idxDirection & 1) != 0 {
			innerNodeBytes = append(innerNodeBytes, siblingHash...)
			innerNodeBytes = append(innerNodeBytes, leafHash...)
		} else {
			innerNodeBytes = append(innerNodeBytes, leafHash...)
			innerNodeBytes = append(innerNodeBytes, siblingHash...)
		}
		idxDirection = idxDirection >> 1
		leafHash = hashBytes(crypto.HashFactory{HashType: HashType}.NewHash(), innerNodeBytes)
	}
	return leafHash
}

func hashEphemeralPublicKeyLeaf(round uint64, falconPK [falcon.PublicKeySize]byte) []byte {
	var sigRoundAsBytes [8]byte
	binary.LittleEndian.PutUint64(sigRoundAsBytes[:], round)

	var ephemeralPublicKeyBytes []byte
	ephemeralPublicKeyBytes = append(ephemeralPublicKeyBytes, []byte{'K', 'P'}...)
	ephemeralPublicKeyBytes = append(ephemeralPublicKeyBytes, []byte{0, 0}...)
	ephemeralPublicKeyBytes = append(ephemeralPublicKeyBytes, sigRoundAsBytes[:]...)
	ephemeralPublicKeyBytes = append(ephemeralPublicKeyBytes, falconPK[:]...)
	leafHash := hashBytes(crypto.HashFactory{HashType: HashType}.NewHash(), ephemeralPublicKeyBytes)
	return leafHash
}

func verifyFalconSignature(a *require.Assertions, sigBytes []byte, parsedBytes int, message []byte) (int, [falcon.PublicKeySize]byte) {
	var falconSig [falcon.CTSignatureSize]byte
	copy(falconSig[:], sigBytes[parsedBytes:parsedBytes+1538])
	parsedBytes += 1538
	ctSign := falcon.CTSignature(falconSig)

	var falconPK [falcon.PublicKeySize]byte
	copy(falconPK[:], sigBytes[parsedBytes:parsedBytes+1793])
	parsedBytes += 1793
	ephemeralPk := falcon.PublicKey(falconPK)

	err := ephemeralPk.VerifyCTSignature(ctSign, message)
	a.NoError(err)
	return parsedBytes, falconPK
}

func findLInProof(a *require.Assertions, signature merklesignature.Signature, proof *StateProof) uint64 {
	for _, t := range proof.Reveals {
		if bytes.Compare(t.SigSlot.Sig.Signature, signature.Signature) == 0 {
			return t.SigSlot.L
		}
	}
	a.Fail("could not find matching reveal")
	return 0
}

func TestBuilder_AddRejectsInvalidSigVersion(t *testing.T) {
	partitiontest.PartitionTest(t)

	// setting up a builder
	a := require.New(t)

	totalWeight := 10000000
	npartHi := 1
	npartLo := 9

	data := testMessage("hello world").IntoStateProofMessageHash()

	key := generateTestSigner(0, uint64(stateProofIntervalForTests)*20+1, stateProofIntervalForTests, a)
	var parts []basics.Participant
	parts = append(parts, createParticipantSliceWithWeight(totalWeight, npartHi, key.GetVerifier())...)
	parts = append(parts, createParticipantSliceWithWeight(totalWeight, npartLo, key.GetVerifier())...)

	partcom, err := merklearray.BuildVectorCommitmentTree(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	a.NoError(err)

	builder, err := MakeProver(data, stateProofIntervalForTests, uint64(totalWeight/2), parts, partcom, stateProofStrengthTargetForTests)
	a.NoError(err)

	// actual test:
	signerInRound := key.GetSigner(stateProofIntervalForTests)
	sig, err := signerInRound.SignBytes(data[:])
	require.NoError(t, err, "failed to create keys")
	// Corrupting the version of the signature:
	sig.Signature[1]++

	a.ErrorIs(builder.IsValid(0, &sig, true), merklesignature.ErrSignatureSaltVersionMismatch)
}

func TestBuildAndReady(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	totalWeight := 10000000
	data := testMessage("hello world").IntoStateProofMessageHash()
	var parts []basics.Participant

	partcom, err := merklearray.BuildVectorCommitmentTree(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	a.NoError(err)

	builder, err := MakeProver(data, stateProofIntervalForTests, uint64(totalWeight/2), parts, partcom, stateProofStrengthTargetForTests)
	a.NoError(err)

	a.False(builder.Ready())
	_, err = builder.CreateProof()
	a.ErrorIs(err, ErrSignedWeightLessThanProvenWeight)

	builder.signedWeight = builder.ProvenWeight
	a.False(builder.Ready())
	_, err = builder.CreateProof()
	a.ErrorIs(err, ErrSignedWeightLessThanProvenWeight)

	builder.signedWeight = builder.ProvenWeight + 1
	a.True(builder.Ready())
	_, err = builder.CreateProof()
	a.NotErrorIs(err, ErrSignedWeightLessThanProvenWeight)

}

func TestErrorCases(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	builder := Prover{}
	_, err := builder.Present(1)
	a.ErrorIs(err, ErrPositionOutOfBound)

	builder.Participants = make([]basics.Participant, 1, 1)
	builder.sigs = make([]sigslot, 1, 1)
	err = builder.IsValid(1, &merklesignature.Signature{}, false)
	a.ErrorIs(err, ErrPositionOutOfBound)

	err = builder.IsValid(0, &merklesignature.Signature{}, false)
	require.ErrorIs(t, err, ErrPositionWithZeroWeight)

	builder.Participants[0].Weight = 1
	err = builder.IsValid(0, &merklesignature.Signature{}, true)
	a.ErrorIs(err, merklesignature.ErrKeyLifetimeIsZero)

	builder.Participants[0].PK.KeyLifetime = 20
	err = builder.IsValid(0, &merklesignature.Signature{}, true)
	a.ErrorIs(err, merklesignature.ErrSignatureSchemeVerificationFailed)

	builder.sigs[0].Weight = 1
	err = builder.Add(1, merklesignature.Signature{})
	a.ErrorIs(err, ErrPositionOutOfBound)

	err = builder.Add(0, merklesignature.Signature{})
	a.ErrorIs(err, ErrPositionAlreadyPresent)
}

func checkSigsArray(n int, a *require.Assertions) {
	b := &Prover{
		sigs: make([]sigslot, n),
	}
	for i := 0; i < n; i++ {
		b.sigs[i].L = uint64(i)
		b.sigs[i].Weight = 1
	}
	for i := 0; i < n; i++ {
		pos, err := b.coinIndex(uint64(i))
		a.NoError(err)
		a.Equal(uint64(i), pos)
	}
}

func TestCoinIndex(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	n := 1000
	checkSigsArray(n, a)

	n = 1
	checkSigsArray(n, a)

	n = 2
	checkSigsArray(n, a)

	n = 3
	checkSigsArray(n, a)
}

func TestCoinIndexBetweenWeights(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	n := 1000
	b := &Prover{
		sigs: make([]sigslot, n),
	}
	for i := 0; i < n; i++ {
		b.sigs[i].Weight = 2
	}

	b.sigs[0].L = 0
	for i := 1; i < n; i++ {
		b.sigs[i].L = b.sigs[i-1].L + b.sigs[i-1].Weight
	}
	for i := 0; i < 2*n; i++ {
		pos, err := b.coinIndex(uint64(i))
		a.NoError(err)
		a.Equal(pos, uint64(i/2))
	}

	_, err := b.coinIndex(uint64(2*n + 1))
	a.ErrorIs(err, ErrCoinIndexError)
}

func TestBuilderWithZeroProvenWeight(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	data := testMessage("hello world").IntoStateProofMessageHash()

	_, err := MakeProver(data, stateProofIntervalForTests, 0, nil, nil, stateProofStrengthTargetForTests)
	a.ErrorIs(err, ErrIllegalInputForLnApprox)

}

func TestBuilder_BuildStateProofCache(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	p := generateProofForTesting(a, true)
	sp1 := &p.sp
	sp2, err := p.builder.CreateProof()
	a.NoError(err)
	a.Equal(sp1, sp2) // already built, no signatures added

	err = p.builder.Add(p.numberOfParticipnets-1, p.sig)
	a.NoError(err)
	sp3, err := p.builder.CreateProof()
	a.NoError(err)
	a.NotEqual(sp1, sp3) // better StateProof with added signature should have been built

	sp4, err := p.builder.CreateProof()
	a.NoError(err)
	a.Equal(sp3, sp4)

	return
}

// Verifies that the VotersAllocBound constant is equal to the current consensus parameters.
// It is used for msgpack allocbound (needs to be static)
func TestBuilder_StateProofTopVoters(t *testing.T) {
	partitiontest.PartitionTest(t)
	require.Equal(t, config.Consensus[protocol.ConsensusCurrentVersion].StateProofTopVoters, uint64(VotersAllocBound))
}

func BenchmarkBuildVerify(b *testing.B) {
	totalWeight := 1000000
	npart := 1000

	a := require.New(b)

	provenWeight := uint64(totalWeight / 2)
	data := testMessage("hello world").IntoStateProofMessageHash()

	var parts []basics.Participant
	//var partkeys []*merklesignature.Secrets
	var sigs []merklesignature.Signature
	for i := 0; i < npart; i++ {
		signer := generateTestSigner(0, stateProofIntervalForTests+1, stateProofIntervalForTests, a)
		part := basics.Participant{
			PK:     *signer.GetVerifier(),
			Weight: uint64(totalWeight / npart),
		}

		signerInRound := signer.GetSigner(stateProofIntervalForTests)
		sig, err := signerInRound.SignBytes(data[:])
		require.NoError(b, err, "failed to create keys")

		//partkeys = append(partkeys, signer)
		sigs = append(sigs, sig)
		parts = append(parts, part)
	}

	var sp *StateProof
	partcom, err := merklearray.BuildVectorCommitmentTree(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	if err != nil {
		b.Error(err)
	}

	b.Run("AddBuild", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			builder, err := MakeProver(data, stateProofIntervalForTests, provenWeight, parts, partcom, stateProofStrengthTargetForTests)
			if err != nil {
				b.Error(err)
			}

			for i := 0; i < npart; i++ {
				a.False(builder.Present(uint64(i)))
				a.NoError(builder.IsValid(uint64(i), &sigs[i], true))
				builder.Add(uint64(i), sigs[i])
			}

			sp, err = builder.CreateProof()
			if err != nil {
				b.Error(err)
			}
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			verif, _ := MkVerifier(partcom.Root(), provenWeight, stateProofStrengthTargetForTests)
			if err = verif.Verify(stateProofIntervalForTests, data, sp); err != nil {
				b.Error(err)
			}
		}
	})
}
