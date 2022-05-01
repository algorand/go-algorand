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
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"math/bits"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/falcon"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type testMessage []byte

func (m testMessage) IntoStateProofMessageHash() StateProofMessageHash {
	hsh := StateProofMessageHash{}
	copy(hsh[:], m)
	return hsh
}

type paramsForTest struct {
	cc                   Cert
	provenWeight         uint64
	partCommitment       crypto.GenericDigest
	numberOfParticipnets uint64
	data                 StateProofMessageHash
}

const compactCertRoundsForTests = 256
const compactCertStrengthTargetForTests = 256

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

func generateCertForTesting(a *require.Assertions) paramsForTest {
	// Doing a full test of 1M accounts takes too much CPU time in CI.
	doLargeTest := false

	totalWeight := 10000000
	npartHi := 10
	npartLo := 9990

	if doLargeTest {
		npartHi *= 100
		npartLo *= 100
	}

	npart := npartHi + npartLo

	data := testMessage("hello world").IntoStateProofMessageHash()
	provenWt := uint64(totalWeight / 2)

	// Share the key; we allow the same vote key to appear in multiple accounts..
	key := generateTestSigner(0, uint64(compactCertRoundsForTests)*20+1, compactCertRoundsForTests, a)
	var parts []basics.Participant
	var sigs []merklesignature.Signature
	parts = append(parts, createParticipantSliceWithWeight(totalWeight, npartHi, key.GetVerifier())...)
	parts = append(parts, createParticipantSliceWithWeight(totalWeight, npartLo, key.GetVerifier())...)

	signerInRound := key.GetSigner(compactCertRoundsForTests)
	sig, err := signerInRound.SignBytes(data[:])
	a.NoError(err, "failed to create keys")

	for i := 0; i < npart; i++ {
		sigs = append(sigs, sig)
	}

	partcom, err := merklearray.BuildVectorCommitmentTree(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	a.NoError(err)

	b, err := MkBuilder(data, compactCertRoundsForTests, uint64(totalWeight/2), parts, partcom, compactCertStrengthTargetForTests)
	a.NoError(err)

	for i := 0; i < npart; i++ {
		a.False(b.Present(uint64(i)))
		a.NoError(b.IsValid(uint64(i), sigs[i], !doLargeTest))
		b.Add(uint64(i), sigs[i])
	}

	cert, err := b.Build()
	a.NoError(err)

	p := paramsForTest{
		cc:                   *cert,
		provenWeight:         provenWt,
		partCommitment:       partcom.Root(),
		numberOfParticipnets: uint64(npart),
		data:                 data,
	}
	return p
}

func TestBuildVerify(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	p := generateCertForTesting(a)
	cert := p.cc

	var someReveal Reveal
	for _, rev := range cert.Reveals {
		someReveal = rev
		break
	}

	certenc := protocol.Encode(&cert)
	fmt.Printf("Cert size:\n")
	fmt.Printf("  %6d elems sigproofs\n", len(cert.SigProofs.Path))
	fmt.Printf("  %6d bytes sigproofs\n", len(protocol.EncodeReflect(cert.SigProofs)))
	fmt.Printf("  %6d bytes partproofs\n", len(protocol.EncodeReflect(cert.PartProofs)))
	fmt.Printf("  %6d bytes sigproof per reveal\n", len(protocol.EncodeReflect(cert.SigProofs))/len(cert.Reveals))
	fmt.Printf("  %6d reveals:\n", len(cert.Reveals))
	fmt.Printf("    %6d bytes reveals[*] participant\n", len(protocol.Encode(&someReveal.Part)))
	fmt.Printf("    %6d bytes reveals[*] sigslot\n", len(protocol.Encode(&someReveal.SigSlot)))
	fmt.Printf("    %6d bytes reveals[*] total\n", len(protocol.Encode(&someReveal)))
	fmt.Printf("  %6d bytes total\n", len(certenc))

	verif, err := MkVerifier(p.partCommitment, p.provenWeight, compactCertStrengthTargetForTests)
	a.NoError(err)

	err = verif.Verify(compactCertRoundsForTests, p.data, &cert)
	a.NoError(err, "failed to verify the compact cert")
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

	publicKeyBytes := part.PK
	partCommitment := make([]byte, 0, len(protocol.CompactCertPart)+len(binaryWeight)+len(publicKeyBytes))
	partCommitment = append(partCommitment, protocol.CompactCertPart...)
	partCommitment = append(partCommitment, binaryWeight...)
	partCommitment = append(partCommitment, publicKeyBytes[:]...)

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
		key := generateTestSigner(0, uint64(compactCertRoundsForTests)*8, compactCertRoundsForTests, a)

		part := basics.Participant{
			PK:     *key.GetVerifier(),
			Weight: uint64(totalWeight / 2 / numPart),
		}
		parts = append(parts, part)

		sig, err := key.GetSigner(compactCertRoundsForTests).SignBytes(data[:])
		require.NoError(t, err, "failed to create keys")
		sigs = append(sigs, sig)

	}

	partcom, err := merklearray.BuildVectorCommitmentTree(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	a.NoError(err)

	b, err := MkBuilder(data, compactCertRoundsForTests, uint64(totalWeight/(2*numPart)), parts, partcom, compactCertStrengthTargetForTests)
	a.NoError(err)

	for i := 0; i < numPart; i++ {
		a.False(b.Present(uint64(i)))
		a.NoError(b.IsValid(uint64(i), sigs[i], false))
		b.Add(uint64(i), sigs[i])
	}

	cert, err := b.Build()
	a.NoError(err)

	leaf0 := calculateHashOnSigLeaf(t, sigs[0], findLInCert(a, sigs[0], cert))
	leaf1 := calculateHashOnSigLeaf(t, sigs[1], findLInCert(a, sigs[1], cert))
	leaf2 := calculateHashOnSigLeaf(t, sigs[2], findLInCert(a, sigs[2], cert))
	leaf3 := calculateHashOnSigLeaf(t, sigs[3], findLInCert(a, sigs[3], cert))

	// hash internal node according to the vector commitment indices
	inner1 := calculateHashOnInternalNode(leaf0, leaf2)
	inner2 := calculateHashOnInternalNode(leaf1, leaf3)

	calcRoot := calculateHashOnInternalNode(inner1, inner2)

	a.Equal(cert.SigCommit, crypto.GenericDigest(calcRoot))

}

// The aim of this test is to simulate how a SNARK circuit will verify a signature.(part of the overall compcatcert verification)
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

// The aim of this test is to simulate how a SNARK circuit will verify a signature.(part of the overall compcatcert verification)
// it includes parsing the signature's format (according to Algorand's spec) and binds it to a specific length.
// here we also expect the scheme to use Falcon signatures and nothing else.
func TestSimulateSignatureVerificationOneEphemeralKey(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	// we create one ephemeral key so the signature's proof should be with len 0
	signer := generateTestSigner(1, compactCertRoundsForTests, compactCertRoundsForTests, a)

	sigRound := uint64(compactCertRoundsForTests)
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

	a.Equal(leafHash, verifier[:])
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

func findLInCert(a *require.Assertions, signature merklesignature.Signature, cert *Cert) uint64 {
	for _, t := range cert.Reveals {
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

	key := generateTestSigner(0, uint64(compactCertRoundsForTests)*20+1, compactCertRoundsForTests, a)
	var parts []basics.Participant
	parts = append(parts, createParticipantSliceWithWeight(totalWeight, npartHi, key.GetVerifier())...)
	parts = append(parts, createParticipantSliceWithWeight(totalWeight, npartLo, key.GetVerifier())...)

	partcom, err := merklearray.BuildVectorCommitmentTree(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	a.NoError(err)

	builder, err := MkBuilder(data, compactCertRoundsForTests, uint64(totalWeight/2), parts, partcom, compactCertStrengthTargetForTests)
	a.NoError(err)

	// actual test:
	signerInRound := key.GetSigner(compactCertRoundsForTests)
	sig, err := signerInRound.SignBytes(data[:])
	require.NoError(t, err, "failed to create keys")
	// Corrupting the version of the signature:
	sig.Signature[1]++

	a.ErrorIs(builder.IsValid(0, sig, true), merklesignature.ErrSignatureSaltVersionMismatch)
}

func TestCoinIndex(t *testing.T) {
	partitiontest.PartitionTest(t)

	n := 1000
	b := &Builder{
		sigs: make([]sigslot, n),
	}

	for i := 0; i < n; i++ {
		b.sigs[i].L = uint64(i)
		b.sigs[i].Weight = 1
	}

	for i := 0; i < n; i++ {
		pos, err := b.coinIndex(uint64(i))
		require.NoError(t, err)
		require.Equal(t, pos, uint64(i))
	}
}

func TestBuilderWithZeroProvenWeight(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	data := testMessage("hello world").IntoStateProofMessageHash()

	_, err := MkBuilder(data, compactCertRoundsForTests, 0, nil, nil, compactCertStrengthTargetForTests)
	a.ErrorIs(err, ErrIllegalInputForLnApprox)

}

func BenchmarkBuildVerify(b *testing.B) {
	totalWeight := 1000000
	npart := 1000

	a := require.New(b)

	provenWeight := uint64(totalWeight / 2)
	data := testMessage("hello world").IntoStateProofMessageHash()

	var parts []basics.Participant
	var partkeys []*merklesignature.Secrets
	var sigs []merklesignature.Signature
	for i := 0; i < npart; i++ {
		signer := generateTestSigner(0, compactCertRoundsForTests+1, compactCertRoundsForTests, a)
		part := basics.Participant{
			PK:     *signer.GetVerifier(),
			Weight: uint64(totalWeight / npart),
		}

		signerInRound := signer.GetSigner(compactCertRoundsForTests)
		sig, err := signerInRound.SignBytes(data[:])
		require.NoError(b, err, "failed to create keys")

		partkeys = append(partkeys, signer)
		sigs = append(sigs, sig)
		parts = append(parts, part)
	}

	var cert *Cert
	partcom, err := merklearray.BuildVectorCommitmentTree(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	if err != nil {
		b.Error(err)
	}

	b.Run("AddBuild", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			builder, err := MkBuilder(data, compactCertRoundsForTests, provenWeight, parts, partcom, compactCertStrengthTargetForTests)
			if err != nil {
				b.Error(err)
			}

			for i := 0; i < npart; i++ {
				a.False(builder.Present(uint64(i)))
				a.NoError(builder.IsValid(uint64(i), sigs[i], true))
				builder.Add(uint64(i), sigs[i])
			}

			cert, err = builder.Build()
			if err != nil {
				b.Error(err)
			}
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			verif, _ := MkVerifier(partcom.Root(), provenWeight, compactCertStrengthTargetForTests)
			if err = verif.Verify(compactCertRoundsForTests, data, cert); err != nil {
				b.Error(err)
			}
		}
	})
}
