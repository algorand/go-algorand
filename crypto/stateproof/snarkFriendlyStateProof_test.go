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

package stateproof

import (
	"fmt"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
)

func TestCertToJSON(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	totalWeight := 10000000
	npartHi := 3
	npartLo := 5
	npart := npartHi + npartLo
	const targetForSampleCert = 4

	data := testMessage("hello world").IntoStateProofMessageHash()
	provenWt := uint64(totalWeight / 2)

	var parts []basics.Participant
	var sigs []merklesignature.Signature
	for i := 0; i < npartHi; i++ {
		part, sig := createParticipantAndSignature(a, totalWeight, npartHi, data)
		parts = append(parts, part)
		sigs = append(sigs, sig)
	}

	for i := 0; i < npartLo; i++ {
		part, sig := createParticipantAndSignature(a, totalWeight, npartLo, data)
		parts = append(parts, part)
		sigs = append(sigs, sig)
	}

	partcom, err := merklearray.BuildVectorCommitmentTree(basics.ParticipantsArray(parts), crypto.HashFactory{HashType: HashType})
	a.NoError(err)

	b, err := MakeBuilder(data, stateProofIntervalForTests, uint64(totalWeight/2), parts, partcom, targetForSampleCert)
	a.NoError(err)

	for i := 0; i < npart; i++ {
		a.False(b.Present(uint64(i)))
		a.NoError(b.IsValid(uint64(i), &sigs[i], true))
		b.Add(uint64(i), sigs[i])
	}

	cert, err := b.Build()
	a.NoError(err)

	verif, err := MkVerifier(partcom.Root(), provenWt, targetForSampleCert)
	a.NoError(err)

	err = verif.Verify(stateProofIntervalForTests, data, cert)
	a.NoError(err, "failed to verify the compact cert")

	certenc, err := cert.createSnarkFriendlyCert(data[:])
	a.NoError(err)

	fmt.Printf(toZokCode(certenc, verif, testMessage("hello world").IntoStateProofMessageHash(), stateProofIntervalForTests))

}

func createParticipantAndSignature(a *require.Assertions, totalWeight int, npartHi int, data MessageHash) (basics.Participant, merklesignature.Signature) {
	key := generateTestSigner(0, uint64(stateProofIntervalForTests)*7+1, stateProofIntervalForTests, a)
	part := basics.Participant{
		PK:     *key.GetVerifier(),
		Weight: uint64(totalWeight / 2 / npartHi),
	}

	signerInRound := key.GetSigner(stateProofIntervalForTests)
	sig, err := signerInRound.SignBytes(data[:])
	a.NoError(err, "failed to create keys")

	return part, sig
}
