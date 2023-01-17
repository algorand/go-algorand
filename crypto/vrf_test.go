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

package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func mustDecode(t *testing.T, out []byte, hexIn string) {
	_, err := hex.Decode(out, []byte(hexIn))
	if err != nil {
		t.Errorf("hex decode error: %v", err)
	}
}

func testVector(t *testing.T, skHex, pkHex, alphaHex, piHex, betaHex string) {
	var seed [32]byte
	// our "secret keys" are 64 bytes: the spec's 32-byte "secret keys" (which we call the "seed") followed by the 32-byte precomputed public key
	// so the 32-byte "SK" in the test vectors is not directly decoded into a VrfPrivkey, it instead has to go through VrfKeypairFromSeed()

	var pk VrfPubkey
	var alpha []byte
	var pi VrfProof
	var beta VrfOutput

	// Decode hex
	mustDecode(t, seed[:], skHex)
	mustDecode(t, pk[:], pkHex)
	mustDecode(t, pi[:], piHex)
	mustDecode(t, beta[:], betaHex)
	// alpha is variable-length
	alpha = make([]byte, hex.DecodedLen(len(alphaHex)))
	mustDecode(t, alpha, alphaHex)

	pkTest, sk := VrfKeygenFromSeed(seed)
	if pkTest != pk {
		t.Errorf("Computed public key does not match the test vector")
	}

	piTest, ok := sk.proveBytes(alpha)
	if !ok {
		t.Errorf("Failed to produce a proof")
	}
	if piTest != pi {
		t.Errorf("Proof produced by Prove() does not match the test vector")
	}

	ok, betaTest := pk.verifyBytes(pi, alpha)
	if !ok {
		t.Errorf("Verify() fails on proof from the test vector")
	}
	if betaTest != beta {
		t.Errorf("VRF output does not match test vector")
	}
}

// ECVRF-ED25519-SHA512-Elligator2 test vectors from: https://www.ietf.org/id/draft-irtf-cfrg-vrf-03.txt appendix A.4
func TestVRFTestVectors(t *testing.T) {
	partitiontest.PartitionTest(t)
	testVector(t,
		"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", //sk
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", //pk
		"", // alpha
		"b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900", // pi
		"5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc",                                 // beta
	)

	testVector(t,
		"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", //sk
		"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", //pk
		"72", // alpha
		"ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07", // pi
		"94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8",                                 // beta
	)
}

func BenchmarkVrfVerify(b *testing.B) {
	pks := make([]VrfPubkey, b.N)
	strs := make([][]byte, b.N)
	proofs := make([]VrfProof, b.N)
	for i := 0; i < b.N; i++ {
		var sk VrfPrivkey
		pks[i], sk = VrfKeygen()
		strs[i] = make([]byte, 100)
		_, err := rand.Read(strs[i])
		if err != nil {
			panic(err)
		}
		var ok bool
		proofs[i], ok = sk.proveBytes(strs[i])
		if !ok {
			panic("Failed to construct VRF proof")
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = pks[i].verifyBytes(proofs[i], strs[i])
	}
}
