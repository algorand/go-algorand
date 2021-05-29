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

package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"testing"
)

// ECVRF-ED25519-SHA512-Elligator2 test vectors from: https://www.ietf.org/id/draft-irtf-cfrg-vrf-03.txt appendix A.4
func TestVRFTestVectorsGo(t *testing.T) {
	testVectorGo(t,
		"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", //sk
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", //pk
		"", // alpha
		"b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900", // pi
		"5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc",                                 // beta
	)

	testVectorGo(t,
		"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", //sk
		"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", //pk
		"72", // alpha
		"ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07", // pi
		"94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8",                                 // beta
	)
}

func testVectorGo(t *testing.T, skHex, pkHex, alphaHex, piHex, betaHex string) {
	t.Helper()
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

	pkTest, sk := VrfKeygenFromSeedGo(seed)
	if pkTest != pk {
		t.Errorf("Computed public key does not match the test vector")
	}

	piTest, ok := sk.proveBytesGo(alpha)
	if !ok {
		t.Errorf("Failed to produce a proof")
	}
	if piTest != pi {
		t.Errorf("Proof produced by Prove() does not match the test vector")
	}

	ok, betaTest := pk.verifyBytesGo(pi, alpha)
	if !ok {
		t.Errorf("Verify() fails on proof from the test vector")
	}
	if betaTest != beta {
		t.Errorf("VRF output does not match test vector:\n%x\n%x\n", beta, betaTest)
	}
}

func BenchmarkVrfVerifyGo(b *testing.B) {
	pks := make([]VrfPubkey, b.N)
	strs := make([][]byte, b.N)
	proofs := make([]VrfProof, b.N)
	for i := 0; i < b.N; i++ {
		validPoint := false
		var sk VrfPrivkey
		for !validPoint {
			pks[i], sk = VrfKeygen()
			strs[i] = make([]byte, 100)
			_, err := rand.Read(strs[i])
			if err != nil {
				panic(err)
			}
			var ok bool
			proofs[i], ok = sk.proveBytesGo(strs[i])
			validPoint = ok == true
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = pks[i].verifyBytesGo(proofs[i], strs[i])
	}
}

func BenchmarkProveBytes(b *testing.B) {
	var keySeed [32]byte
	sks := make([]VrfPrivkey, b.N)
	strs := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		_, err := rand.Read(keySeed[:])
		if err != nil {
			panic(err)
		}
		_, sks[i] = VrfKeygenFromSeed(keySeed)
		strs[i] = make([]byte, 100)
		_, err = rand.Read(strs[i])
		if err != nil {
			panic(err)
		}
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sks[i].proveBytes(strs[i])
	}
}

func BenchmarkProveBytesGo(b *testing.B) {
	var keySeed [32]byte
	sks := make([]VrfPrivkey, b.N)
	strs := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		_, err := rand.Read(keySeed[:])
		if err != nil {
			panic(err)
		}
		_, sks[i] = VrfKeygenFromSeed(keySeed)
		strs[i] = make([]byte, 100)
		_, err = rand.Read(strs[i])
		if err != nil {
			panic(err)
		}
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sks[i].proveBytesGo(strs[i])
	}
}

func TestPureGoVrfKeygenFromSeed(t *testing.T) {
	var keySeed [32]byte
	rand.Read(keySeed[:])
	pk1, sk1 := VrfKeygenFromSeed(keySeed)
	pk2, sk2 := VrfKeygenFromSeedGo(keySeed)

	if fmt.Sprint(sk1) != fmt.Sprint(sk2) {
		t.Logf("sk1 %x\n", sk1)
		t.Logf("sk2 %x\n", sk2)
		t.Errorf("sks did not match:%v\n%v", sk1, sk2)
	}
	if fmt.Sprint(pk1) != fmt.Sprint(pk2) {
		t.Logf("pk1 %x\n", pk1)
		t.Logf("pk2 %x\n", pk2)
		t.Errorf("pks did not match:%v\n%v", pk1, pk2)
	}
}

func TestPureGoProveBytes(t *testing.T) {
	var sk VrfPrivkey
	var str []byte

	randSource := mathrand.New(mathrand.NewSource(42))

	var keySeed [32]byte
	copy(keySeed[:], []byte("abcdefghijklmnopqrstuvwxyzfoobars"))
	_, sk = VrfKeygenFromSeed(keySeed)
	str = make([]byte, 100)
	_, err := randSource.Read(str)
	if err != nil {
		panic(err)
	}

	proof1, ok1 := sk.proveBytes(str)
	if !ok1 {
		panic("Failed to construct VRF proof")
	}
	proof2, ok2 := sk.proveBytesGo(str)
	if !ok2 {
		panic("Failed to construct VRF proof")
	}
	if fmt.Sprint(proof1) != fmt.Sprint(proof2) {
		t.Logf("proof1 %x\n", proof1)
		t.Logf("proof2 %x\n", proof2)
		t.Errorf("proofs did not match:%v\n%v", proof1, proof2)
	}
}

func TestPureGoVrfVerify(t *testing.T) {
	var pk VrfPubkey
	var sk VrfPrivkey
	var keySeed [32]byte
	var alpha []byte

	// randSource := mathrand.New(mathrand.NewSource(42))
	// copy(keySeed[:], []byte("abcdefghijklmnopqrstuvwxyzfoobars"))
	skHex := "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	pkHex := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	alphaHex := ""

	mustDecode(t, keySeed[:], skHex)
	mustDecode(t, pk[:], pkHex)
	// alpha is variable-length
	alpha = make([]byte, hex.DecodedLen(len(alphaHex)))
	mustDecode(t, alpha, alphaHex)

	pk, sk = VrfKeygenFromSeedGo(keySeed)
	cgoProof, ok := sk.proveBytes(alpha)
	if !ok {
		panic("Failed to construct VRF proof")
	}
	cgoOk, cgoOut := pk.verifyBytes(cgoProof, alpha)

	proof, ok := sk.proveBytesGo(alpha)
	if !ok {
		panic("Failed to construct VRF proof")
	}
	ok, out := pk.verifyBytesGo(proof, alpha)
	if cgoOk != ok {
		fmt.Println(cgoOk, ok)
		fmt.Printf("cgo: %x\n", cgoOut)
		fmt.Printf("pgo: %x\n", out)
		t.Error("go and cgo implementations differ:", ok, cgoOk)
	}
	if bytes.Compare(cgoOut[:], out[:]) != 0 {
		fmt.Printf("cgo: %x\n", cgoOut)
		fmt.Printf("pgo: %x\n", out)
		t.Error("go and cgo implementations differ:", ok, cgoOk)
	}
}
