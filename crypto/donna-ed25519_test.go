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
	"math/rand"
	"testing"
)

func randString2() (b TestingHashable) {
	d := make([]byte, 20)
	_, err := rand.Read(d)
	if err != nil {
		panic(err)
	}
	return TestingHashable{d}
}

func TestDonnaCurve25519SignVerify(t *testing.T) {
	randString := randString2()
	var seed DonnaSeed
	RandBytes(seed[:])
	donnaSecrets := GenerateSignatureSecretsDonna(seed)
	donnaSecrets.Sign(randString)
}

func TestGenerateSignatureSecretsBoth(t *testing.T) {
	var s Seed
	RandBytes(s[:])
	refSodium := GenerateSignatureSecrets(s)

	var sDonna DonnaSeed
	copy(sDonna[:], s[:])
	refDonna := GenerateSignatureSecretsDonna(sDonna)
	if bytes.Compare(refSodium.SignatureVerifier[:], refDonna.DonnaSignatureVerifier[:]) != 0 {
		t.Errorf("libdonna and soduim public keys are not consistent ")
		return
	}
	if bytes.Compare(refSodium.SK[:], refDonna.SK[:]) != 0 {
		t.Errorf("libdonna and soduim are not consistent ")
		return
	}
}

func makeDonnaSecret() *DonnaSignatureSecrets {
	var s DonnaSeed
	RandBytes(s[:])
	return GenerateSignatureSecretsDonna(s)
}

func signVerifyDonna(t *testing.T, c *DonnaSignatureSecrets, c2 *DonnaSignatureSecrets) {
	s := randString()
	sig := c.Sign(s)
	if !c.Verify(s, sig) {
		t.Errorf("correct signature failed to verify (plain)")
	}

	s2 := randString()
	sig2 := c.Sign(s2)
	if c.Verify(s, sig2) {
		t.Errorf("wrong message incorrectly verified (plain)")
	}

	sig3 := c2.Sign(s)
	if c.Verify(s, sig3) {
		t.Errorf("wrong key incorrectly verified (plain)")
	}

	if c.Verify(s2, sig3) {
		t.Errorf("wrong message+key incorrectly verified (plain)")
	}
}

func TestSinging(t *testing.T) {
	signVerifyDonna(t, makeDonnaSecret(), makeDonnaSecret())
}
