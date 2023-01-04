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
	"math/rand"
	"testing"

	"github.com/algorand/go-algorand/protocol"
)

type TestingHashable struct {
	data []byte
}

func (s TestingHashable) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.TestHashable, s.data
}

func randString() (b TestingHashable) {
	d := make([]byte, 20)
	_, err := rand.Read(d)
	if err != nil {
		panic(err)
	}
	return TestingHashable{d}
}

func signVerify(t *testing.T, c *SignatureSecrets, c2 *SignatureSecrets) {
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

func proveVerifyVrf(t *testing.T, c *VRFSecrets, c2 *VRFSecrets) {
	d := randString()
	pf, ok := c.SK.Prove(d)
	if !ok {
		t.Errorf("failed to construct proof (corrupt vrf secrets?)")
	}
	if ok, _ := c.PK.Verify(pf, d); !ok {
		t.Errorf("correct proof failed to verify (proof)")
	}

	pf3, ok := c2.SK.Prove(d)
	if !ok {
		t.Errorf("failed to construct proof (corrupt vrf secrets?)")
	}
	if ok, _ := c.PK.Verify(pf3, d); ok {
		t.Errorf("wrong key incorrectly verified (proof)")
	}

	d2 := randString()
	if ok, _ := c.PK.Verify(pf, d2); ok {
		t.Errorf("wrong message incorrectly verified (proof)")
	}
}

func BenchmarkHash(b *testing.B) {
	s := randString()
	d := Hash(s.data)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		d = Hash(d[:])
	}
	_ = d
}
