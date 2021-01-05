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

package sortition

import (
	"math/rand"
	"testing"

	"github.com/algorand/go-algorand/crypto"
)

func BenchmarkSortition(b *testing.B) {
	b.StopTimer()
	keys := make([]crypto.Digest, b.N)
	for i := 0; i < b.N; i++ {
		rand.Read(keys[i][:])
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		Select(1000000, 1000000000000, 2500, keys[i])
	}
}

func TestSortitionBasic(t *testing.T) {
	hitcount := uint64(0)
	const N = 1000
	const expectedSize = 20
	const myMoney = 100
	const totalMoney = 200
	for i := 0; i < N; i++ {
		var vrfOutput crypto.Digest
		rand.Read(vrfOutput[:])
		selected := Select(myMoney, totalMoney, expectedSize, vrfOutput)
		hitcount += selected
	}
	expected := uint64(N * expectedSize / 2)
	var d uint64
	if expected > hitcount {
		d = expected - hitcount
	} else {
		d = hitcount - expected
	}
	// within 2% good enough
	maxd := expected / 50
	if d > maxd {
		t.Errorf("wanted %d selections but got %d, d=%d, maxd=%d", expected, hitcount, d, maxd)
	}
}
