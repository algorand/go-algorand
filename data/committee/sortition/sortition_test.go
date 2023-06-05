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

package sortition

import (
	"math/rand"
	"os"
	"strconv"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/sortition"
	"pgregory.net/rapid"
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
	partitiontest.PartitionTest(t)
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

func TestCompareSortitionImpls(tt *testing.T) {
	partitiontest.PartitionTest(tt)

	// if TOTAL_MONEY env var is set, parse uint64 from env
	var envTotalMoney uint64
	if tm := os.Getenv("TOTAL_MONEY"); tm != "" {
		if val, err := strconv.ParseUint(tm, 10, 64); err == nil {
			envTotalMoney = val
			tt.Logf("using TOTAL_MONEY=%d from env", envTotalMoney)
		}
	}

	rapid.Check(tt, func(t *rapid.T) {
		// select one of the protocol committee sizes
		proto := config.Consensus[protocol.ConsensusCurrentVersion]
		expectedSize := rapid.OneOf(
			rapid.Just(proto.NumProposers),
			rapid.Just(proto.SoftCommitteeSize),
			rapid.Just(proto.CertCommitteeSize),
			rapid.Just(proto.NextCommitteeSize),
			rapid.Just(proto.LateCommitteeSize),
			rapid.Just(proto.RedoCommitteeSize),
			rapid.Just(proto.DownCommitteeSize),
		).Draw(t, "expectedSize").(uint64)
		//expectedSize := rapid.Uint64Range(1, totalMoney).Draw(t, "expectedSize").(uint64) // draw random

		// total online circulation (must be at least committee size)
		var totalMoney uint64
		if envTotalMoney != 0 {
			totalMoney = envTotalMoney
		} else {
			const totalMicroAlgos = 10000000000000000
			totalMoney = rapid.Uint64Range(expectedSize, totalMicroAlgos).Draw(t, "totalMoney").(uint64)
		}

		// participating account balance
		money := rapid.Uint64Range(1, totalMoney-1).Draw(t, "money").(uint64)

		// draw random vrf output
		var vrfOutput crypto.Digest
		vrfSeed := int64(rapid.Int64Min(0).Draw(t, "vrfSeed").(int64))
		rnd := rand.New(rand.NewSource(vrfSeed))
		rnd.Read(vrfOutput[:])

		tt.Logf("money %d, totalMoney %d, expectedSize %d, vrfSeed %d, vrfOutput %x", money, totalMoney, expectedSize, vrfSeed, vrfOutput)
		selectedLocal := Select(money, totalMoney, float64(expectedSize), vrfOutput)
		selectedExtern := sortition.Select(money, totalMoney, float64(expectedSize), sortition.Digest(vrfOutput))
		if selectedLocal != selectedExtern {
			t.Fatalf("different results (money %d, totalMoney %d, expectedSize %d, vrfOutput %x): local %d, extern %d",
				money, totalMoney, expectedSize, vrfOutput, selectedLocal, selectedExtern)
		}
	})
}
