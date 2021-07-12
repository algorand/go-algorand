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
	"flag"
	"math/rand"
	"testing"
	"time"

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

var runcountP *uint64 = flag.Uint64("sortition-exausting-test-count", 1000, "number of sortition tests to run")

func TestSortitionExhausting(t *testing.T) {
	rand.Seed(time.Now().Unix())

	errsum := uint64(0)
	errfracsum := float64(0.0)
	maxerr := uint64(0)
	runcount := *runcountP
	const totalMoney = 10000000000000000
	for i := uint64(0); i < runcount; i++ {
		money := uint64(rand.Int63n(totalMoney))
		// committee size [30.0 .. 60.0)
		expectedSize := (rand.Float64() * 30.0) + 30.0
		n := float64(money)
		p := expectedSize / float64(totalMoney)
		ratio := rand.Float64()
		boost := boostCdfWalk(n, p, ratio, money)
		gocdf := sortitionPoissonCDFWalk(p, ratio, money)
		var cdferr uint64
		if boost > gocdf {
			cdferr = boost - gocdf
		} else {
			cdferr = gocdf - boost
		}
		if boost != gocdf {
			t.Logf("boost=%d gocdf=%d", boost, gocdf)
		}
		var errfrac float64
		if boost != 0 {
			errfrac = float64(cdferr) / float64(boost)
		} else {
			errfrac = float64(cdferr)
		}
		if cdferr > maxerr {
			maxerr = cdferr
		}
		errsum += cdferr
		errfracsum += errfrac
	}
	t.Logf("%d total err across %d tests, avg=%f (%f), max=%d", errsum, runcount, float64(errsum)/float64(runcount), errfracsum/float64(runcount), maxerr)
}

func boostCdfWrapper(p, ratio float64, money uint64) uint64 {
	return boostCdfWalk(float64(money), p, ratio, money)
}

func cdfBenchmarkInner(b *testing.B, tf func(p, ratio float64, money uint64) uint64) {
	const totalMoney = 10000000000000000
	moneys := make([]uint64, b.N)
	esizes := make([]float64, b.N)
	ratios := make([]float64, b.N)
	for i := 0; i < b.N; i++ {
		moneys[i] = uint64(rand.Int63n(totalMoney))
		esizes[i] = (rand.Float64() * 30.0) + 30.0
		ratios[i] = rand.Float64()
	}
	b.ResetTimer()
	for i, money := range moneys {
		expectedSize := esizes[i]
		ratio := ratios[i]
		p := expectedSize / float64(totalMoney)
		tf(p, ratio, money)
	}
}

func BenchmarkBoostCdfWalk(b *testing.B) {
	cdfBenchmarkInner(b, boostCdfWrapper)
}

func BenchmarkPoissonCdfWalk(b *testing.B) {
	cdfBenchmarkInner(b, sortitionPoissonCDFWalk)
}
