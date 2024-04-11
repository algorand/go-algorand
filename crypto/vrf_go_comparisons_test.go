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
	"flag"
	mathrand "math/rand"
	"testing"
)

var (
	flagRunPureGoComparisonsTests  = flag.Bool("purego-compare", false, "If enabled, run comparison tests between C and pure Go VRF implementations.")
	flagRunPureGoComparisonsTestsN = flag.Int("purego-compare-iterations", 10000, "Specifies the number of iterations to perform.")
	flagRunPureGoComparisonsSeed   = flag.Int("purego-compare-seed", 42, "Specifies the random number generator seed for the comparison tests.")
)

func TestPureGoImplementationComparison(t *testing.T) {
	if !*flagRunPureGoComparisonsTests {
		t.Skip("skipping pure go comparison tests since -purego-compare flag is not supplied")
	}
	N := *flagRunPureGoComparisonsTestsN
	t.Log("running with", N, "iterations with seed of", *flagRunPureGoComparisonsSeed)
	pks := make([]VrfPubkey, N)
	sks := make([]VrfPrivkey, N)
	strs := make([][]byte, N)
	proofs := make([]VrfProof, N)
	randSource := mathrand.New(mathrand.NewSource(int64(*flagRunPureGoComparisonsSeed)))

	for i := 0; i < N; i++ {
		pks[i], sks[i] = VrfKeygen()
		strs[i] = make([]byte, 100)
		_, err := randSource.Read(strs[i])
		if err != nil {
			panic(err)
		}
	}
	t.Log("done generating keys")

	for i := 0; i < N; i++ {
		var ok bool
		proofs[i], ok = sks[i].proveBytes(strs[i])
		goProof, goOk := sks[i].proveBytesGo(strs[i])

		if i > 0 && i%(N/10) == 0 {
			t.Logf("%v/%v", i, N)
		}

		if ok != goOk {
			t.Errorf("non-matching results: %d sk:%x pk:%x str:%x %v %v\n", i, sks[i][:32], pks[i], strs[i], ok, goOk)
		}
		if bytes.Compare(proofs[i][:], goProof[:]) != 0 {
			t.Errorf("non-matching results: %x %x %x\n", strs[i], proofs[i], goProof)
		}
		// compare verify outputs
		_, cVerify := pks[i].verifyBytes(proofs[i], strs[i])
		_, goVerify := pks[i].verifyBytes(proofs[i], strs[i])
		if cVerify != goVerify {
			t.Errorf("non-matching verify results.")
		}
	}
}
