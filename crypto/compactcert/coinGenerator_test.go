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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// make sure that all the fields in the coinChoiceSeed are being part of the hash.
// If this test breaks we need to make sure to update the SNARK prover and verifier as well.
func TestCoinFixedLengthHash(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	var sigcom = make(crypto.GenericDigest, HashSize)
	var partcom = make(crypto.GenericDigest, HashSize)
	var data StateProofMessageHash

	crypto.RandBytes(sigcom[:])
	crypto.RandBytes(partcom[:])
	crypto.RandBytes(data[:])

	choice := coinChoiceSeed{
		partCommitment: partcom,
		lnProvenWeight: 454197,
		sigCommitment:  sigcom,
		signedWeight:   1 << 10,
		data:           data,
	}

	rep := crypto.HashRep(&choice)
	a.Equal(275, len(rep))
}

func TestHashCoin(t *testing.T) {
	partitiontest.PartitionTest(t)

	var slots [32]uint64
	var sigcom = make(crypto.GenericDigest, HashSize)
	var partcom = make(crypto.GenericDigest, HashSize)
	var msgHash StateProofMessageHash

	crypto.RandBytes(sigcom[:])
	crypto.RandBytes(partcom[:])
	crypto.RandBytes(msgHash[:])

	choice := coinChoiceSeed{
		signedWeight:   uint64(len(slots)),
		sigCommitment:  sigcom,
		partCommitment: partcom,
		data:           msgHash,
	}
	coinHash := makeCoinGenerator(&choice)

	for j := uint64(0); j < 1000; j++ {
		coin := coinHash.getNextCoin()
		if coin >= uint64(len(slots)) {
			t.Errorf("hashCoin out of bounds")
		}

		slots[coin]++
	}

	for i, count := range slots {
		if count < 3 {
			t.Errorf("slot %d too low: %d", i, count)
		}
		if count > 100 {
			t.Errorf("slot %d too high: %d", i, count)
		}
	}
}

func BenchmarkHashCoin(b *testing.B) {
	var sigcom = make(crypto.GenericDigest, HashSize)
	var partcom = make(crypto.GenericDigest, HashSize)
	var msgHash StateProofMessageHash

	crypto.RandBytes(sigcom[:])
	crypto.RandBytes(partcom[:])
	crypto.RandBytes(msgHash[:])

	choice := coinChoiceSeed{
		signedWeight:   1025,
		sigCommitment:  sigcom,
		partCommitment: partcom,
		data:           msgHash,
	}
	coinHash := makeCoinGenerator(&choice)

	for i := 0; i < b.N; i++ {
		coinHash.getNextCoin()
	}
}

func BenchmarkHashCoinGenerate(b *testing.B) {
	var sigcom = make(crypto.GenericDigest, HashSize)
	var partcom = make(crypto.GenericDigest, HashSize)
	var msgHash StateProofMessageHash

	crypto.RandBytes(sigcom[:])
	crypto.RandBytes(partcom[:])
	crypto.RandBytes(msgHash[:])

	choice := coinChoiceSeed{
		signedWeight:   1025,
		sigCommitment:  sigcom,
		partCommitment: partcom,
		data:           msgHash,
	}

	for i := 0; i < b.N; i++ {
		makeCoinGenerator(&choice)
	}
}
