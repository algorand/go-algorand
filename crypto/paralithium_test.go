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
	"crypto/sha256"
	"encoding/binary"
	"github.com/algorand/go-algorand/test/partitiontest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDilithiumSignAndVerify(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	for i := 0; i < 100; i++ {
		psigner := GenerateParalithiumSigner()
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(i))
		bs := sha256.Sum256(b)
		sig := psigner.SignBytes(bs[:])
		//sig := dil2Sign(sk, bs[:])
		dvf := psigner.GetVerifyingKey()

		a.NoError(dvf.GetVerifier().VerifyBytes(bs[:], sig))
	}
}

func TestDilithiumSignerImplemantation(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	psigner := GenerateParalithiumSigner()

	sig := psigner.Sign(TestingHashable{})

	dvf := psigner.GetVerifyingKey()
	dverifier := dvf.GetVerifier()
	a.NoError(dverifier.Verify(TestingHashable{}, sig))
	a.Error(dverifier.Verify(TestingHashable{
		data: []byte{1, 2, 3},
	}, sig))
	sig[0]++
	a.Error(dverifier.Verify(TestingHashable{}, sig))

	bs := sha256.Sum256(make([]byte, 8))
	sig2 := psigner.SignBytes(bs[:])
	a.NoError(dverifier.VerifyBytes(bs[:], sig2))

	bs2 := bs
	bs2[0]++
	a.Error(dverifier.VerifyBytes(bs2[:], sig2))
	sig2[0]++
	a.Error(dverifier.VerifyBytes(bs[:], sig2))

	// Non-empty hashable:
	hashableWithData := TestingHashable{
		data: []byte{1, 2, 3},
	}
	sig = psigner.Sign(hashableWithData)
	a.NoError(dverifier.Verify(hashableWithData, sig))

	sig = psigner.Sign(hashableWithData)
	hashableWithData.data[0]++
	a.Error(dverifier.Verify(hashableWithData, sig))
	hashableWithData.data[0]--

	sig[0]++
	a.Error(dverifier.Verify(hashableWithData, sig))
}
