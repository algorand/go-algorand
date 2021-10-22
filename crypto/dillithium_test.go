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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDilithiumSignAndVerify(t *testing.T) {
	a := require.New(t)
	for i := 0; i < 100; i++ {
		dsigner := NewDilithiumSigner()
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(i))
		bs := sha256.Sum256(b)
		sig := dsigner.SignBytes(bs[:])
		//sig := dil2Sign(sk, bs[:])
		dvf := dsigner.GetVerifyingKey()

		a.NoError(dvf.GetVerifier().VerifyBytes(bs[:], sig))
	}
}

func TestDilithiumSignerImplemantation(t *testing.T) {
	a := require.New(t)
	dsigner := NewDilithiumSigner()

	sig := dsigner.Sign(TestingHashable{})

	dvf := dsigner.GetVerifyingKey()
	dverifier := dvf.GetVerifier()
	a.NoError(dverifier.Verify(TestingHashable{}, sig))
	a.Error(dverifier.Verify(TestingHashable{
		data: []byte{1, 2, 3},
	}, sig))
	sig[0]++
	a.Error(dverifier.Verify(TestingHashable{}, sig))

	bs := sha256.Sum256(make([]byte, 8))
	sig2 := dsigner.SignBytes(bs[:])
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
	sig = dsigner.Sign(hashableWithData)
	a.NoError(dverifier.Verify(hashableWithData, sig))

	sig = dsigner.Sign(hashableWithData)
	hashableWithData.data[0]++
	a.Error(dverifier.Verify(hashableWithData, sig))
	hashableWithData.data[0]--

	sig[0]++
	a.Error(dverifier.Verify(hashableWithData, sig))
}
