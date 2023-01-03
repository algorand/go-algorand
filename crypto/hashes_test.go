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
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"

	"github.com/stretchr/testify/require"
)

func TestHashFactoryCreatingNewHashes(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	h := HashFactory{HashType: Sha512_256}.NewHash()

	a.NotNil(h)
	a.Equal(Sha512_256Size, h.Size())

	h = HashFactory{HashType: Sumhash}.NewHash()
	a.NotNil(h)
	a.Equal(SumhashDigestSize, h.Size())

	h = HashFactory{HashType: Sha256}.NewHash()
	a.NotNil(h)
	a.Equal(Sha256Size, h.Size())
}

func TestHashSum(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	h := HashFactory{HashType: Sha512_256}.NewHash()

	a.NotNil(h)
	a.Equal(Sha512_256Size, h.Size())

	dgst := HashObj(TestingHashable{})
	a.Equal(GenericHashObj(h, TestingHashable{}), dgst[:])

}

func TestEmptyHash(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	h := HashFactory{HashType: Sha512_256}
	h.HashType = MaxHashType
	hash := h.NewHash()
	a.Equal(0, hash.Size())
	a.Equal(0, hash.BlockSize())

	var msg [4]byte
	len, err := hash.Write(msg[:])
	a.Equal(0, len)
	a.Error(err)

	a.Equal(0, hash.BlockSize())
	var emptySlice []byte
	a.Equal(emptySlice, hash.Sum(nil))
}
