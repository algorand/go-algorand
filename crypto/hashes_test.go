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
	"github.com/algorand/go-algorand/test/partitiontest"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashFactoryCreatingNewHashes(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	hfactory := HashFactory{HashType: Sha512_256}
	h, err := hfactory.NewHash()
	a.NoError(err)
	a.NotNil(h)
	a.Equal(Sha512_256Size, h.Size())

	hfactory = HashFactory{HashType: Sumhash}
	h, err = hfactory.NewHash()
	a.NoError(err)
	a.NotNil(h)
	a.Equal(SumhashDigestSize, h.Size())

	hfactory = HashFactory{HashType: HashType(math.MaxUint64)}
	h, err = hfactory.NewHash()
	a.Error(err)
	a.Nil(h)
}

func TestHashSum(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	hfactory := HashFactory{HashType: Sha512_256}
	h, err := hfactory.NewHash()
	a.NoError(err)
	a.NotNil(h)
	a.Equal(Sha512_256Size, h.Size())

	dgst := HashObj(TestingHashable{})
	a.Equal(GenereicHashObj(h, TestingHashable{}), dgst[:])

}
