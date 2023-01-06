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

package merklesignature

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestBuilderSanity(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	numOfKeys := uint64(100)
	keys, err := KeysBuilder(numOfKeys)
	a.NoError(err)
	a.Equal(uint64(len(keys)), numOfKeys)

	s, err := keys[0].SignBytes([]byte{0})
	a.NoError(err)

	v := keys[0].GetVerifyingKey()
	err = v.VerifyBytes([]byte{0}, s)
	a.NoError(err)
}

func TestBuilderFitsToCPUs(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	numOfKeys := uint64(runtime.NumCPU() * 2)
	keys, err := KeysBuilder(numOfKeys)
	a.NoError(err)
	a.Equal(numOfKeys, uint64(len(keys)))

}

func TestBuilderOneKey(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	numOfKeys := uint64(1)
	keys, err := KeysBuilder(numOfKeys)
	a.NoError(err)
	a.Equal(numOfKeys, uint64(len(keys)))
}

func TestBuilderZeroKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	numOfKeys := uint64(0)
	keys, err := KeysBuilder(numOfKeys)
	a.NoError(err)
	a.Equal(numOfKeys, uint64(len(keys)))
}

func BenchmarkMerkleSignatureSchemeGenerate(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		New(0, 3000000, 256)
	}
}
