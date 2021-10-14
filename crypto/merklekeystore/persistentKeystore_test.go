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

package merklekeystore

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestStoringKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	s := generateTestSigner(crypto.DilithiumType, 0, 4096, 345, a)
	k := s.keyStore
	defer k.store.Close()

	a.Equal(countKeysInRange(0, 4096, 345), length(s, a))
	count, err := k.DropKeys(700)
	a.NoError(err)
	a.Equal(2, int(count))
	a.Equal(countKeysInRange(700, 4096, 345), length(s, a))
}

func TestDroppingKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	s := generateTestSigner(crypto.DilithiumType, 25, 1023, 23, a)
	k := s.keyStore
	defer k.store.Close()

	a.Equal(countKeysInRange(25, 1023, 23), length(s, a))
	count, err := k.DropKeys(600)
	a.NoError(err)
	a.Equal(countKeysInRange(25, 600, 23), int(count))
	a.Equal(countKeysInRange(601, 1023, 23), length(s, a))

	count, err = k.DropKeys(601)
	a.NoError(err)
	a.Equal(0, int(count))
	a.Equal(countKeysInRange(602, 1023, 23), length(s, a))

	count, err = k.DropKeys(1023)
	a.NoError(err)
	a.Equal(countKeysInRange(602, 1023, 23), int(count))
	a.Equal(0, length(s, a))
}

func TestPersistRestore(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	s := generateTestSigner(crypto.DilithiumType, 25, 1023, 23, a)
	k := s.keyStore
	defer k.store.Close()

	s2 := &Signer{}
	a.NoError(s2.Restore(k.store))
	a.Equal(countKeysInRange(25, 1023, 23), length(s2, a))
}

func BenchmarkFetchKeys(b *testing.B) {
	a := require.New(b)

	start := uint64(1)
	end := uint64(3000000)
	interval := uint64(128)
	s := generateTestSigner(crypto.DilithiumType, start, end, interval, a)
	defer s.keyStore.store.Close()
	b.ResetTimer()

	j := interval
	for i := 0; i < b.N; i++ {
		_, _ = s.keyStore.GetKey(j)
		j += interval
		if j > end {
			j = interval
		}
	}
}

func BenchmarkTrimKeys(b *testing.B) {
	a := require.New(b)
	start := uint64(1)
	end := uint64(3000000)
	interval := uint64(128)
	s := generateTestSigner(crypto.DilithiumType, start, end, interval, a)
	defer s.keyStore.store.Close()
	b.ResetTimer()

	j := interval
	for i := 0; i < b.N; i++ {
		_, _ = s.Trim(j)
		j += interval
		if j > end {
			j = interval
		}
	}
}

func countKeysInRange(firstValid uint64, lastValid uint64, interval uint64) int {
	keysSkipped := firstValid / interval
	keysUpTo := lastValid / interval

	return int(keysUpTo - keysSkipped)
}
