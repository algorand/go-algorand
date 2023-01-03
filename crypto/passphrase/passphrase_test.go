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

package passphrase

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestGenerateAndRecovery(t *testing.T) {
	partitiontest.PartitionTest(t)

	key := make([]byte, 32)
	for i := 0; i < 1000; i++ {
		// Generate a key
		_, err := rand.Read(key)
		require.NoError(t, err)
		// Go from key -> mnemonic
		m, err := KeyToMnemonic(key)
		// Go from mnemonic -> key
		recovered, err := MnemonicToKey(m)
		require.NoError(t, err)
		require.Equal(t, recovered, key)
	}
}

func TestZeroVector(t *testing.T) {
	partitiontest.PartitionTest(t)

	zeroVector := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	mn := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest"

	m, err := KeyToMnemonic(zeroVector)
	require.NoError(t, err)
	require.Equal(t, mn, m)
	return
}

func TestWordNotInList(t *testing.T) {
	partitiontest.PartitionTest(t)

	mn := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzz invest"
	_, err := MnemonicToKey(mn)
	require.Error(t, err)
	return
}

func TestCorruptedChecksum(t *testing.T) {
	partitiontest.PartitionTest(t)

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	m, err := KeyToMnemonic(key)
	wl := strings.Split(m, sepStr)
	lastWord := wl[len(wl)-1]
	// Shuffle the last word (last 11 bits of checksum)
	wl[len(wl)-1] = wordlist[(indexOf(wordlist, lastWord)+1)%len(wordlist)]
	recovered, err := MnemonicToKey(strings.Join(wl, sepStr))
	require.Error(t, err)
	require.Empty(t, recovered)
}

func TestInvalidKeyLen(t *testing.T) {
	partitiontest.PartitionTest(t)

	badLens := []int{0, 31, 33, 100}
	for _, l := range badLens {
		key := make([]byte, l)
		_, err := rand.Read(key)
		require.NoError(t, err)
		m, err := KeyToMnemonic(key)
		require.Error(t, err)
		require.Empty(t, m)
	}
}

func TestUint11Array(t *testing.T) {
	partitiontest.PartitionTest(t)

	N := 11*8*32 + 1

	for i := 0; i < N; i++ {
		a := make([]byte, i, i)
		b := toUint11Array(a)
		c := toByteArray(b)
		require.True(t, len(c) == len(a) || len(c) == len(a)+1 || len(c) == len(a)+2)
		if i == 0 {
			require.Equal(t, len(c), 0)
		} else {
			require.Equal(t, a, c[:i])
		}
	}

	for i := 0; i < N; i++ {
		a := make([]byte, i, i)
		crypto.RandBytes(a)
		b := toUint11Array(a)
		c := toByteArray(b)
		require.True(t, len(c) == len(a) || len(c) == len(a)+1 || len(c) == len(a)+2)
		if i == 0 {
			require.Equal(t, len(c), 0)
		} else {
			require.Equal(t, a, c[:i])
		}
	}

	for i := 0; i < N; i++ {
		a := make([]uint32, i, i)
		b := toByteArray(a)
		c := toUint11Array(b)
		require.True(t, len(c) == len(a) || len(c) == len(a)+1)
		if i == 0 {
			require.Equal(t, len(c), 0)
		} else {
			require.Equal(t, a, c[:i])
		}
	}

	for i := 0; i < N; i++ {
		a := make([]uint32, i, i)
		for j := 0; j < i; j++ {
			a[j] = uint32(crypto.RandUint64() % ((1 << 11) - 1))
		}
		b := toByteArray(a)
		c := toUint11Array(b)
		require.True(t, len(c) == len(a) || len(c) == len(a)+1)
		if i == 0 {
			require.Equal(t, len(c), 0)
		} else {
			require.Equal(t, a, c[:i])
		}
	}

	for i := 0; i < N; i++ {
		a := make([]uint32, i, i)
		b := toByteArray(a)
		require.True(t, len(b)*8 >= len(a)*11)
	}
}
