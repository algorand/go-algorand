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
	"github.com/stretchr/testify/require"
	"testing"
)

func TestStoringKeys(t *testing.T) {
	a := require.New(t)

	s := generateTestSigner(0, 4096, 345, a)
	k := s.keyStore
	defer k.store.Close()

	a.Equal(countKeysInRange(0, 4096, 345), length(s, a))
	count, err := k.DropKeys(700)
	a.NoError(err)
	a.Equal(2, int(count))
	a.Equal(countKeysInRange(700, 4096, 345), length(s, a))
}

func TestDroppingKeys(t *testing.T) {
	a := require.New(t)

	s := generateTestSigner(25, 1023, 23, a)
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
	a := require.New(t)

	s := generateTestSigner(25, 1023, 23, a)
	k := s.keyStore
	defer k.store.Close()

	s2 := &Signer{}
	a.NoError(s2.Restore(k.store))
	a.Equal(countKeysInRange(25, 1023, 23), length(s2, a))
}

func countKeysInRange(firstValid uint64, lastValid uint64, interval uint64) int {
	keysSkipped := firstValid / interval
	keysUpTo := lastValid / interval

	return int(keysUpTo - keysSkipped)
}
