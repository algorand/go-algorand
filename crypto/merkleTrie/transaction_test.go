// Copyright (C) 2019-2020 Algorand, Inc.
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

package merkletrie

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
)

func TestTransactions(t *testing.T) {
	mt := MakeMerkleTrie()
	// create 500 hashes.
	hashes := make([]crypto.Digest, 500)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte(i / 256)})
	}

	// add the first 20 hashes:
	for i := 0; i < 20; i++ {
		added, err := mt.Add(hashes[i][:])
		require.NotEqual(t, false, added)
		require.NoError(t, err)
	}

	baseline, err := mt.RootHash()
	require.NoError(t, err)
	tx := mt.BeginTransaction()
	for i := 20; i < 30; i++ {
		added, err := tx.Add(hashes[i][:])
		require.NotEqual(t, false, added)
		require.NoError(t, err)
	}
	beforeRollback, err := mt.RootHash()
	require.NotEqual(t, baseline, beforeRollback)
	require.NoError(t, err)

	rolledBackCount, err := tx.Rollback()
	require.Equal(t, nil, err)
	require.Equal(t, 10, rolledBackCount)
	afterRollback, err := mt.RootHash()
	require.Equal(t, baseline, afterRollback)
	require.Equal(t, nil, err)
}

func TestTransactionsFailedRollback(t *testing.T) {
	mt := MakeMerkleTrie()
	// create 500 hashes.
	hashes := make([]crypto.Digest, 500)
	for i := 0; i < len(hashes); i++ {
		hashes[i] = crypto.Hash([]byte{byte(i % 256), byte(i / 256)})
	}

	// add the first 20 hashes:
	for i := 0; i < 20; i++ {
		added, err := mt.Add(hashes[i][:])
		require.NotEqual(t, false, added)
		require.NoError(t, err)
	}

	baseline, err := mt.RootHash()
	require.NoError(t, err)
	tx := mt.BeginTransaction()
	for i := 20; i < 30; i++ {
		added, err := tx.Add(hashes[i][:])
		require.NotEqual(t, false, added)
		require.NoError(t, err)
	}

	// remove one of the hashes that we added. this would break the rollback.
	deleted, err := mt.Delete(hashes[25][:])
	require.Equal(t, true, deleted)
	require.NoError(t, err)

	beforeRollback, err := mt.RootHash()
	require.NotEqual(t, baseline, beforeRollback)
	require.NoError(t, err)

	rolledBackCount, err := tx.Rollback()
	require.Equal(t, errTransactionRollbackFailed, err)
	require.Equal(t, 5, rolledBackCount)

	afterRollback, err := mt.RootHash()
	require.Equal(t, beforeRollback, afterRollback)
	require.NoError(t, err)
}
