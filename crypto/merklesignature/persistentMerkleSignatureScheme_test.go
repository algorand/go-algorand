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

package merklesignature

import (
	"context"
	"database/sql"
	"testing"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

func TestFetchKey(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)
	store := createTestDB(a)
	defer store.Close()

	interval := uint64(256)
	mss, err := New(1, 1000, interval, crypto.FalconType)
	a.NoError(err)
	a.NoError(mss.Persist(*store))

	key, rnd, err := mss.FetchKey(interval*1, *store)
	a.Equal(mss.GetKey(rnd), key)

	key, rnd, err = mss.FetchKey(interval*2, *store)
	a.Equal(mss.GetKey(rnd), key)

	key, rnd, err = mss.FetchKey(interval*5, *store)
	a.Equal(mss.GetKey(rnd), key)

}

func createTestDB(a *require.Assertions) *db.Accessor {
	tmpname := uuid.NewV4().String() // could this just be a constant string instead? does it even matter?
	store, err := db.MakeAccessor(tmpname, false, true)
	a.NoError(err)
	a.NotNil(store)

	err = store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err = tx.Exec(`CREATE TABLE schema (
			tablename TEXT PRIMARY KEY,
			version INTEGER
		);`)
		return err
	})
	a.NoError(err)

	return &store
}
