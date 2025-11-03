// Copyright (C) 2019-2025 Algorand, Inc.
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

package sqlitedriver

import (
	"context"
	"database/sql"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	storetesting "github.com/algorand/go-algorand/ledger/store/testing"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

func TestKeyPrefixIntervalPreprocessing(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testCases := []struct {
		input            []byte
		outputPrefix     []byte
		outputPrefixIncr []byte
	}{
		{input: []byte{0xAB, 0xCD}, outputPrefix: []byte{0xAB, 0xCD}, outputPrefixIncr: []byte{0xAB, 0xCE}},
		{input: []byte{0xFF}, outputPrefix: []byte{0xFF}, outputPrefixIncr: nil},
		{input: []byte{0xFE, 0xFF}, outputPrefix: []byte{0xFE, 0xFF}, outputPrefixIncr: []byte{0xFF}},
		{input: []byte{0xFF, 0xFF}, outputPrefix: []byte{0xFF, 0xFF}, outputPrefixIncr: nil},
		{input: []byte{0xAB, 0xCD}, outputPrefix: []byte{0xAB, 0xCD}, outputPrefixIncr: []byte{0xAB, 0xCE}},
		{input: []byte{0x1E, 0xFF, 0xFF}, outputPrefix: []byte{0x1E, 0xFF, 0xFF}, outputPrefixIncr: []byte{0x1F}},
		{input: []byte{0xFF, 0xFE, 0xFF, 0xFF}, outputPrefix: []byte{0xFF, 0xFE, 0xFF, 0xFF}, outputPrefixIncr: []byte{0xFF, 0xFF}},
		{input: []byte{0x00, 0xFF}, outputPrefix: []byte{0x00, 0xFF}, outputPrefixIncr: []byte{0x01}},
		{input: []byte(string("bx:123")), outputPrefix: []byte(string("bx:123")), outputPrefixIncr: []byte(string("bx:124"))},
		{input: []byte{}, outputPrefix: []byte{}, outputPrefixIncr: nil},
		{input: nil, outputPrefix: []byte{}, outputPrefixIncr: nil},
		{input: []byte{0x1E, 0xFF, 0xFF}, outputPrefix: []byte{0x1E, 0xFF, 0xFF}, outputPrefixIncr: []byte{0x1F}},
		{input: []byte{0xFF, 0xFE, 0xFF, 0xFF}, outputPrefix: []byte{0xFF, 0xFE, 0xFF, 0xFF}, outputPrefixIncr: []byte{0xFF, 0xFF}},
		{input: []byte{0x00, 0xFF}, outputPrefix: []byte{0x00, 0xFF}, outputPrefixIncr: []byte{0x01}},
	}
	for _, tc := range testCases {
		actualOutputPrefix, actualOutputPrefixIncr := keyPrefixIntervalPreprocessing(tc.input)
		require.Equal(t, tc.outputPrefix, actualOutputPrefix)
		require.Equal(t, tc.outputPrefixIncr, actualOutputPrefixIncr)
	}
}

// TestAccountsDbQueriesCreateClose tests to see that we can create the accountsDbQueries and close it.
// it also verify that double-closing it doesn't create an issue.
func TestAccountsDbQueriesCreateClose(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := storetesting.DbOpenTest(t, true)
	storetesting.SetDbLogging(t, dbs)
	defer dbs.Close()

	err := dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		AccountsInitTest(t, tx, make(map[basics.Address]basics.AccountData), protocol.ConsensusCurrentVersion)
		return nil
	})
	require.NoError(t, err)
	qs, err := AccountsInitDbQueries(dbs.Rdb.Handle)
	require.NoError(t, err)
	require.NotNil(t, qs.lookupAccountStmt)
	qs.Close()
	require.Nil(t, qs.lookupAccountStmt)
	qs.Close()
	require.Nil(t, qs.lookupAccountStmt)
}

// TestWrapIOError ensures that SQL ErrIOErr is converted to trackerdb.ErrIoErr
// github.com/mattn/go-sqlite3/blob/master/error.go
// github.com/mattn/go-sqlite3/blob/master/sqlite3.go#L830
func TestWrapIOError(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// This structure is how sqlite3 returns Errors
	err := sqlite3.Error{Code: sqlite3.ErrIoErr}
	var trackerIOErr *trackerdb.ErrIoErr
	require.ErrorAs(t, wrapIOError(err), &trackerIOErr)

	// ErrNo10 is a sqlite3 error code for ErrIoErr
	err = sqlite3.Error{Code: sqlite3.ErrNo(10)}
	require.ErrorAs(t, wrapIOError(err), &trackerIOErr)

	err = sqlite3.Error{Code: sqlite3.ErrSchema}
	require.NotErrorAs(t, wrapIOError(err), &trackerIOErr)

	// confirm that double wrapping only applies once
	err = sqlite3.Error{Code: sqlite3.ErrIoErr}
	require.Equal(t, wrapIOError(err), wrapIOError(wrapIOError(err)))

}
