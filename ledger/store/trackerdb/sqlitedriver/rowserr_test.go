// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	storetesting "github.com/algorand/go-algorand/ledger/store/testing"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// The tests in this file check that errors which end a query's row iteration early are
// returned, rather than treated as the end of the results. Each one first runs the call
// against the real table, then swaps in a view that fails mid-iteration.

// rowsErrTestDB returns a transaction on a fresh database initialized with one online
// account that holds an asset, so the accountbase, resources, onlineaccounts, and
// onlineroundparamstail tables all have rows.
func rowsErrTestDB(t *testing.T) *sql.Tx {
	dbs, _ := storetesting.DbOpenTest(t, true)
	storetesting.SetDbLogging(t, dbs)
	t.Cleanup(dbs.Close)

	tx, err := dbs.Wdb.Handle.Begin()
	require.NoError(t, err)
	t.Cleanup(func() { tx.Rollback() })

	var addr basics.Address
	crypto.RandBytes(addr[:])
	ad := ledgertesting.RandomOnlineAccountData(0)
	ad.VoteLastValid = 1000
	ad.Assets = map[basics.AssetIndex]basics.AssetHolding{1: {Amount: 5}}
	AccountsInitTest(t, tx, map[basics.Address]basics.AccountData{addr: ad}, protocol.ConsensusCurrentVersion)
	return tx
}

func TestRowsErrLoadTxTail(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tx := rowsErrTestDB(t)
	arw := NewAccountsSQLReaderWriter(tx)

	roundData := make([][]byte, 3)
	for i := range roundData {
		data := trackerdb.TxTailRound{Hdr: bookkeeping.BlockHeader{TimeStamp: int64(i + 1)}}
		roundData[i] = protocol.Encode(&data)
	}
	require.NoError(t, arw.TxtailNewRound(context.Background(), 1, roundData, 0))

	data, _, _, err := arw.LoadTxTail(context.Background(), 3)
	require.NoError(t, err)
	require.Len(t, data, 3)

	ReplaceTableWithFailingViewTest(t, tx, "txtail")
	data, _, _, err = arw.LoadTxTail(context.Background(), 3)
	require.ErrorContains(t, err, FailingViewErrorTest)
	require.Nil(t, data)
}

func TestRowsErrOnlineAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tx := rowsErrTestDB(t)
	arw := NewAccountsSQLReaderWriter(tx)

	all, err := arw.OnlineAccountsAll(0)
	require.NoError(t, err)
	require.Len(t, all, 1)
	expired, err := arw.ExpiredOnlineAccountsForRound(0, 2000, 1, 0)
	require.NoError(t, err)
	require.Len(t, expired, 1)

	ReplaceTableWithFailingViewTest(t, tx, "onlineaccounts")

	all, err = arw.OnlineAccountsAll(0)
	require.ErrorContains(t, err, FailingViewErrorTest)
	require.Nil(t, all)

	expired, err = arw.ExpiredOnlineAccountsForRound(0, 2000, 1, 0)
	require.ErrorContains(t, err, FailingViewErrorTest)
	require.Nil(t, expired)

	// The genesis online account has updround 0, so it would be considered for deletion.
	err = arw.onlineAccountsDelete(1, "onlineaccounts")
	require.ErrorContains(t, err, FailingViewErrorTest)
	var count int
	require.NoError(t, tx.QueryRow("SELECT count(1) FROM onlineaccounts_orig").Scan(&count))
	require.Equal(t, 1, count)
}

func TestRowsErrAccountsOnlineRoundParams(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tx := rowsErrTestDB(t)
	arw := NewAccountsSQLReaderWriter(tx)

	params, _, err := arw.AccountsOnlineRoundParams()
	require.NoError(t, err)
	require.NotEmpty(t, params)

	ReplaceTableWithFailingViewTest(t, tx, "onlineroundparamstail")
	params, _, err = arw.AccountsOnlineRoundParams()
	require.ErrorContains(t, err, FailingViewErrorTest)
	require.Nil(t, params)
}

func TestRowsErrLoadAllFullAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	tx := rowsErrTestDB(t)
	arw := NewAccountsSQLReaderWriter(tx)
	noop := func(basics.Address, basics.AccountData) {}

	count, err := arw.LoadAllFullAccounts(context.Background(), "accountbase", "resources", noop)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	// The failing resources query is issued by LoadFullAccount for each account.
	ReplaceTableWithFailingViewTest(t, tx, "resources")
	_, err = arw.LoadAllFullAccounts(context.Background(), "accountbase", "resources", noop)
	require.ErrorContains(t, err, FailingViewErrorTest)
}

// runOrderedAccountsIter calls Next until the iterator reports an error or completes, and
// returns the final error (sql.ErrNoRows on success).
func runOrderedAccountsIter(t *testing.T, iter *orderedAccountsIter) error {
	for range 100 {
		_, _, err := iter.Next(context.Background())
		if err != nil {
			return err
		}
	}
	require.FailNow(t, "orderedAccountsIter did not finish")
	return nil
}

func TestRowsErrOrderedAccountsIter(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("ok", func(t *testing.T) {
		t.Parallel()
		tx := rowsErrTestDB(t)
		require.ErrorIs(t, runOrderedAccountsIter(t, MakeOrderedAccountsIter(tx, 10)), sql.ErrNoRows)
	})

	// accountbase fails before any account is read, in processAllBaseAccountRecords
	t.Run("accountbase", func(t *testing.T) {
		t.Parallel()
		tx := rowsErrTestDB(t)
		ReplaceTableWithFailingViewTest(t, tx, "accountbase")
		require.ErrorContains(t, runOrderedAccountsIter(t, MakeOrderedAccountsIter(tx, 10)), FailingViewErrorTest)
	})

	// resources fails while gathering the first account's resources, in processAllResources
	t.Run("resources", func(t *testing.T) {
		t.Parallel()
		tx := rowsErrTestDB(t)
		ReplaceTableWithFailingViewTest(t, tx, "resources")
		require.ErrorContains(t, runOrderedAccountsIter(t, MakeOrderedAccountsIter(tx, 10)), FailingViewErrorTest)
	})

	// With no accounts, resources are only read by the check that no resource rows are left over.
	t.Run("leftover resources", func(t *testing.T) {
		t.Parallel()
		tx := rowsErrTestDB(t)
		_, err := tx.Exec("DELETE FROM accountbase")
		require.NoError(t, err)
		ReplaceTableWithFailingViewTest(t, tx, "resources")
		require.ErrorContains(t, runOrderedAccountsIter(t, MakeOrderedAccountsIter(tx, 10)), FailingViewErrorTest)
	})

	// accountsiteratorhashes is created by the iterator itself, so swap it just before it is queried.
	t.Run("hashes", func(t *testing.T) {
		t.Parallel()
		tx := rowsErrTestDB(t)
		iter := MakeOrderedAccountsIter(tx, 10)
		for iter.step != oaiStepSelectFromOrderedTable {
			_, _, err := iter.Next(context.Background())
			require.NoError(t, err)
		}
		ReplaceTableWithFailingViewTest(t, tx, "accountsiteratorhashes")
		require.ErrorContains(t, runOrderedAccountsIter(t, iter), FailingViewErrorTest)
	})
}
