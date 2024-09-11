// Copyright (C) 2019-2024 Algorand, Inc.
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
	"crypto/rand"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	storetesting "github.com/algorand/go-algorand/ledger/store/testing"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// Test functions operating on catchpointfirststageinfo table.
func TestCatchpointFirstStageInfoTable(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := storetesting.DbOpenTest(t, true)
	defer dbs.Close()

	ctx := context.Background()

	err := accountsCreateCatchpointFirstStageInfoTable(ctx, dbs.Wdb.Handle)
	require.NoError(t, err)

	crw := NewCatchpointSQLReaderWriter(dbs.Wdb.Handle)

	for _, round := range []basics.Round{4, 6, 8} {
		info := trackerdb.CatchpointFirstStageInfo{
			TotalAccounts: uint64(round) * 10,
		}
		err = crw.InsertOrReplaceCatchpointFirstStageInfo(ctx, round, &info)
		require.NoError(t, err)
	}

	for _, round := range []basics.Round{4, 6, 8} {
		info, exists, err := crw.SelectCatchpointFirstStageInfo(ctx, round)
		require.NoError(t, err)
		require.True(t, exists)

		infoExpected := trackerdb.CatchpointFirstStageInfo{
			TotalAccounts: uint64(round) * 10,
		}
		require.Equal(t, infoExpected, info)
	}

	_, exists, err := crw.SelectCatchpointFirstStageInfo(ctx, 7)
	require.NoError(t, err)
	require.False(t, exists)

	rounds, err := crw.SelectOldCatchpointFirstStageInfoRounds(ctx, 6)
	require.NoError(t, err)
	require.Equal(t, []basics.Round{4, 6}, rounds)

	err = crw.DeleteOldCatchpointFirstStageInfo(ctx, 6)
	require.NoError(t, err)

	rounds, err = crw.SelectOldCatchpointFirstStageInfoRounds(ctx, 9)
	require.NoError(t, err)
	require.Equal(t, []basics.Round{8}, rounds)
}

func TestUnfinishedCatchpointsTable(t *testing.T) {
	partitiontest.PartitionTest(t)

	dbs, _ := storetesting.DbOpenTest(t, true)
	defer dbs.Close()

	cts := NewCatchpointSQLReaderWriter(dbs.Wdb.Handle)

	err := accountsCreateUnfinishedCatchpointsTable(
		context.Background(), dbs.Wdb.Handle)
	require.NoError(t, err)

	var d3 crypto.Digest
	rand.Read(d3[:])
	err = cts.InsertUnfinishedCatchpoint(context.Background(), 3, d3)
	require.NoError(t, err)

	var d5 crypto.Digest
	rand.Read(d5[:])
	err = cts.InsertUnfinishedCatchpoint(context.Background(), 5, d5)
	require.NoError(t, err)

	ret, err := cts.SelectUnfinishedCatchpoints(context.Background())
	require.NoError(t, err)
	expected := []trackerdb.UnfinishedCatchpointRecord{
		{
			Round:     3,
			BlockHash: d3,
		},
		{
			Round:     5,
			BlockHash: d5,
		},
	}
	require.Equal(t, expected, ret)

	err = cts.DeleteUnfinishedCatchpoint(context.Background(), 3)
	require.NoError(t, err)

	ret, err = cts.SelectUnfinishedCatchpoints(context.Background())
	require.NoError(t, err)
	expected = []trackerdb.UnfinishedCatchpointRecord{
		{
			Round:     5,
			BlockHash: d5,
		},
	}
	require.Equal(t, expected, ret)
}
