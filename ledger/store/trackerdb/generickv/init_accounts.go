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

package generickv

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

type dbForInit interface {
	trackerdb.Store
	KvRead
	KvWrite
}

// AccountsInitTest initializes the database for testing with the given accounts.
func AccountsInitTest(tb testing.TB, db dbForInit, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	params := trackerdb.Params{
		InitAccounts: initAccounts,
		InitProto:    proto,
	}
	_, err := RunMigrations(context.Background(), db, params, trackerdb.AccountDBVersion)
	require.NoError(tb, err)
	return true
}

// AccountsInitLightTest initializes the database for testing with the given accounts.
//
// This is duplicate due to a specific legacy test in accdeltas_test.go.
// TODO: remove the need for this.
func AccountsInitLightTest(tb testing.TB, db dbForInit, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error) {
	params := trackerdb.Params{
		InitAccounts: initAccounts,
		// TODO: how do we get the correct version from the proto arg?
		InitProto: protocol.ConsensusCurrentVersion,
	}
	_, err = RunMigrations(context.Background(), db, params, trackerdb.AccountDBVersion)
	require.NoError(tb, err)
	return true, nil
}
