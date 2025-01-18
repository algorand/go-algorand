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

package dualdriver

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

type writerForTesting struct {
	primary   trackerdb.WriterTestExt
	secondary trackerdb.WriterTestExt
}

// AccountsInitLightTest implements trackerdb.WriterTestExt
func (tx *writerForTesting) AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabse bool, err error) {
	newDatabaseP, errP := tx.primary.AccountsInitLightTest(tb, initAccounts, proto)
	newDatabaseS, errS := tx.secondary.AccountsInitLightTest(tb, initAccounts, proto)
	// coalesce errors
	err = coalesceErrors(errP, errS)
	if err != nil {
		return
	}
	// check results match
	if newDatabaseP != newDatabaseS {
		err = ErrInconsistentResult
		return
	}
	// return primary results
	return newDatabaseP, nil
}

// AccountsInitTest implements trackerdb.WriterTestExt
func (tx *writerForTesting) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	newDatabaseP := tx.primary.AccountsInitTest(tb, initAccounts, proto)
	tx.secondary.AccountsInitTest(tb, initAccounts, proto)
	// return primary results
	return newDatabaseP
}

// AccountsUpdateSchemaTest implements trackerdb.WriterTestExt
func (*writerForTesting) AccountsUpdateSchemaTest(ctx context.Context) (err error) {
	panic("unimplemented")
}

// ModifyAcctBaseTest implements trackerdb.WriterTestExt
func (*writerForTesting) ModifyAcctBaseTest() error {
	panic("unimplemented")
}
