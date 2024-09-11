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

package testdb

import (
	"testing"

	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/dualdriver"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/pebbledbdriver"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/sqlitedriver"
)

// OpenForTesting will create a testing store to be used on tests outside of the trackerdb package.
func OpenForTesting(t testing.TB, inMemory bool) trackerdb.Store {
	primaryDB, _ := sqlitedriver.OpenForTesting(t, inMemory)
	// pebbledb can always be run in memory, sqlite is the one that causes problems on tests
	secondaryDB := pebbledbdriver.OpenForTesting(t, true)

	return dualdriver.MakeStore(primaryDB, secondaryDB)
}
