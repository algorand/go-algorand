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

package testdb

import (
	"testing"

	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/dualdriver"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/pebbledbdriver"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/sqlitedriver"
	"github.com/algorand/go-algorand/logging"
)

// OpenForTesting will create a testing store to be used on tests outside of the trackerdb package.
func OpenForTesting(t *testing.T) trackerdb.TrackerStore {
	logger := logging.TestingLog(t)

	primaryDB, _ := sqlitedriver.DbOpenTrackerTest(t, true)
	primaryDB.SetLogger(logger)

	secondaryDB := pebbledbdriver.OpenForTesting(t, true)
	secondaryDB.SetLogger(logger)

	return dualdriver.MakeStore(primaryDB, secondaryDB)
}
