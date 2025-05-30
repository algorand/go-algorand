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

package testsuite

import (
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/ledger/store/trackerdb/testdb"
)

func TestDualEngines(t *testing.T) {
	// partitiontest.PartitionTest(t) // partitioning inside subtest
	dbFactory := func(proto config.ConsensusParams) dbForTests {
		db := testdb.OpenForTesting(t, true)
		seedDb(t, db)

		return db
	}

	// run the suite
	runGenericTestsWithDB(t, dbFactory)
}
