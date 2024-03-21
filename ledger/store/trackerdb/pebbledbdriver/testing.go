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

package pebbledbdriver

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

// OpenForTesting opens a sqlite db file for testing purposes.
func OpenForTesting(t testing.TB, inMemory bool) trackerdb.Store {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	// create a tmp dir for the db, the testing runtime will clean it up automatically
	dir := fmt.Sprintf("%s/db", t.TempDir())

	db, err := Open(dir, inMemory, proto, logging.TestingLog(t))
	require.NoErrorf(t, err, "Dir : %s\nInMemory: %v", dir, inMemory)

	return db
}
