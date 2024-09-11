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

package testing

import (
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
	"github.com/stretchr/testify/require"
)

// DbOpenTest opens a db file for testing purposes.
func DbOpenTest(t testing.TB, inMemory bool) (db.Pair, string) {
	fn := fmt.Sprintf("%s/%s.%d", t.TempDir(), strings.ReplaceAll(t.Name(), "/", "."), crypto.RandUint64())
	dbs, err := db.OpenPair(fn, inMemory)
	require.NoErrorf(t, err, "Filename : %s\nInMemory: %v", fn, inMemory)
	return dbs, fn
}

// SetDbLogging sets a testing logger on a database.
func SetDbLogging(t testing.TB, dbs db.Pair) {
	dblogger := logging.TestingLog(t)
	dbs.Rdb.SetLogger(dblogger)
	dbs.Wdb.SetLogger(dblogger)
}
