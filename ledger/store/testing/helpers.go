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
	fn := fmt.Sprintf("%s.%d", strings.ReplaceAll(t.Name(), "/", "."), crypto.RandUint64())
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
