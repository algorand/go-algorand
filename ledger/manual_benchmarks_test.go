// Copyright (C) 2019-2022 Algorand, Inc.
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

package ledger

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

type manualBenchmarkResult struct {
	Name         string        `json:"name"`
	InMemory     bool          `json:"sqliteInMemory"`
	N            int           `json:"n"`
	NumOps       int           `json:"numOps"`
	OpDuration   time.Duration `json:"opDuration"`
	NSperOp      int           `json:"nsPerOp"`
	RealDuration time.Duration `json:"realDuration"`
}

const benchmarksDirectory = "benchmarks"

func writeBenchmarkResults(t *testing.T, results []manualBenchmarkResult, filename string) {
	marshal := func(t *testing.T, r interface{}) []byte {
		writeBytes, err := json.MarshalIndent(r, "", "  ")
		require.NoError(t, err)
		return writeBytes
	}
	timestamp := func() string {
		ts := time.Now().UTC().Format(time.RFC3339)
		return strings.Replace(ts, ":", "", -1) // get rid of offensive colons
	}

	writeBytes := marshal(t, results)
	tstamp := timestamp()
	err := os.WriteFile(
		filepath.Join(benchmarksDirectory, fmt.Sprintf("%s_%s.json", filename, tstamp)),
		writeBytes,
		0644,
	)
	require.NoError(t, err)
}

var maxManualDuration = 5400 * time.Second

func manualBoxDbBenchmarkFactory(testName string, customLookup *string, inMemory bool, N int, dur time.Duration) func(*testing.T) manualBenchmarkResult {
	return func(t *testing.T) manualBenchmarkResult {
		realStart := time.Now()
		dbs, fn := dbOpenTest(t, inMemory)
		setDbLogging(t, dbs)
		defer cleanupTestDb(dbs, fn, inMemory)

		// return account data, initialize DB tables from accountsInitTest
		_ = benchmarkInitBalances(t, 1, dbs, protocol.ConsensusCurrentVersion)

		qs, err := accountsInitDbQueries(dbs.Rdb.Handle)
		require.NoError(t, err)
		defer qs.close()

		// make writer to DB
		tx, err := dbs.Wdb.Handle.Begin()
		require.NoError(t, err)

		// writer is only for kvstore
		writer, err := makeAccountsSQLWriter(tx, true, true, true, true)
		defer writer.close()
		require.NoError(t, err)

		bytes := make([]byte, 32)
		i := 0
		for ; i < N && time.Since(realStart) < maxManualDuration; i++ {
			_, err := rand.Read(bytes)
			require.NoError(t, err)
			appID := basics.AppIndex(rand.Uint64())
			key := logic.MakeBoxKey(appID, string(bytes))
			err = writer.upsertKvPair(key, key)
			require.NoError(t, err)
		}
		N = i // in case of early breakout above

		err = tx.Commit()
		require.NoError(t, err)

		var lookupStmt *sql.Stmt
		if customLookup != nil {
			lookupStmt, err = dbs.Wdb.Handle.Prepare(*customLookup)
			require.NoError(t, err)
		}

		start := time.Now()
		var elapsed time.Duration

		i = 0
		for ; time.Since(start) < dur && time.Since(realStart) < maxManualDuration; i++ {
			_, err := rand.Read(bytes)
			require.NoError(t, err)
			appID := basics.AppIndex(rand.Uint64())
			key := logic.MakeBoxKey(appID, string(bytes))
			results := make(map[string]bool)
			if lookupStmt == nil {
				localStart := time.Now()
				qs.lookupKeysByPrefix(key, 0, results, 0)
				elapsed += time.Since(localStart)
			} else {
				var v sql.NullString
				var pv persistedKVData

				localStart := time.Now()
				err = lookupStmt.QueryRow([]byte(key)).Scan(&pv.round, &v)
				elapsed += time.Since(localStart)

				require.NoError(t, err)
			}
		}
		return manualBenchmarkResult{testName, inMemory, N, i, elapsed, int(elapsed) / i, time.Since(realStart)}
	}
}

/*
go test -v -timeout 7200s -run ^TestManualBoxBenchmark$ github.com/algorand/go-algorand/ledger
*/

func TestManualBoxBenchmark(t *testing.T) {
	testName := "boxlookupKeysByPrefix_onFileSystem"
	// lookup := "SELECT rnd, value FROM acctrounds LEFT JOIN kvstore ON key = ? WHERE id='acctbase';"
	var customLookup *string // = &lookup
	inMemory := false
	duration := 20 * time.Second

	sleepInBetween := 10 * time.Second
	tests := 16 // 17 is really the max
	results := make([]manualBenchmarkResult, tests)

	base := 2
	N := 1000
	for exp := 0; exp < tests; exp++ {
		results[exp] = manualBoxDbBenchmarkFactory(testName, customLookup, inMemory, N, duration)(t)
		fmt.Printf("%+v\n", results[exp]) // run with -v flag to see during test
		if exp < tests-1 {
			time.Sleep(sleepInBetween)
		}
		N *= base
	}
	writeBenchmarkResults(t, results, testName)
}
