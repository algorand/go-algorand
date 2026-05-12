// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

package blockdb

import (
	"database/sql"
	"fmt"
	"math/rand/v2"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/data/basics"
)

// openBenchReader is shared setup for the BlockGet benchmarks. The bench
// is opt-in: set BLOCKDB_BENCH_PATH to a *.sqlite produced by an algod
// node (or by tools/debug/compressblockdb) and run with -bench. Returns
// the open tx, a Reader bound to it, and the [min, max] round range.
func openBenchReader(b *testing.B) (tx *sql.Tx, reader *Reader, minR, maxR basics.Round) {
	b.Helper()
	path := os.Getenv("BLOCKDB_BENCH_PATH")
	if path == "" {
		b.Skip("set BLOCKDB_BENCH_PATH to enable")
	}
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro", path))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })

	var lo, hi int64
	if err := db.QueryRow("SELECT MIN(rnd), MAX(rnd) FROM blocks").Scan(&lo, &hi); err != nil {
		b.Fatal(err)
	}

	tx, err = db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = tx.Rollback() })

	reader, err = NewReader(tx)
	if err != nil {
		b.Fatal(err)
	}
	return tx, reader, basics.Round(lo), basics.Round(hi)
}

// BenchmarkReader_BlockGet measures the per-round read latency for
// uniformly-random rounds. This is the worst case for windowed
// compression: every read walks back to its frame anchor and
// decompresses up to N continuation rows.
func BenchmarkReader_BlockGet(b *testing.B) {
	tx, reader, minR, maxR := openBenchReader(b)
	span := uint64(maxR-minR) + 1

	// Pre-pick rounds so the RNG cost is outside the timed loop.
	rng := rand.New(rand.NewPCG(1, 2))
	rounds := make([]basics.Round, b.N)
	for i := range rounds {
		rounds[i] = minR + basics.Round(rng.Uint64N(span))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := reader.BlockGet(tx, rounds[i]); err != nil {
			b.Fatalf("BlockGet(%d): %v", rounds[i], err)
		}
	}
}

// BenchmarkReader_BlockGetSequential measures the per-round read latency
// for an in-order scan from a random offset. Sequential reads are the
// catchup / migration access pattern and benefit from SQLite's warm page
// cache across consecutive rounds.
func BenchmarkReader_BlockGetSequential(b *testing.B) {
	tx, reader, minR, maxR := openBenchReader(b)
	span := uint64(maxR-minR) + 1
	if uint64(b.N) > span {
		b.Skipf("b.N=%d exceeds DB span %d", b.N, span)
	}

	rng := rand.New(rand.NewPCG(1, 2))
	start := minR + basics.Round(rng.Uint64N(span-uint64(b.N)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := reader.BlockGet(tx, start+basics.Round(i)); err != nil {
			b.Fatalf("BlockGet(%d): %v", start+basics.Round(i), err)
		}
	}
}
