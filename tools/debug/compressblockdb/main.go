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

// compressblockdb reads an existing ledger.block.sqlite and writes a new
// copy whose blkdata/certdata columns are encoded with windowed-zstd
// compression at the given window size N. Useful for measuring the on-disk
// savings the compression produces on a real DB without modifying the
// original file.
//
// The source DB may itself be uncompressed, fully compressed, partially
// compressed, or contain rows from multiple historical window sizes:
// blockdb.BlockGetCert auto-detects the per-row format on read.
//
// Sources that do not start at round 0 are handled the same way catchpoint
// catchup seeds a fresh node: the lowest source round is staged through
// BlockStartCatchupStaging + BlockCompleteCatchup so the dest's blocks
// table starts populated, and the rest of the rounds are appended via
// BlockPut, which carries the streaming encoder state forward across
// rounds the way the production blockqueue syncer does.
package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/store/blockdb"
)

var batchSize = flag.Int("batch", 10000, "Commit destination transaction every this many rounds")

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: compressblockdb [flags] <src.sqlite> <dst.sqlite> <window>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Reads <src.sqlite> (an existing ledger.block.sqlite) and writes a new")
	fmt.Fprintln(os.Stderr, "copy to <dst.sqlite> whose rows are encoded with the windowed-zstd")
	fmt.Fprintln(os.Stderr, "compression at window size <window>. Use window=0 to write an uncompressed")
	fmt.Fprintln(os.Stderr, "copy and window=1 for an independent zstd frame per row. The source")
	fmt.Fprintln(os.Stderr, "may itself be raw, windowed, or mixed; the lowest stored round does")
	fmt.Fprintln(os.Stderr, "not have to be 0.")
	fmt.Fprintln(os.Stderr, "")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) != 3 {
		usage()
	}
	src, dst := args[0], args[1]
	n, err := strconv.ParseUint(args[2], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad window value %q: %v\n", args[2], err)
		os.Exit(1)
	}
	if !strings.HasSuffix(src, ".sqlite") || !strings.HasSuffix(dst, ".sqlite") {
		fmt.Fprintln(os.Stderr, "both filenames must end in .sqlite")
		os.Exit(1)
	}
	if !slices.Contains([]uint64{0, 1, 2, 4, 8, 16, 32}, n) {
		fmt.Fprintf(os.Stderr, "window %d is not a supported value (must be one of 0,1,2,4,8,16,32)\n", n)
		os.Exit(1)
	}
	if _, err := os.Stat(dst); err == nil {
		fmt.Fprintf(os.Stderr, "destination %s already exists; refusing to overwrite\n", dst)
		os.Exit(1)
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "stat %s: %v\n", dst, err)
		os.Exit(1)
	}

	if *batchSize <= 0 {
		fmt.Fprintf(os.Stderr, "batch must be positive, got %d\n", *batchSize)
		os.Exit(1)
	}

	if err := run(src, dst, n, *batchSize); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(srcPath, dstPath string, n uint64, batch int) error {
	srcDB, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro&_journal_mode=wal", srcPath))
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer srcDB.Close()
	if perr := srcDB.Ping(); perr != nil {
		return fmt.Errorf("open source: %w", perr)
	}

	dstDB, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?_journal_mode=wal", dstPath))
	if err != nil {
		return fmt.Errorf("open dest: %w", err)
	}
	dstClosed := false
	defer func() {
		if !dstClosed {
			_ = dstDB.Close()
		}
	}()

	minR, maxR, err := sourceRange(srcDB)
	if err != nil {
		return err
	}
	nrounds := uint64(maxR-minR) + 1
	fmt.Printf("source %s: rounds %d..%d (%d rounds)\n", srcPath, minR, maxR, nrounds)
	fmt.Printf("dest   %s: window N=%d\n", dstPath, n)

	if ierr := initDest(dstDB, n); ierr != nil {
		return ierr
	}

	srcReader, err := openReader(srcDB)
	if err != nil {
		return fmt.Errorf("open src reader: %w", err)
	}

	dstStore, err := openStore(dstDB, n)
	if err != nil {
		return fmt.Errorf("open dst store: %w", err)
	}
	defer dstStore.Close()

	if serr := stageFirst(srcDB, dstDB, minR, srcReader); serr != nil {
		return serr
	}
	c := &copier{srcReader: srcReader, dstStore: dstStore, written: 1}

	start := time.Now()
	for batchLo := minR + 1; batchLo <= maxR; batchLo += basics.Round(batch) {
		batchHi := min(batchLo+basics.Round(batch)-1, maxR)
		if berr := c.copyBatch(srcDB, dstDB, batchLo, batchHi); berr != nil {
			return fmt.Errorf("batch [%d,%d]: %w", batchLo, batchHi, berr)
		}
		fmt.Printf("  %d/%d (%.1f%%) in %s\n",
			c.written, nrounds,
			float64(c.written)*100/float64(nrounds),
			time.Since(start).Round(time.Second),
		)
	}

	// Truncate the WAL and close the destination connection before
	// measuring file size so the dest file fully reflects committed pages
	// (otherwise recent commits can still be sitting in dst.sqlite-wal and
	// the reported ratio is misleadingly small).
	if _, cerr := dstDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); cerr != nil {
		return fmt.Errorf("checkpoint dest: %w", cerr)
	}
	if cerr := dstDB.Close(); cerr != nil {
		return fmt.Errorf("close dest: %w", cerr)
	}
	dstClosed = true

	srcSize, err := sqliteOnDiskSize(srcPath)
	if err != nil {
		return err
	}
	dstSize, err := sqliteOnDiskSize(dstPath)
	if err != nil {
		return err
	}
	fmt.Printf("done: %d rounds in %s\n", c.written, time.Since(start).Round(time.Second))
	fmt.Printf("  source file: %.2f MB\n", float64(srcSize)/(1<<20))
	fmt.Printf("  dest file:   %.2f MB (%.2f%% of source)\n",
		float64(dstSize)/(1<<20),
		float64(dstSize)*100/float64(srcSize))
	return nil
}

// openReader opens a Reader on a short read-only transaction; the Reader
// survives the rollback because NewReader captures schema detection without
// retaining the tx. The source side of the copy is read-only and never
// allocates writer state.
func openReader(db *sql.DB) (*blockdb.Reader, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	return blockdb.NewReader(tx)
}

// openStore opens a Store on a short read-only transaction; the Store
// survives the rollback because NewStore captures schema detection without
// retaining the tx. window is the compression window the Store's writer
// will encode at.
func openStore(db *sql.DB, window uint64) (*blockdb.Store, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	return blockdb.NewStore(tx, window)
}

// sqliteOnDiskSize sums the .sqlite file with any -wal / -shm sidecars so
// the reported size reflects everything the DB occupies on disk. A pre-WAL
// or already-checkpointed DB has the sidecars missing or empty; their
// absence is not an error.
func sqliteOnDiskSize(path string) (int64, error) {
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

func sourceRange(db *sql.DB) (basics.Round, basics.Round, error) {
	var minNull, maxNull sql.NullInt64
	if err := db.QueryRow("SELECT MIN(rnd), MAX(rnd) FROM blocks").Scan(&minNull, &maxNull); err != nil {
		return 0, 0, fmt.Errorf("query source range: %w", err)
	}
	if !minNull.Valid {
		return 0, 0, fmt.Errorf("source has no rows")
	}
	return basics.Round(minNull.Int64), basics.Round(maxNull.Int64), nil
}

func initDest(db *sql.DB, window uint64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if err := blockdb.BlockInit(tx, nil, window); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("init dest schema: %w", err)
	}
	return tx.Commit()
}

// stageFirst seeds the dest blocks table with the source's lowest stored
// round using the same BlockStartCatchupStaging + BlockCompleteCatchup pair
// the catchpoint catchup path uses for its first block. After this returns,
// dest's blocks table holds exactly the row at firstRound, and BlockPut can
// be used contiguously for every subsequent round.
//
// Staging writes the row verbatim (window_start = NULL); cross-row
// compression begins with the first BlockPut call.
func stageFirst(srcDB, dstDB *sql.DB, firstRound basics.Round, srcReader *blockdb.Reader) error {
	srcTx, err := srcDB.Begin()
	if err != nil {
		return err
	}
	blk, cert, err := srcReader.BlockGetCert(srcTx, firstRound)
	_ = srcTx.Rollback()
	if err != nil {
		return fmt.Errorf("read round %d: %w", firstRound, err)
	}

	dstTx, err := dstDB.Begin()
	if err != nil {
		return err
	}
	if err := blockdb.BlockStartCatchupStaging(dstTx, blk, cert); err != nil {
		_ = dstTx.Rollback()
		return fmt.Errorf("stage first round %d: %w", firstRound, err)
	}
	if err := blockdb.BlockCompleteCatchup(dstTx); err != nil {
		_ = dstTx.Rollback()
		return fmt.Errorf("complete catchup at round %d: %w", firstRound, err)
	}
	return dstTx.Commit()
}

// copier carries cross-batch encoder state via dstStore. BlockPut on the
// dest preserves the writer's in-flight zstd frame across consecutive
// successful Put calls, so the LZ77 window spans every round in [firstRound+1, hi].
type copier struct {
	srcReader *blockdb.Reader
	dstStore  *blockdb.Store
	written   uint64
}

func (c *copier) copyBatch(srcDB, dstDB *sql.DB, lo, hi basics.Round) error {
	srcTx, err := srcDB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = srcTx.Rollback() }()

	dstTx, err := dstDB.Begin()
	if err != nil {
		return err
	}

	for r := lo; r <= hi; r++ {
		var (
			blk  bookkeeping.Block
			cert agreement.Certificate
		)
		blk, cert, err = c.srcReader.BlockGetCert(srcTx, r)
		if err != nil {
			_ = dstTx.Rollback()
			c.dstStore.Reset()
			return fmt.Errorf("read round %d: %w", r, err)
		}
		if err = c.dstStore.BlockPut(dstTx, &blk, &cert); err != nil {
			_ = dstTx.Rollback()
			c.dstStore.Reset()
			return fmt.Errorf("put round %d: %w", r, err)
		}
		c.written++
	}
	if err := dstTx.Commit(); err != nil {
		c.dstStore.Reset()
		return err
	}
	return nil
}
