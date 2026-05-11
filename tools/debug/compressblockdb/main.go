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
// copy whose blkdata/certdata columns are encoded with the windowed-zstd
// codec at the given window size N. Useful for measuring the on-disk savings
// the codec produces on a real DB without modifying the original file.
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
	fmt.Fprintln(os.Stderr, "codec at window size <window>. Use window=1 to write an uncompressed")
	fmt.Fprintln(os.Stderr, "copy. The source may itself be raw, windowed, or mixed; the lowest")
	fmt.Fprintln(os.Stderr, "stored round does not have to be 0.")
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
	if int(n) > blockdb.MaxCompressionWindow {
		fmt.Fprintf(os.Stderr, "window %d exceeds blockdb.MaxCompressionWindow (%d)\n",
			n, blockdb.MaxCompressionWindow)
		os.Exit(1)
	}
	if _, err := os.Stat(dst); err == nil {
		fmt.Fprintf(os.Stderr, "destination %s already exists; refusing to overwrite\n", dst)
		os.Exit(1)
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "stat %s: %v\n", dst, err)
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
	defer dstDB.Close()

	minR, maxR, err := sourceRange(srcDB)
	if err != nil {
		return err
	}
	nrounds := uint64(maxR-minR) + 1
	fmt.Printf("source %s: rounds %d..%d (%d rounds)\n", srcPath, minR, maxR, nrounds)
	fmt.Printf("dest   %s: window N=%d\n", dstPath, n)

	writer := blockdb.NewBlockWriter(n)
	defer writer.Close()

	if ierr := initDest(dstDB, writer); ierr != nil {
		return ierr
	}

	if serr := stageFirst(srcDB, dstDB, minR); serr != nil {
		return serr
	}
	c := &copier{writer: writer, written: 1}

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

	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		return err
	}
	dstInfo, err := os.Stat(dstPath)
	if err != nil {
		return err
	}
	fmt.Printf("done: %d rounds in %s\n", c.written, time.Since(start).Round(time.Second))
	fmt.Printf("  source file: %.2f MB\n", float64(srcInfo.Size())/(1<<20))
	fmt.Printf("  dest file:   %.2f MB (%.2f%% of source)\n",
		float64(dstInfo.Size())/(1<<20),
		float64(dstInfo.Size())*100/float64(srcInfo.Size()))
	return nil
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

func initDest(db *sql.DB, writer *blockdb.BlockWriter) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if err := blockdb.BlockInit(tx, nil, writer); err != nil {
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
func stageFirst(srcDB, dstDB *sql.DB, firstRound basics.Round) error {
	srcTx, err := srcDB.Begin()
	if err != nil {
		return err
	}
	blk, cert, err := blockdb.BlockGetCert(srcTx, firstRound)
	_ = srcTx.Rollback()
	if err != nil {
		return fmt.Errorf("read round %d: %w", firstRound, err)
	}

	dstTx, err := dstDB.Begin()
	if err != nil {
		return err
	}
	if err := blockdb.BlockStartCatchupStaging(dstTx, &blk, &cert); err != nil {
		_ = dstTx.Rollback()
		return fmt.Errorf("stage first round %d: %w", firstRound, err)
	}
	if err := blockdb.BlockCompleteCatchup(dstTx); err != nil {
		_ = dstTx.Rollback()
		return fmt.Errorf("complete catchup at round %d: %w", firstRound, err)
	}
	return dstTx.Commit()
}

// copier carries cross-batch encoder state via writer. BlockPut on the
// dest preserves the writer's in-flight zstd frame across consecutive
// successful Put calls, so the LZ77 window spans every round in [firstRound+1, hi].
type copier struct {
	writer  *blockdb.BlockWriter
	written uint64
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
		blk, cert, err = blockdb.BlockGetCert(srcTx, r)
		if err != nil {
			_ = dstTx.Rollback()
			c.writer.Reset()
			return fmt.Errorf("read round %d: %w", r, err)
		}
		if err = blockdb.BlockPut(dstTx, &blk, &cert, c.writer); err != nil {
			_ = dstTx.Rollback()
			c.writer.Reset()
			return fmt.Errorf("put round %d: %w", r, err)
		}
		c.written++
	}
	if err := dstTx.Commit(); err != nil {
		c.writer.Reset()
		return err
	}
	return nil
}
