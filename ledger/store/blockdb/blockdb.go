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
	"strings"

	"github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// 2019-12-15: removed column 'auxdata blob' from 'CREATE TABLE' statement. It was not explicitly removed from databases and may continue to exist with empty entries in some old databases.
//
// blockSchema is the pre-compression canonical shape. When compression is
// enabled BlockInit ALTERs the table to add the nullable window_start
// column; a node that never enables compression leaves the table as-is.
// Read callers thread a hasWindowStart bool through from the open-time
// detection so the read path never has to introspect the schema per call.
var blockSchema = []string{
	`CREATE TABLE IF NOT EXISTS blocks (
		rnd integer primary key,
		proto text,
		hdrdata blob,
		blkdata blob,
		certdata blob)`,
}

var blockResetExprs = []string{
	`DROP TABLE IF EXISTS blocks`,
}

// addWindowStartColumn applies the ALTER TABLE migration that brings a
// pre-compression schema up to date on databases created by earlier
// releases. SQLite has no ADD COLUMN IF NOT EXISTS, and a duplicate-column
// ALTER is reported as the generic SQLITE_ERROR (its only distinguishing
// signal is the message text), so we check the table's columns first via
// PRAGMA table_info. If the table does not exist (PRAGMA returns no rows)
// the function is a no-op so callers can invoke it unconditionally.
func addWindowStartColumn(tx *sql.Tx, table string) error {
	// Determine column presence and table existence in one PRAGMA.
	rows, err := tx.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return fmt.Errorf("blockdb: list columns of %s: %w", table, err)
	}
	defer rows.Close()
	exists := false
	for rows.Next() {
		exists = true
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("blockdb: scan column row of %s: %w", table, err)
		}
		if name == "window_start" {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("blockdb: list columns of %s: %w", table, err)
	}
	if !exists {
		return nil
	}
	if _, err := tx.Exec("ALTER TABLE " + table + " ADD COLUMN window_start integer"); err != nil {
		return fmt.Errorf("blockdb: add window_start column to %s: %w", table, err)
	}
	return nil
}

// BlockInit initializes blockdb
// window is the BlockDBCompressionWindow to use for any initBlocks rows that get written;
// it has no effect when initBlocks is empty, or when the blocks table is already populated.
func BlockInit(tx *sql.Tx, initBlocks []bookkeeping.Block, window uint64) error {
	for _, tableCreate := range blockSchema {
		_, err := tx.Exec(tableCreate)
		if err != nil {
			return fmt.Errorf("blockdb blockInit could not create table %v", err)
		}
	}
	// Migrate only when compression is enabled. A node that never sets
	// BlockDBCompressionWindow > 0 leaves the schema bit-identical to
	// what an earlier release produced. catchpointblocks usually doesn't
	// exist (no-op); migrating it matters for catchups resumed across an
	// upgrade where BlockStartCatchupStaging's DROP+CREATE is skipped.
	if window > 0 {
		if err := addWindowStartColumn(tx, "blocks"); err != nil {
			return err
		}
		if err := addWindowStartColumn(tx, "catchpointblocks"); err != nil {
			return err
		}
	}

	next, err := BlockNext(tx)
	if err != nil {
		return err
	}

	if next == 0 && len(initBlocks) > 0 {
		writer := NewBlockWriter(window)
		defer writer.Close()
		for i := range initBlocks {
			err = BlockPut(tx, &initBlocks[i], &agreement.Certificate{}, writer)
			if err != nil {
				serr, ok := err.(sqlite3.Error)
				if ok && serr.Code == sqlite3.ErrConstraint {
					continue
				}
				return err
			}
		}
	}

	return nil
}

// BlockResetDB resets blockdb
func BlockResetDB(tx *sql.Tx) error {
	for _, stmt := range blockResetExprs {
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

// BlockGet retrieves a block by a round number. hasWindowStart selects the
// read shape (see blockGetEncoded); callers should pass the result of
// HasWindowStart evaluated once at open time.
func BlockGet(tx *sql.Tx, rnd basics.Round, hasWindowStart bool) (blk bookkeeping.Block, err error) {
	buf, _, err := blockGetEncoded(tx, rnd, true /*blkOnly*/, hasWindowStart)
	if err != nil {
		return
	}
	err = protocol.Decode(buf, &blk)
	return
}

// BlockGetHdr retrieves a block header by a round number
func BlockGetHdr(tx *sql.Tx, rnd basics.Round) (hdr bookkeeping.BlockHeader, err error) {
	var buf []byte
	err = tx.QueryRow("SELECT hdrdata FROM blocks WHERE rnd=?", rnd).Scan(&buf)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ledgercore.ErrNoEntry{Round: rnd}
		}

		return
	}

	err = protocol.Decode(buf, &hdr)
	return
}

// BlockGetEncodedCert retrieves raw block and cert by a round number.
// hasWindowStart selects the read shape; see BlockGet.
func BlockGetEncodedCert(tx *sql.Tx, rnd basics.Round, hasWindowStart bool) (blk []byte, cert []byte, err error) {
	return blockGetEncoded(tx, rnd, false, hasWindowStart)
}

// BlockGetCert retrieves block and cert by a round number. hasWindowStart
// selects the read shape; see BlockGet.
func BlockGetCert(tx *sql.Tx, rnd basics.Round, hasWindowStart bool) (blk bookkeeping.Block, cert agreement.Certificate, err error) {
	blkbuf, certbuf, err := BlockGetEncodedCert(tx, rnd, hasWindowStart)
	if err != nil {
		return
	}
	err = protocol.Decode(blkbuf, &blk)
	if err != nil {
		return
	}

	if certbuf != nil {
		err = protocol.Decode(certbuf, &cert)
		if err != nil {
			return
		}
	}

	return
}

// BlockPut stores block and certificate. writer must be non-nil.
func BlockPut(tx *sql.Tx, blk *bookkeeping.Block, cert *agreement.Certificate, writer *BlockWriter) error {
	var max sql.NullInt64
	err := tx.QueryRow("SELECT MAX(rnd) FROM blocks").Scan(&max)
	if err != nil {
		return err
	}

	rnd := blk.Round()
	if max.Valid {
		if rnd != basics.Round(max.Int64+1) {
			err = fmt.Errorf("inserting block %d but expected %d", rnd, max.Int64+1)
			return err
		}
	} else {
		if rnd != 0 {
			err = fmt.Errorf("inserting block %d but expected 0", rnd)
			return err
		}
	}

	blkChunk, certChunk, anchorRound, err := encodeBlockCertData(blk, cert, writer)
	if err != nil {
		return err
	}

	// When compression is disabled the row is byte-identical to the
	// pre-compression on-disk layout, so we use the 5-column INSERT and
	// never touch the window_start column (which may not even exist).
	if writer.Codec().Disabled() {
		_, err = tx.Exec("INSERT INTO blocks (rnd, proto, hdrdata, blkdata, certdata) VALUES (?, ?, ?, ?, ?)",
			rnd,
			blk.CurrentProtocol,
			protocol.Encode(&blk.BlockHeader),
			blkChunk,
			certChunk,
		)
		return err
	}
	_, err = tx.Exec("INSERT INTO blocks (rnd, proto, hdrdata, blkdata, certdata, window_start) VALUES (?, ?, ?, ?, ?, ?)",
		rnd,
		blk.CurrentProtocol,
		protocol.Encode(&blk.BlockHeader),
		blkChunk,
		certChunk,
		uint64(anchorRound),
	)
	return err
}

// BlockNext returns the next expected round number
func BlockNext(tx *sql.Tx) (basics.Round, error) {
	var max sql.NullInt64
	err := tx.QueryRow("SELECT MAX(rnd) FROM blocks").Scan(&max)
	if err != nil {
		return 0, err
	}

	if max.Valid {
		return basics.Round(max.Int64 + 1), nil
	}

	return 0, nil
}

// BlockLatest returns the latest persisted round number
func BlockLatest(tx *sql.Tx) (basics.Round, error) {
	var max sql.NullInt64
	err := tx.QueryRow("SELECT MAX(rnd) FROM blocks").Scan(&max)
	if err != nil {
		return 0, err
	}

	if max.Valid {
		return basics.Round(max.Int64), nil
	}

	return 0, fmt.Errorf("no blocks present")
}

// BlockEarliest returns the lowest persisted round number
func BlockEarliest(tx *sql.Tx) (basics.Round, error) {
	var min sql.NullInt64
	err := tx.QueryRow("SELECT MIN(rnd) FROM blocks").Scan(&min)
	if err != nil {
		return 0, err
	}

	if min.Valid {
		return basics.Round(min.Int64), nil
	}

	return 0, fmt.Errorf("no blocks present")
}

// BlockForgetBefore removes block entries with round numbers less than the specified round
func BlockForgetBefore(tx *sql.Tx, rnd basics.Round) error {
	next, err := BlockNext(tx)
	if err != nil {
		return err
	}

	if rnd >= next {
		return fmt.Errorf("forgetting too much: rnd %d >= next %d", rnd, next)
	}

	_, err = tx.Exec("DELETE FROM blocks WHERE rnd<?", rnd)
	return err
}

// RoundDownRetention aligns a candidate retention boundary to a round that
// preserves every possible windowed-zstd anchor supported by the block DB.
// Reads look back by MaxCompressionWindow, so retention must keep rows from
// the same maximum-sized window even if the current node has compression
// disabled or uses a smaller window than an earlier run.
func RoundDownRetention(rnd basics.Round) basics.Round {
	const n = uint64(MaxCompressionWindow)
	return basics.Round(uint64(rnd) - uint64(rnd)%n)
}

// BlockStartCatchupStaging initializes catchup for catchpoint
func BlockStartCatchupStaging(tx *sql.Tx, blk bookkeeping.Block, cert agreement.Certificate) error {
	// delete the old catchpointblocks table, if there is such.
	for _, stmt := range blockResetExprs {
		stmt = strings.Replace(stmt, "blocks", "catchpointblocks", 1)
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}

	// create the catchpointblocks table
	for _, stmt := range blockSchema {
		stmt = strings.Replace(stmt, "blocks", "catchpointblocks", 1)
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}
	// Mirror the blocks schema. If blocks already has window_start (i.e.
	// compression is enabled for this DB), catchpointblocks needs it too;
	// otherwise BlockCompleteCatchup's rename would produce a blocks table
	// that the windowed BlockPut INSERT can no longer target.
	hasWS, err := tableHasColumn(tx, "blocks", "window_start")
	if err != nil {
		return err
	}
	if hasWS {
		if aerr := addWindowStartColumn(tx, "catchpointblocks"); aerr != nil {
			return aerr
		}
	}

	// insert the top entry to the blocks table.
	// staging rows are always raw msgp; window_start stays NULL.
	_, err = tx.Exec("INSERT INTO catchpointblocks (rnd, proto, hdrdata, blkdata, certdata) VALUES (?, ?, ?, ?, ?)",
		blk.Round(),
		blk.CurrentProtocol,
		protocol.Encode(&blk.BlockHeader),
		protocol.Encode(&blk),
		protocol.Encode(&cert),
	)
	if err != nil {
		return err
	}
	return nil
}

// BlockCompleteCatchup applies catchpoint caught up blocks
func BlockCompleteCatchup(tx *sql.Tx) (err error) {
	_, err = tx.Exec("ALTER TABLE blocks RENAME TO blocks_old")
	if err != nil {
		return err
	}
	_, err = tx.Exec("ALTER TABLE catchpointblocks RENAME TO blocks")
	if err != nil {
		return err
	}
	_, err = tx.Exec("DROP TABLE IF EXISTS blocks_old")
	if err != nil {
		return err
	}
	return nil
}

// BlockAbortCatchup TODO: unused, either actually implement cleanup on catchpoint failure, or delete this
func BlockAbortCatchup(tx *sql.Tx) error {
	// delete the old catchpointblocks table, if there is such.
	for _, stmt := range blockResetExprs {
		stmt = strings.Replace(stmt, "blocks", "catchpointblocks", 1)
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

// BlockPutStaging store a block into catchpoint staging table
func BlockPutStaging(tx *sql.Tx, blk bookkeeping.Block, cert agreement.Certificate) (err error) {
	// insert the new entry
	// window_start defaults to NULL (raw msgp); catchpoint restore does not use compression.
	_, err = tx.Exec("INSERT INTO catchpointblocks (rnd, proto, hdrdata, blkdata, certdata) VALUES (?, ?, ?, ?, ?)",
		blk.Round(),
		blk.CurrentProtocol,
		protocol.Encode(&blk.BlockHeader),
		protocol.Encode(&blk),
		protocol.Encode(&cert),
	)
	if err != nil {
		return err
	}
	return nil
}

// BlockEnsureSingleBlock retains only one (highest) block in catchpoint staging table
func BlockEnsureSingleBlock(tx *sql.Tx) (blk bookkeeping.Block, err error) {
	// delete all the blocks that aren't the latest one.
	var max sql.NullInt64
	err = tx.QueryRow("SELECT MAX(rnd) FROM catchpointblocks").Scan(&max)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ledgercore.ErrNoEntry{}
		}
		return bookkeeping.Block{}, err
	}
	if !max.Valid {
		return bookkeeping.Block{}, ledgercore.ErrNoEntry{}
	}
	round := basics.Round(max.Int64)

	_, err = tx.Exec("DELETE FROM catchpointblocks WHERE rnd<?", round)

	if err != nil {
		return bookkeeping.Block{}, err
	}

	var buf []byte
	err = tx.QueryRow("SELECT blkdata FROM catchpointblocks WHERE rnd=?", round).Scan(&buf)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ledgercore.ErrNoEntry{Round: round}
		}
		return
	}

	err = protocol.Decode(buf, &blk)

	return blk, err
}
