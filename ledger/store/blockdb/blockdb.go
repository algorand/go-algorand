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

// BlockInit initializes blockdb
func BlockInit(tx *sql.Tx, initBlocks []bookkeeping.Block) error {
	for _, tableCreate := range blockSchema {
		_, err := tx.Exec(tableCreate)
		if err != nil {
			return fmt.Errorf("blockdb blockInit could not create table %v", err)
		}
	}

	next, err := BlockNext(tx)
	if err != nil {
		return err
	}

	if next == 0 {
		for _, blk := range initBlocks {
			err = BlockPut(tx, blk, agreement.Certificate{})
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

// BlockGet retrieves a block by a round number
func BlockGet(tx *sql.Tx, rnd basics.Round) (blk bookkeeping.Block, err error) {
	var buf []byte
	err = tx.QueryRow("SELECT blkdata FROM blocks WHERE rnd=?", rnd).Scan(&buf)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ledgercore.ErrNoEntry{Round: rnd}
		}

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

// BlockGetEncodedCert retrieves raw block and cert by a round number
func BlockGetEncodedCert(tx *sql.Tx, rnd basics.Round) (blk []byte, cert []byte, err error) {
	err = tx.QueryRow("SELECT blkdata, certdata FROM blocks WHERE rnd=?", rnd).Scan(&blk, &cert)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ledgercore.ErrNoEntry{Round: rnd}
		}

		return
	}
	return
}

// BlockGetCert retrieves block and cert by a round number
func BlockGetCert(tx *sql.Tx, rnd basics.Round) (blk bookkeeping.Block, cert agreement.Certificate, err error) {
	blkbuf, certbuf, err := BlockGetEncodedCert(tx, rnd)
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

// BlockPut stores block and certificate
func BlockPut(tx *sql.Tx, blk bookkeeping.Block, cert agreement.Certificate) error {
	var max sql.NullInt64
	err := tx.QueryRow("SELECT MAX(rnd) FROM blocks").Scan(&max)
	if err != nil {
		return err
	}

	if max.Valid {
		if blk.Round() != basics.Round(max.Int64+1) {
			err = fmt.Errorf("inserting block %d but expected %d", blk.Round(), max.Int64+1)
			return err
		}
	} else {
		if blk.Round() != 0 {
			err = fmt.Errorf("inserting block %d but expected 0", blk.Round())
			return err
		}
	}

	_, err = tx.Exec("INSERT INTO blocks (rnd, proto, hdrdata, blkdata, certdata) VALUES (?, ?, ?, ?, ?)",
		blk.Round(),
		blk.CurrentProtocol,
		protocol.Encode(&blk.BlockHeader),
		protocol.Encode(&blk),
		protocol.Encode(&cert),
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

	// insert the top entry to the blocks table.
	_, err := tx.Exec("INSERT INTO catchpointblocks (rnd, proto, hdrdata, blkdata, certdata) VALUES (?, ?, ?, ?, ?)",
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
