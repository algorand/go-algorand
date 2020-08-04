// Copyright (C) 2019-2020 Algorand, Inc.
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
	"bytes"
	"database/sql"
	"fmt"
	"strings"

	"github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
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

func blockInit(tx *sql.Tx, initBlocks []bookkeeping.Block) error {
	for _, tableCreate := range blockSchema {
		_, err := tx.Exec(tableCreate)
		if err != nil {
			return fmt.Errorf("blockdb blockInit could not create table %v", err)
		}
	}

	next, err := blockNext(tx)
	if err != nil {
		return err
	}

	if next == 0 {
		for _, blk := range initBlocks {
			err = blockPut(tx, blk, agreement.Certificate{})
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

func blockResetDB(tx *sql.Tx) error {
	for _, stmt := range blockResetExprs {
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

func blockGet(tx *sql.Tx, rnd basics.Round) (blk bookkeeping.Block, err error) {
	var buf []byte
	err = tx.QueryRow("SELECT blkdata FROM blocks WHERE rnd=?", rnd).Scan(&buf)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ErrNoEntry{Round: rnd}
		}

		return
	}

	err = protocol.Decode(buf, &blk)
	return
}

func blockGetHdr(tx *sql.Tx, rnd basics.Round) (hdr bookkeeping.BlockHeader, err error) {
	var buf []byte
	err = tx.QueryRow("SELECT hdrdata FROM blocks WHERE rnd=?", rnd).Scan(&buf)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ErrNoEntry{Round: rnd}
		}

		return
	}

	err = protocol.Decode(buf, &hdr)
	return
}

func blockGetEncodedCert(tx *sql.Tx, rnd basics.Round) (blk []byte, cert []byte, err error) {
	err = tx.QueryRow("SELECT blkdata, certdata FROM blocks WHERE rnd=?", rnd).Scan(&blk, &cert)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ErrNoEntry{Round: rnd}
		}

		return
	}
	return
}

func blockGetCert(tx *sql.Tx, rnd basics.Round) (blk bookkeeping.Block, cert agreement.Certificate, err error) {
	blkbuf, certbuf, err := blockGetEncodedCert(tx, rnd)
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

func blockReplaceIfExists(tx *sql.Tx, log logging.Logger, blk bookkeeping.Block, cert agreement.Certificate) (updated bool, err error) {
	// Fetch encoded block + cert for the requested round so we can compare
	var oldProto protocol.ConsensusVersion
	var oldHdr, oldBlk, oldCert []byte
	const query = "SELECT proto, hdrdata, blkdata, certdata FROM blocks WHERE rnd=?"
	err = tx.QueryRow(query, blk.Round()).Scan(&oldProto, &oldHdr, &oldBlk, &oldCert)
	if err != nil {
		// Didn't have a block to replace, no problem
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	// Encode new block + cert in order to check against old values and replace
	newProto := blk.CurrentProtocol
	newHdr := protocol.Encode(&blk.BlockHeader)
	newBlk := protocol.Encode(&blk)
	newCert := protocol.Encode(&cert)

	// Log if protocol version or certificate changed for the block we're replacing
	if newProto != oldProto {
		log.Warnf("blockReplaceIfExists(%v): old proto %v != new proto %v", blk.Round(), oldProto, newProto)
	}
	if !bytes.Equal(oldCert, newCert) {
		log.Warnf("blockReplaceIfExists(%v): old cert %v != new cert %v", blk.Round(), oldCert, newCert)
	}

	// Replace the block
	res, err := tx.Exec("UPDATE blocks SET proto=?, hdrdata=?, blkdata=?, certdata=? WHERE rnd=?",
		newProto,
		newHdr,
		newBlk,
		newCert,
		blk.Round(),
	)
	if err != nil {
		return false, err
	}

	// Ensure we actually updated a row
	cnt, err := res.RowsAffected()
	if err != nil {
		return true, err
	}
	if cnt > 0 {
		return true, nil
	}

	// Shouldn't get here since we found the block
	log.Warnf("blockReplaceIfExists(%v): found block but didn't update any rows?", blk.Round())
	return false, nil
}

func blockPut(tx *sql.Tx, blk bookkeeping.Block, cert agreement.Certificate) error {
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

func blockNext(tx *sql.Tx) (basics.Round, error) {
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

func blockLatest(tx *sql.Tx) (basics.Round, error) {
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

func blockEarliest(tx *sql.Tx) (basics.Round, error) {
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

func blockForgetBefore(tx *sql.Tx, rnd basics.Round) error {
	next, err := blockNext(tx)
	if err != nil {
		return err
	}

	if rnd >= next {
		return fmt.Errorf("forgetting too much: rnd %d >= next %d", rnd, next)
	}

	_, err = tx.Exec("DELETE FROM blocks WHERE rnd<?", rnd)
	return err
}

func blockStartCatchupStaging(tx *sql.Tx, blk bookkeeping.Block) error {
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
	_, err := tx.Exec("INSERT INTO catchpointblocks (rnd, proto, hdrdata, blkdata) VALUES (?, ?, ?, ?)",
		blk.Round(),
		blk.CurrentProtocol,
		protocol.Encode(&blk.BlockHeader),
		protocol.Encode(&blk),
	)
	if err != nil {
		return err
	}
	return nil
}

func blockCompleteCatchup(tx *sql.Tx) (err error) {
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

func blockAbortCatchup(tx *sql.Tx) error {
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

func blockPutStaging(tx *sql.Tx, blk bookkeeping.Block) (err error) {
	// insert the new entry
	_, err = tx.Exec("INSERT INTO catchpointblocks (rnd, proto, hdrdata, blkdata) VALUES (?, ?, ?, ?)",
		blk.Round(),
		blk.CurrentProtocol,
		protocol.Encode(&blk.BlockHeader),
		protocol.Encode(&blk),
	)
	if err != nil {
		return err
	}
	return nil
}

func blockEnsureSingleBlock(tx *sql.Tx) (blk bookkeeping.Block, err error) {
	// delete all the blocks that aren't the latest one.
	var max sql.NullInt64
	err = tx.QueryRow("SELECT MAX(rnd) FROM catchpointblocks").Scan(&max)
	if err != nil {
		if err == sql.ErrNoRows {
			err = ErrNoEntry{}
		}
		return bookkeeping.Block{}, err
	}
	if !max.Valid {
		return bookkeeping.Block{}, ErrNoEntry{}
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
			err = ErrNoEntry{Round: round}
		}
		return
	}

	err = protocol.Decode(buf, &blk)

	return blk, err
}
