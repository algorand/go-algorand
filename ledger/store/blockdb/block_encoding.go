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

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

// HasWindowStart reports whether the blocks table has the window_start
// column. Callers should evaluate this once per process (typically right
// after BlockInit) and thread the result through to every BlockGet /
// BlockGetCert / BlockGetEncodedCert call so the read path doesn't have to
// introspect the schema or recover from a failed query per read.
func HasWindowStart(tx *sql.Tx) (bool, error) {
	return tableHasColumn(tx, "blocks", "window_start")
}

func tableHasColumn(tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// encodeBlockCertData runs the block and certificate payloads through the
// writer's per-column encoders. The returned anchorRound is the round that
// opens the zstd frame containing this row; callers translate it into a
// window_start column value (NULL when compression is disabled). Both
// columns share an EncoderPair so they always advance their anchors
// together; only one anchorRound is returned because the two are equal by
// construction. The writer must be non-nil.
func encodeBlockCertData(blk *bookkeeping.Block, cert *agreement.Certificate, writer *BlockWriter) (blkChunk, certChunk []byte, anchorRound basics.Round, err error) {
	pair := writer.pair()
	r := blk.Round()

	blkBytes := protocol.Encode(blk)
	certBytes := protocol.Encode(cert)
	blkChunk, anchorRound, err = pair.Blk.EncodeRow(r, blkBytes)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("blockdb: encode blkdata: %w", err)
	}
	certChunk, _, err = pair.Cert.EncodeRow(r, certBytes)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("blockdb: encode certdata: %w", err)
	}
	return blkChunk, certChunk, anchorRound, nil
}

// isCompressedChunk reports whether chunk is a windowed-zstd chunk (begins
// with the zstd frame magic). Legacy raw, NULL-window rows are msgp and
// start with a fixmap header byte (0x80-0xDF), so the two cannot collide on
// the first byte. A continuation chunk inside an active frame is
// unambiguously compressed because the SQL range scan only returns more
// than one row when window_start IS NOT NULL.
func isCompressedChunk(chunk []byte) bool {
	return len(chunk) >= 4 && chunk[0] == 0x28 && chunk[1] == 0xb5 && chunk[2] == 0x2f && chunk[3] == 0xfd
}

// blockGetEncoded returns the raw blkdata (and certdata, unless blkOnly is
// set) for round rnd, transparently undoing windowed-zstd compression.
//
// hasWindowStart selects between two read shapes:
//   - true: the windowed SELECT, which lets a single SQL statement find the
//     row's frame anchor (inner subquery) and pull every row in [anchor,
//     rnd] (outer range scan). A disabled/raw row or an anchor row
//     collapses to one row; a deep continuation reads the anchor plus
//     everything up through rnd.
//   - false: a single-row PK lookup. This is the only shape valid on a DB
//     whose schema has no window_start column, i.e. a DB written entirely
//     by a release that predates the compression PR. All rows in such a DB
//     are raw msgp, so the simple query is correct.
//
// Callers MUST pass the value returned by HasWindowStart at open time; the
// read path does not introspect the schema on the hot path.
func blockGetEncoded(tx *sql.Tx, rnd basics.Round, blkOnly, hasWindowStart bool) (blk []byte, cert []byte, err error) {
	if !hasWindowStart {
		return blockGetEncodedSimple(tx, rnd, blkOnly)
	}
	return blockGetEncodedWindowed(tx, rnd, blkOnly)
}

// blockGetEncodedWindowed runs the unified windowed SELECT and decodes the
// result. It requires the blocks table to have the window_start column.
func blockGetEncodedWindowed(tx *sql.Tx, rnd basics.Round, blkOnly bool) (blk []byte, cert []byte, err error) {
	const queryBlk = `SELECT b.blkdata FROM blocks b,
	  (SELECT window_start FROM blocks WHERE rnd = ?1) t
	  WHERE b.rnd >= IFNULL(t.window_start, ?1) AND b.rnd <= ?1
	  ORDER BY b.rnd ASC`
	const queryBoth = `SELECT b.blkdata, b.certdata FROM blocks b,
	  (SELECT window_start FROM blocks WHERE rnd = ?1) t
	  WHERE b.rnd >= IFNULL(t.window_start, ?1) AND b.rnd <= ?1
	  ORDER BY b.rnd ASC`

	q := queryBoth
	if blkOnly {
		q = queryBlk
	}
	rows, err := tx.Query(q, rnd)
	if err != nil {
		return
	}
	defer rows.Close()

	var blkChunks, certChunks [][]byte
	for rows.Next() {
		var b, c []byte
		if blkOnly {
			err = rows.Scan(&b)
		} else {
			err = rows.Scan(&b, &c)
		}
		if err != nil {
			return
		}
		blkChunks = append(blkChunks, b)
		if !blkOnly {
			certChunks = append(certChunks, c)
		}
	}
	if err = rows.Err(); err != nil {
		return
	}
	if len(blkChunks) == 0 {
		err = ledgercore.ErrNoEntry{Round: rnd}
		return
	}

	if len(blkChunks) == 1 && !isCompressedChunk(blkChunks[0]) {
		blk = blkChunks[0]
		if !blkOnly {
			cert = certChunks[0]
		}
		return
	}

	blk, err = decodeWindow(blkChunks)
	if err != nil {
		err = fmt.Errorf("blockdb: decode blkdata at round %d: %w", rnd, err)
		return
	}
	if !blkOnly {
		cert, err = decodeWindow(certChunks)
		if err != nil {
			err = fmt.Errorf("blockdb: decode certdata at round %d: %w", rnd, err)
			return
		}
	}
	return
}

// blockGetEncodedSimple is the pre-compression read path: every row is its
// own self-contained raw msgp blob, no window decode needed.
func blockGetEncodedSimple(tx *sql.Tx, rnd basics.Round, blkOnly bool) (blk []byte, cert []byte, err error) {
	if blkOnly {
		err = tx.QueryRow("SELECT blkdata FROM blocks WHERE rnd=?", rnd).Scan(&blk)
	} else {
		err = tx.QueryRow("SELECT blkdata, certdata FROM blocks WHERE rnd=?", rnd).Scan(&blk, &cert)
	}
	if err == sql.ErrNoRows {
		err = ledgercore.ErrNoEntry{Round: rnd}
	}
	return
}
