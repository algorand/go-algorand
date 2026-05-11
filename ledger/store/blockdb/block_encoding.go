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

// encodeBlockCertData runs the block and certificate payloads through the
// writer's per-column encoders. The returned anchorRound is the round that
// opens the zstd frame containing this row; callers translate it into a
// window_start column value (NULL when the codec is disabled). Both
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

// isCodecChunk reports whether chunk is a windowed-zstd chunk (begins with
// the zstd frame magic). Legacy raw, NULL-window rows are msgp and start
// with a fixmap header byte (0x80-0xDF), so the two cannot collide on the
// first byte. A continuation chunk inside an active frame is unambiguously
// codec because the SQL range scan only returns more than one row when
// window_start IS NOT NULL.
func isCodecChunk(chunk []byte) bool {
	return len(chunk) >= 4 && chunk[0] == 0x28 && chunk[1] == 0xb5 && chunk[2] == 0x2f && chunk[3] == 0xfd
}

// blockGetEncoded returns the raw blkdata (and certdata, unless blkOnly is
// set) for round rnd, transparently undoing windowed-zstd compression. The
// SQL statement does the structural work: an inner subquery looks up the
// target row's window_start, and the outer range scan pulls every row in
// [IFNULL(window_start, rnd), rnd] in one PK range read. A legacy/disabled
// row or a codec-anchor row collapses to a single row; a deep continuation
// returns the anchor plus everything up through rnd.
func blockGetEncoded(tx *sql.Tx, rnd basics.Round, blkOnly bool) (blk []byte, cert []byte, err error) {
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

	if len(blkChunks) == 1 && !isCodecChunk(blkChunks[0]) {
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
