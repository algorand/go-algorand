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

func encodeBlockCertData(blk bookkeeping.Block, cert agreement.Certificate, writer *BlockWriter) (blkChunk, certChunk []byte, err error) {
	if writer == nil {
		writer = NewBlockWriter(0)
	}
	pair := writer.pair()

	blkBytes := protocol.Encode(&blk)
	certBytes := protocol.Encode(&cert)
	blkChunk, err = pair.Blk.EncodeRow(blk.Round(), blkBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("blockdb: encode blkdata: %w", err)
	}
	certChunk, err = pair.Cert.EncodeRow(blk.Round(), certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("blockdb: encode certdata: %w", err)
	}
	return blkChunk, certChunk, nil
}

// blockGetEncoded returns the raw blkdata (and certdata, unless blkOnly is
// set) for round rnd, transparently undoing windowed-zstd compression. Rows
// written before the codec was introduced have no format prefix and are
// returned verbatim. When blkOnly is true the certdata column is never
// fetched, so block-only lookups do not pay the per-row cert IO that the
// codec amplifies. The lookback is fixed at MaxCompressionWindow so reads
// remain correct across config changes, including when compression has been
// disabled while old windowed rows still occupy the DB.
func blockGetEncoded(tx *sql.Tx, rnd basics.Round, blkOnly bool) (blk []byte, cert []byte, err error) {
	cols := "blkdata, certdata"
	if blkOnly {
		cols = "blkdata"
	}
	var blkChunk, certChunk []byte
	if blkOnly {
		err = tx.QueryRow("SELECT "+cols+" FROM blocks WHERE rnd=?", rnd).Scan(&blkChunk)
	} else {
		err = tx.QueryRow("SELECT "+cols+" FROM blocks WHERE rnd=?", rnd).Scan(&blkChunk, &certChunk)
	}
	if err != nil {
		if err == sql.ErrNoRows {
			err = ledgercore.ErrNoEntry{Round: rnd}
		}
		return
	}

	// Fast path: legacy raw rows or formatRaw rows decode without touching
	// any other rows.
	if !needsWindow(blkChunk) && (blkOnly || !needsWindow(certChunk)) {
		blk, err = decodeStandaloneRow(blkChunk)
		if err != nil {
			return
		}
		if !blkOnly {
			cert, err = decodeStandaloneRow(certChunk)
		}
		return
	}

	// Slow path: scan up to MaxCompressionWindow rows ending at rnd. The
	// lookback is fixed at the maximum supported window size so reads
	// remain correct even if BlockDBCompressionWindow was previously larger
	// than the current config value, or if the user disabled compression
	// while old windowed rows still occupy the DB. The actual frame anchor
	// is found via FindAnchorOffset, so encoders that started a window
	// mid-N (post-restart) decode correctly too.
	lookback := uint64(MaxCompressionWindow - 1)
	lo := rnd
	if uint64(rnd) >= lookback {
		lo = rnd - basics.Round(lookback)
	} else {
		lo = 0
	}
	blkChunks, certChunks, rerr := readWindowChunks(tx, lo, rnd, blkOnly)
	if rerr != nil {
		err = rerr
		return
	}
	anchorIdx := FindAnchorOffset(blkChunks)
	if anchorIdx < 0 {
		err = fmt.Errorf("blockdb: no zstd frame anchor found in [%d,%d]", lo, rnd)
		return
	}
	blk, err = DecodeWindow(blkChunks[anchorIdx:])
	if err != nil {
		return
	}
	if !blkOnly {
		cert, err = DecodeWindow(certChunks[anchorIdx:])
	}
	return
}

// readWindowChunks returns the blkdata (and optionally certdata) chunks
// for the inclusive round range [lo, hi] in ascending order. Missing rows
// at the low end of the range are silently elided (they may legitimately
// be missing because of round 0 or because of forget-before retention).
// When blkOnly is true the certdata column is not fetched and the
// returned certChunks slice is nil.
func readWindowChunks(tx *sql.Tx, lo, hi basics.Round, blkOnly bool) (blkChunks, certChunks [][]byte, err error) {
	cols := "blkdata, certdata"
	if blkOnly {
		cols = "blkdata"
	}
	rows, err := tx.Query("SELECT "+cols+" FROM blocks WHERE rnd>=? AND rnd<=? ORDER BY rnd ASC", lo, hi)
	if err != nil {
		return
	}
	defer rows.Close()
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
	err = rows.Err()
	return
}

// needsWindow reports whether a row chunk needs cross-row data to decode.
// Both windowed prefixes (anchor and continuation) require fetching the
// surrounding window because the anchor chunk holds the zstd frame header
// and the continuations hold its delta blocks.
func needsWindow(chunk []byte) bool {
	if len(chunk) == 0 {
		return false
	}
	switch chunk[0] {
	case formatWindowedAnchor, formatWindowedContinuation:
		return true
	}
	return false
}

// decodeStandaloneRow returns the raw payload for a chunk that does not
// require cross-row data (legacy raw or formatRaw prefix).
func decodeStandaloneRow(chunk []byte) ([]byte, error) {
	if len(chunk) == 0 {
		return nil, nil
	}
	if needsWindow(chunk) {
		return nil, fmt.Errorf("blockdb: standalone-decode called on windowed chunk (prefix %#x)", chunk[0])
	}
	return DecodeRaw(chunk), nil
}
