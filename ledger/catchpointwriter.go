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
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

const balancesChunkReadSize = 512
const initialVersion = uint64(0200)

type catchpointWriter struct {
	hasher           hash.Hash
	innerWriter      io.WriteCloser
	dbr              db.Accessor
	filePath         string
	file             *os.File
	gzip             *gzip.Writer
	tar              *tar.Writer
	headerWritten    bool
	balancesOffset   int
	balancesChunk    catchpointFileBalancesChunk
	fileHeader       *catchpointFileHeader
	balancesChunkNum uint
}

type catchpointFileHeader struct {
	_struct       struct{}      `codec:",omitempty,omitemptyarray"`
	Version       uint64        `codec:"ver"`
	Round         basics.Round  `codec:"rnd"`
	Totals        AccountTotals `codec:"tot"`
	TotalAccounts uint64        `codec:"numacc"`
}

type catchpointFileBalancesChunk []encodedBalanceRecord

func makeCatchpointWriter(filePath string, dbr db.Accessor) *catchpointWriter {
	return &catchpointWriter{
		filePath: filePath,
		dbr:      dbr,
	}
}

func (cw *catchpointWriter) WriteStep(ctx context.Context) (more bool, err error) {
	if cw.file == nil {
		err = os.MkdirAll(filepath.Dir(cw.filePath), 0700)
		if err != nil {
			return
		}
		cw.file, err = os.OpenFile(cw.filePath, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return
		}
		cw.gzip = gzip.NewWriter(cw.file)
		cw.tar = tar.NewWriter(cw.gzip)
	}

	// have we timed-out / canceled by that point ?
	select {
	case <-ctx.Done():
		err = ctx.Err()
		if err == context.DeadlineExceeded {
			return true, nil
		}
		return
	default:
	}

	if cw.fileHeader == nil {
		err = cw.dbr.Atomic(cw.readHeaderFromDatabase)
		if err != nil {
			return
		}
	}

	// have we timed-out / canceled by that point ?
	select {
	case <-ctx.Done():
		err = ctx.Err()
		if err == context.DeadlineExceeded {
			return true, nil
		}
		return
	default:
	}

	if !cw.headerWritten {
		encodedHeader := protocol.EncodeReflect(*cw.fileHeader)
		err = cw.tar.WriteHeader(&tar.Header{
			Name: "content.msgpack",
			Mode: 0600,
			Size: int64(len(encodedHeader)),
		})
		if err != nil {
			return
		}
		_, err = cw.tar.Write(encodedHeader)
		if err != nil {
			return
		}
		cw.headerWritten = true
	}

	for {
		// have we timed-out / canceled by that point ?
		select {
		case <-ctx.Done():
			err = ctx.Err()
			if err == context.DeadlineExceeded {
				return true, nil
			}
			return
		default:
		}

		if len(cw.balancesChunk) == 0 {
			err = cw.dbr.Atomic(cw.readDatabaseStep)
			if err != nil {
				return
			}
		}

		// have we timed-out / canceled by that point ?
		select {
		case <-ctx.Done():
			err = ctx.Err()
			if err == context.DeadlineExceeded {
				return true, nil
			}
			return
		default:
		}

		// write to disk.
		if len(cw.balancesChunk) > 0 {
			cw.balancesChunkNum++
			encodedChunk := protocol.EncodeReflect(cw.balancesChunk)
			err = cw.tar.WriteHeader(&tar.Header{
				Name: fmt.Sprintf("balances.%d.%d.msgpack", cw.balancesChunkNum, (cw.fileHeader.TotalAccounts+balancesChunkReadSize-1)/balancesChunkReadSize),
				Mode: 0600,
				Size: int64(len(encodedChunk)),
			})
			if err != nil {
				return
			}
			_, err = cw.tar.Write(encodedChunk)
			if err != nil {
				return
			}

			if len(cw.balancesChunk) < balancesChunkReadSize {
				cw.tar.Close()
				cw.gzip.Close()
				cw.file.Close()
				cw.balancesChunk = nil
				cw.file = nil
				return false, nil
			}
			cw.balancesChunk = nil
		}

		// have we timed-out / canceled by that point ?
		select {
		case <-ctx.Done():
			err = ctx.Err()
			if err == context.DeadlineExceeded {
				return true, nil
			}
			return
		default:
		}
	}
}

func (cw *catchpointWriter) readDatabaseStep(tx *sql.Tx) (err error) {
	cw.balancesChunk, err = encodedAccountsRange(tx, cw.balancesOffset, balancesChunkReadSize)
	if err == nil {
		cw.balancesOffset += balancesChunkReadSize
	}
	return
}

func (cw *catchpointWriter) readHeaderFromDatabase(tx *sql.Tx) (err error) {
	var header catchpointFileHeader
	header.Round, err = accountsRound(tx)
	if err != nil {
		return
	}
	header.Totals, err = accountsTotals(tx)
	if err != nil {
		return
	}
	header.TotalAccounts, err = totalAccounts(context.Background(), tx)
	if err != nil {
		return
	}
	header.Version = initialVersion
	cw.fileHeader = &header
	return
}
