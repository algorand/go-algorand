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

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

const (
	// BalancesPerCatchpointFileChunk defines the number of accounts that would be stored in each chunk in the catchpoint file.
	// note that the last chunk would typically be less than this number.
	BalancesPerCatchpointFileChunk = 512

	// catchpointFileVersion is the catchpoint file version
	catchpointFileVersion = uint64(0200)

	// maxEncodedAppStateEntries denotes max possible key/value entries for an account
	maxEncodedAppStateEntries = basics.EncodedMaxKeyValueEntries * (basics.EncodedMaxAppParams + basics.EncodedMaxAppLocalStates)
)

// max key or value length including encoding overhead
var maxAppKeyValueLen = config.MaxBytesKeyValueLen * 2

// catchpointWriter is the struct managing the persistance of accounts data into the catchpoint file.
// it's designed to work in a step fashion : a caller will call the WriteStep method in a loop until
// the writing is complete. It might take multiple steps until the operation is over, and the caller
// has the option of throttling the CPU utilization in between the calls.
type catchpointWriter struct {
	ctx               context.Context
	hasher            hash.Hash
	innerWriter       io.WriteCloser
	tx                *sql.Tx
	filePath          string
	file              *os.File
	gzip              *gzip.Writer
	tar               *tar.Writer
	headerWritten     bool
	balancesOffset    int
	balancesChunk     catchpointFileBalancesChunk
	fileHeader        *CatchpointFileHeader
	balancesChunkNum  uint64
	writtenBytes      int64
	blocksRound       basics.Round
	blockHeaderDigest crypto.Digest
	label             string
	accountsIterator  encodedAccountsBatchIter
}

type storageData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Aidx   uint64 `codec:"i"`
	Global bool   `codec:"g"`
	Key    []byte `codec:"k,allocbound=maxAppKeyValueLen"`
	Vtype  uint64 `codec:"t"`
	Venc   []byte `codec:"v,allocbound=maxAppKeyValueLen"`
}

type encodedBalanceRecord struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Address         basics.Address `codec:"pk,allocbound=crypto.DigestSize"`
	MiniAccountData msgp.Raw       `codec:"ad,allocbound=basics.MaxEncodedAccountDataSize"`
	StorageData     []storageData  `codec:"sd,allocbound=maxEncodedAppStateEntries"`
}

// CatchpointFileHeader is the content we would have in the "content.msgpack" file in the catchpoint tar archive.
// we need it to be public, as it's being decoded externally by the catchpointdump utility.
type CatchpointFileHeader struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Version           uint64        `codec:"version"`
	BalancesRound     basics.Round  `codec:"balancesRound"`
	BlocksRound       basics.Round  `codec:"blocksRound"`
	Totals            AccountTotals `codec:"accountTotals"`
	TotalAccounts     uint64        `codec:"accountsCount"`
	TotalChunks       uint64        `codec:"chunksCount"`
	Catchpoint        string        `codec:"catchpoint"`
	BlockHeaderDigest crypto.Digest `codec:"blockHeaderDigest"`
}

type catchpointFileBalancesChunk struct {
	_struct  struct{}               `codec:",omitempty,omitemptyarray"`
	Balances []encodedBalanceRecord `codec:"bl,allocbound=BalancesPerCatchpointFileChunk"`
}

func makeCatchpointWriter(ctx context.Context, filePath string, tx *sql.Tx, blocksRound basics.Round, blockHeaderDigest crypto.Digest, label string) *catchpointWriter {
	return &catchpointWriter{
		ctx:               ctx,
		filePath:          filePath,
		tx:                tx,
		blocksRound:       blocksRound,
		blockHeaderDigest: blockHeaderDigest,
		label:             label,
		accountsIterator:  encodedAccountsBatchIter{orderByAddress: true},
	}
}

func (cw *catchpointWriter) Abort() error {
	cw.accountsIterator.Close()
	if cw.tar != nil {
		cw.tar.Close()
	}
	if cw.gzip != nil {
		cw.gzip.Close()
	}
	if cw.file != nil {
		cw.gzip.Close()
	}
	err := os.Remove(cw.filePath)
	return err
}

func (cw *catchpointWriter) WriteStep(stepCtx context.Context) (more bool, err error) {
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
	if more, err = hasContextDeadlineExceeded(stepCtx); more == true || err != nil {
		return
	}

	if cw.fileHeader == nil {
		err = cw.readHeaderFromDatabase(cw.ctx, cw.tx)
		if err != nil {
			return
		}
	}

	// have we timed-out / canceled by that point ?
	if more, err = hasContextDeadlineExceeded(stepCtx); more == true || err != nil {
		return
	}

	if !cw.headerWritten {
		encodedHeader := protocol.Encode(cw.fileHeader)
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
		if more, err = hasContextDeadlineExceeded(stepCtx); more == true || err != nil {
			return
		}

		if len(cw.balancesChunk.Balances) == 0 {
			err = cw.readDatabaseStep(cw.ctx, cw.tx)
			if err != nil {
				return
			}
		}

		// have we timed-out / canceled by that point ?
		if more, err = hasContextDeadlineExceeded(stepCtx); more == true || err != nil {
			return
		}

		// write to disk.
		if len(cw.balancesChunk.Balances) > 0 {
			cw.balancesChunkNum++
			encodedChunk := protocol.Encode(&cw.balancesChunk)
			err = cw.tar.WriteHeader(&tar.Header{
				Name: fmt.Sprintf("balances.%d.%d.msgpack", cw.balancesChunkNum, cw.fileHeader.TotalChunks),
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

			if len(cw.balancesChunk.Balances) < BalancesPerCatchpointFileChunk || cw.balancesChunkNum == cw.fileHeader.TotalChunks {
				cw.tar.Close()
				cw.gzip.Close()
				cw.file.Close()
				cw.balancesChunk.Balances = nil
				cw.file = nil
				var fileInfo os.FileInfo
				fileInfo, err = os.Stat(cw.filePath)
				if err != nil {
					return false, err
				}
				cw.writtenBytes = fileInfo.Size()
				return false, nil
			}
			cw.balancesChunk.Balances = nil
		}
	}
}

func (cw *catchpointWriter) readDatabaseStep(ctx context.Context, tx *sql.Tx) (err error) {
	cw.balancesChunk.Balances, err = cw.accountsIterator.Next(ctx, tx, BalancesPerCatchpointFileChunk)
	if err == nil {
		cw.balancesOffset += BalancesPerCatchpointFileChunk
	}
	return
}

func (cw *catchpointWriter) readHeaderFromDatabase(ctx context.Context, tx *sql.Tx) (err error) {
	var header CatchpointFileHeader
	header.BalancesRound, _, err = accountsRound(tx)
	if err != nil {
		return
	}
	header.Totals, err = accountsTotals(tx, false)
	if err != nil {
		return
	}
	header.TotalAccounts, err = totalAccounts(context.Background(), tx)
	if err != nil {
		return
	}
	header.TotalChunks = (header.TotalAccounts + BalancesPerCatchpointFileChunk - 1) / BalancesPerCatchpointFileChunk
	header.BlocksRound = cw.blocksRound
	header.Catchpoint = cw.label
	header.Version = catchpointFileVersion
	header.BlockHeaderDigest = cw.blockHeaderDigest
	cw.fileHeader = &header
	return
}

// GetSize returns the number of bytes that have been written to the file.
func (cw *catchpointWriter) GetSize() int64 {
	return cw.writtenBytes
}

// GetBalancesRound returns the round number of the balances to which this catchpoint is generated for.
func (cw *catchpointWriter) GetBalancesRound() basics.Round {
	if cw.fileHeader != nil {
		return cw.fileHeader.BalancesRound
	}
	return basics.Round(0)
}

// GetBalancesCount returns the number of balances written to this catchpoint file.
func (cw *catchpointWriter) GetTotalAccounts() uint64 {
	if cw.fileHeader != nil {
		return cw.fileHeader.TotalAccounts
	}
	return 0
}

// GetCatchpoint returns the catchpoint string to which this catchpoint file was generated for.
func (cw *catchpointWriter) GetCatchpoint() string {
	if cw.fileHeader != nil {
		return cw.fileHeader.Catchpoint
	}
	return ""
}

// hasContextDeadlineExceeded examine the given context and see if it was canceled or timed-out.
// if it has timed out, the function returns contextExceeded=true and contextError = nil.
// if it's a non-timeout error, the functions returns contextExceeded=false and contextError = error.
// otherwise, the function returns the contextExceeded=false and contextError = nil.
func hasContextDeadlineExceeded(ctx context.Context) (contextExceeded bool, contextError error) {
	// have we timed-out / canceled by that point ?
	select {
	case <-ctx.Done():
		contextError = ctx.Err()
		if contextError == context.DeadlineExceeded {
			contextExceeded = true
			contextError = nil
			return
		}
	default:
	}
	return
}
