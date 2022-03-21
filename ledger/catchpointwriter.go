// Copyright (C) 2019-2022 Algorand, Inc.
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
	"os"
	"path/filepath"

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
)

const (
	// BalancesPerCatchpointFileChunk defines the number of accounts that would be stored in each chunk in the catchpoint file.
	// note that the last chunk would typically be less than this number.
	BalancesPerCatchpointFileChunk = 512

	// CatchpointFileVersionV5 is the catchpoint file version that was used when the database schema was V0-V5.
	CatchpointFileVersionV5 = uint64(0200)

	// CatchpointFileVersionV6 is the catchpoint file version that is matching database schema V6
	CatchpointFileVersionV6 = uint64(0201)
)

// catchpointWriter is the struct managing the persistence of accounts data into the catchpoint file.
// it's designed to work in a step fashion : a caller will call the WriteStep method in a loop until
// the writing is complete. It might take multiple steps until the operation is over, and the caller
// has the option of throttling the CPU utilization in between the calls.
type catchpointWriter struct {
	ctx               context.Context
	tx                *sql.Tx
	filePath          string
	file              *os.File
	gzip              *gzip.Writer
	tar               *tar.Writer
	headerWritten     bool
	balancesOffset    int
	balancesChunk     catchpointFileBalancesChunkV6
	fileHeader        *CatchpointFileHeader
	balancesChunkNum  uint64
	writtenBytes      int64
	blocksRound       basics.Round
	blockHeaderDigest crypto.Digest
	label             string
	accountsIterator  encodedAccountsBatchIter
}

type encodedBalanceRecordV5 struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Address     basics.Address `codec:"pk,allocbound=crypto.DigestSize"`
	AccountData msgp.Raw       `codec:"ad,allocbound=basics.MaxEncodedAccountDataSize"`
}

type catchpointFileBalancesChunkV5 struct {
	_struct  struct{}                 `codec:",omitempty,omitemptyarray"`
	Balances []encodedBalanceRecordV5 `codec:"bl,allocbound=BalancesPerCatchpointFileChunk"`
}

// SortUint64 re-export this sort, which is implmented in basics, and being used by the msgp when
// encoding the resources map below.
type SortUint64 = basics.SortUint64

type encodedBalanceRecordV6 struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Address     basics.Address      `codec:"a,allocbound=crypto.DigestSize"`
	AccountData msgp.Raw            `codec:"b,allocbound=basics.MaxEncodedAccountDataSize"`
	Resources   map[uint64]msgp.Raw `codec:"c,allocbound=basics.MaxEncodedAccountDataSize"`
}

type catchpointFileBalancesChunkV6 struct {
	_struct  struct{}                 `codec:",omitempty,omitemptyarray"`
	Balances []encodedBalanceRecordV6 `codec:"bl,allocbound=BalancesPerCatchpointFileChunk"`
}

// CatchpointFileHeader is the content we would have in the "content.msgpack" file in the catchpoint tar archive.
// we need it to be public, as it's being decoded externally by the catchpointdump utility.
type CatchpointFileHeader struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Version           uint64                   `codec:"version"`
	BalancesRound     basics.Round             `codec:"balancesRound"`
	BlocksRound       basics.Round             `codec:"blocksRound"`
	Totals            ledgercore.AccountTotals `codec:"accountTotals"`
	TotalAccounts     uint64                   `codec:"accountsCount"`
	TotalChunks       uint64                   `codec:"chunksCount"`
	Catchpoint        string                   `codec:"catchpoint"`
	BlockHeaderDigest crypto.Digest            `codec:"blockHeaderDigest"`
}

func makeCatchpointWriter(ctx context.Context, filePath string, tx *sql.Tx, blocksRound basics.Round, blockHeaderDigest crypto.Digest, label string) *catchpointWriter {
	return &catchpointWriter{
		ctx:               ctx,
		filePath:          filePath,
		tx:                tx,
		blocksRound:       blocksRound,
		blockHeaderDigest: blockHeaderDigest,
		label:             label,
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
	if more, err = hasContextDeadlineExceeded(stepCtx); more || err != nil {
		return
	}

	if cw.fileHeader == nil {
		err = cw.readHeaderFromDatabase(cw.ctx, cw.tx)
		if err != nil {
			return
		}
	}

	// have we timed-out / canceled by that point ?
	if more, err = hasContextDeadlineExceeded(stepCtx); more || err != nil {
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

	writerRequest := make(chan catchpointFileBalancesChunkV6, 1)
	writerResponse := make(chan error, 2)
	go cw.asyncWriter(writerRequest, writerResponse, cw.balancesChunkNum)
	defer func() {
		close(writerRequest)
		// wait for the writerResponse to close.
		for {
			select {
			case writerError, open := <-writerResponse:
				if open {
					err = writerError
				} else {
					return
				}
			}
		}
	}()

	for {
		// have we timed-out / canceled by that point ?
		if more, err = hasContextDeadlineExceeded(stepCtx); more || err != nil {
			return
		}

		if len(cw.balancesChunk.Balances) == 0 {
			err = cw.readDatabaseStep(cw.ctx, cw.tx)
			if err != nil {
				return
			}
		}

		// have we timed-out / canceled by that point ?
		if more, err = hasContextDeadlineExceeded(stepCtx); more || err != nil {
			return
		}

		// check if we had any error on the writer from previous iterations.
		select {
		case err := <-writerResponse:
			// we ran into an error. wait for the channel to close before returning with the error.
			<-writerResponse
			return false, err
		default:
		}

		// write to disk.
		if len(cw.balancesChunk.Balances) > 0 {
			cw.balancesChunkNum++
			writerRequest <- cw.balancesChunk
			if len(cw.balancesChunk.Balances) < BalancesPerCatchpointFileChunk || cw.balancesChunkNum == cw.fileHeader.TotalChunks {
				cw.accountsIterator.Close()
				// if we're done, wait for the writer to complete it's writing.
				err, opened := <-writerResponse
				if opened {
					// we ran into an error. wait for the channel to close before returning with the error.
					<-writerResponse
					return false, err
				}
				// channel is closed. we're done writing and no issues detected.
				return false, nil
			}
			cw.balancesChunk.Balances = nil
		}
	}
}

func (cw *catchpointWriter) asyncWriter(balances chan catchpointFileBalancesChunkV6, response chan error, initialBalancesChunkNum uint64) {
	defer close(response)
	balancesChunkNum := initialBalancesChunkNum
	for bc := range balances {
		balancesChunkNum++
		if len(bc.Balances) == 0 {
			break
		}

		encodedChunk := protocol.Encode(&bc)
		err := cw.tar.WriteHeader(&tar.Header{
			Name: fmt.Sprintf("balances.%d.%d.msgpack", balancesChunkNum, cw.fileHeader.TotalChunks),
			Mode: 0600,
			Size: int64(len(encodedChunk)),
		})
		if err != nil {
			response <- err
			break
		}
		_, err = cw.tar.Write(encodedChunk)
		if err != nil {
			response <- err
			break
		}

		if len(bc.Balances) < BalancesPerCatchpointFileChunk || balancesChunkNum == cw.fileHeader.TotalChunks {
			cw.tar.Close()
			cw.gzip.Close()
			cw.file.Close()
			cw.file = nil
			var fileInfo os.FileInfo
			fileInfo, err = os.Stat(cw.filePath)
			if err != nil {
				response <- err
				break
			}
			cw.writtenBytes = fileInfo.Size()
			break
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
	header.BalancesRound, err = accountsRound(tx)
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
	header.Version = CatchpointFileVersionV6
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
