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
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

const (
	// BalancesPerCatchpointFileChunk defines the number of accounts that would be stored in each chunk in the catchpoint file.
	// note that the last chunk would typically be less than this number.
	BalancesPerCatchpointFileChunk = 512

	// DefaultMaxResourcesPerChunk defines the max number of resources that go in a singular chunk
	// 300000 resources * 300B/resource => roughly max 100MB per chunk
	DefaultMaxResourcesPerChunk = 300000
)

// catchpointWriter is the struct managing the persistence of accounts data into the catchpoint file.
// it's designed to work in a step fashion : a caller will call the WriteStep method in a loop until
// the writing is complete. It might take multiple steps until the operation is over, and the caller
// has the option of throttling the CPU utilization in between the calls.
type catchpointWriter struct {
	ctx                  context.Context
	tx                   *sql.Tx
	filePath             string
	totalAccounts        uint64
	totalChunks          uint64
	file                 *os.File
	tar                  *tar.Writer
	compressor           io.WriteCloser
	chunk                catchpointFileChunkV6
	chunkNum             uint64
	numAccountsProcessed uint64
	writtenBytes         int64
	biggestChunkLen      uint64
	accountsIterator     encodedAccountsBatchIter
	maxResourcesPerChunk int
	accountsDone         bool
	kvRows               *sql.Rows
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

// SortUint64 re-export this sort, which is implemented in basics, and being used by the msgp when
// encoding the resources map below.
type SortUint64 = basics.SortUint64

type encodedBalanceRecordV6 struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Address     basics.Address      `codec:"a,allocbound=crypto.DigestSize"`
	AccountData msgp.Raw            `codec:"b,allocbound=basics.MaxEncodedAccountDataSize"`
	Resources   map[uint64]msgp.Raw `codec:"c,allocbound=basics.MaxEncodedAccountDataSize"`

	// flag indicating whether there are more records for the same account coming up
	ExpectingMoreEntries bool `codec:"e"`
}

type encodedKVRecordV6 struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// Adjust these to be big enough for boxes, but not directly tied to box values.
	Key   []byte `codec:"k,allocbound=128"`   // For boxes: "bx:<10 bytes><64 byte name>"
	Value []byte `codec:"v,allocbound=32768"` // For boxes: MaxBoxSize
}

type catchpointFileChunkV6 struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Balances    []encodedBalanceRecordV6 `codec:"bl,allocbound=BalancesPerCatchpointFileChunk"`
	numAccounts uint64
	KVs         []encodedKVRecordV6 `codec:"kv,allocbound=BalancesPerCatchpointFileChunk"`
}

func (chunk catchpointFileChunkV6) empty() bool {
	return len(chunk.Balances) == 0 && len(chunk.KVs) == 0
}

func makeCatchpointWriter(ctx context.Context, filePath string, tx *sql.Tx, maxResourcesPerChunk int) (*catchpointWriter, error) {
	totalAccounts, err := totalAccounts(ctx, tx)
	if err != nil {
		return nil, err
	}
	totalKVs, err := totalKVs(ctx, tx)
	if err != nil {
		return nil, err
	}

	err = os.MkdirAll(filepath.Dir(filePath), 0700)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	compressor, err := catchpointStage1Encoder(file)
	if err != nil {
		return nil, err
	}
	tar := tar.NewWriter(compressor)

	accountChunks := (totalAccounts + BalancesPerCatchpointFileChunk - 1) / BalancesPerCatchpointFileChunk
	kvChunks := (totalKVs + BalancesPerCatchpointFileChunk - 1) / BalancesPerCatchpointFileChunk
	res := &catchpointWriter{
		ctx:                  ctx,
		tx:                   tx,
		filePath:             filePath,
		totalAccounts:        totalAccounts,
		totalChunks:          accountChunks + kvChunks,
		file:                 file,
		compressor:           compressor,
		tar:                  tar,
		maxResourcesPerChunk: maxResourcesPerChunk,
	}
	return res, nil
}

func (cw *catchpointWriter) Abort() error {
	cw.accountsIterator.Close()
	cw.tar.Close()
	cw.compressor.Close()
	cw.file.Close()
	return os.Remove(cw.filePath)
}

func (cw *catchpointWriter) WriteStep(stepCtx context.Context) (more bool, err error) {
	// have we timed-out / canceled by that point ?
	if more, err = hasContextDeadlineExceeded(stepCtx); more || err != nil {
		return
	}

	writerRequest := make(chan catchpointFileChunkV6, 1)
	writerResponse := make(chan error, 2)
	go cw.asyncWriter(writerRequest, writerResponse, cw.chunkNum, cw.numAccountsProcessed)
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

		if cw.chunk.empty() {
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

		// send the chunk to asyncWriter channel
		if !cw.chunk.empty() {
			cw.numAccountsProcessed += cw.chunk.numAccounts
			cw.chunkNum++
			writerRequest <- cw.chunk
			if cw.numAccountsProcessed == cw.totalAccounts {
				cw.accountsIterator.Close()
				if cw.kvRows != nil {
					cw.kvRows.Close()
					cw.kvRows = nil
				}
				// if we're done, wait for the writer to complete its writing.
				err, opened := <-writerResponse
				if opened {
					// we ran into an error. wait for the channel to close before returning with the error.
					<-writerResponse
					return false, err
				}
				// channel is closed. we're done writing and no issues detected.
				return false, nil
			}
			cw.chunk = catchpointFileChunkV6{}
		}
	}
}

func (cw *catchpointWriter) asyncWriter(chunks chan catchpointFileChunkV6, response chan error, initialChunkNum uint64, initialNumAccounts uint64) {
	defer close(response)
	chunkNum := initialChunkNum
	numAccountsProcessed := initialNumAccounts
	for chk := range chunks {
		chunkNum++
		numAccountsProcessed += chk.numAccounts
		if chk.empty() {
			break
		}

		encodedChunk := protocol.Encode(&chk)
		err := cw.tar.WriteHeader(&tar.Header{
			Name: fmt.Sprintf("balances.%d.%d.msgpack", chunkNum, cw.totalChunks),
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
		if chunkLen := uint64(len(encodedChunk)); cw.biggestChunkLen < chunkLen {
			cw.biggestChunkLen = chunkLen
		}
		if numAccountsProcessed == cw.totalAccounts { // Quits too soon. Consider KVs
			cw.tar.Close()
			cw.compressor.Close()
			cw.file.Close()
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

// readDatabaseStep places the next chunk of records into cw.chunk. It yields
// all the account chunks first, and then the kv chunks. Even if the accounts
// are evenly divisible by BalancesPerCatchpointFileChunk, it muts not return an
// empty chunk between accounts and kvs.
func (cw *catchpointWriter) readDatabaseStep(ctx context.Context, tx *sql.Tx) error {
	if !cw.accountsDone {
		balances, numAccounts, err := cw.accountsIterator.Next(ctx, tx, BalancesPerCatchpointFileChunk, cw.maxResourcesPerChunk)
		if err != nil {
			return err
		}
		if len(balances) > 0 {
			cw.chunk = catchpointFileChunkV6{Balances: balances, numAccounts: numAccounts}
			return nil
		}
		// It might seem reasonable, but do not close accountsIterator here,
		// else it will start over on the next iteration
		// cw.accountsIterator.Close()
		cw.accountsDone = true
	}

	// Create the *Rows iterator JIT
	if cw.kvRows == nil {
		rows, err := tx.QueryContext(ctx, "SELECT key, value FROM kvstore")
		if err != nil {
			return err
		}
		cw.kvRows = rows
	}

	kvrs := make([]encodedKVRecordV6, 0, BalancesPerCatchpointFileChunk)
	for cw.kvRows.Next() {
		var k []byte
		var v []byte
		err := cw.kvRows.Scan(&k, &v)
		if err != nil {
			return err
		}
		record := encodedKVRecordV6{Key: k, Value: v}
		kvrs = append(kvrs, record)
		if len(kvrs) == BalancesPerCatchpointFileChunk {
			break
		}
	}
	cw.chunk = catchpointFileChunkV6{KVs: kvrs}
	return nil
}

// GetSize returns the number of bytes that have been written to the file.
func (cw *catchpointWriter) GetSize() int64 {
	return cw.writtenBytes
}

// GetBalancesCount returns the number of balances written to this catchpoint file.
func (cw *catchpointWriter) GetTotalAccounts() uint64 {
	return cw.totalAccounts
}

func (cw *catchpointWriter) GetTotalChunks() uint64 {
	return cw.totalChunks
}

func (cw *catchpointWriter) GetBiggestChunkLen() uint64 {
	return cw.biggestChunkLen
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
