// Copyright (C) 2019-2023 Algorand, Inc.
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
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/ledger/encoded"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

const (
	// BalancesPerCatchpointFileChunk defines the number of accounts that would be stored in each chunk in the catchpoint file.
	// note that the last chunk would typically be less than this number.
	BalancesPerCatchpointFileChunk = 512

	// ResourcesPerCatchpointFileChunk defines the max number of resources that go in a singular chunk
	// 100,000 resources * 20KB/resource => roughly max 2GB per chunk if all of them are max'ed out apps.
	// In reality most entries are asset holdings, and they are very small.
	ResourcesPerCatchpointFileChunk = 100_000

	// SPContextPerCatchpointFile defines the maximum number of state proof verification data stored
	// in the catchpoint file.
	// (2 years * 31536000 seconds per year) / (256 rounds per state proof verification data * 3.6 seconds per round) ~= 70000
	SPContextPerCatchpointFile = 70000
)

// catchpointWriter is the struct managing the persistence of accounts data into the catchpoint file.
// it's designed to work in a step fashion : a caller will call the WriteStep method in a loop until
// the writing is complete. It might take multiple steps until the operation is over, and the caller
// has the option of throttling the CPU utilization in between the calls.
type catchpointWriter struct {
	ctx                  context.Context
	tx                   trackerdb.TransactionScope
	filePath             string
	totalAccounts        uint64
	totalKVs             uint64
	file                 *os.File
	tar                  *tar.Writer
	compressor           io.WriteCloser
	chunk                catchpointFileChunkV6
	chunkNum             uint64
	writtenBytes         int64
	biggestChunkLen      uint64
	accountsIterator     accountsBatchIter
	maxResourcesPerChunk int
	accountsDone         bool
	kvRows               kvIter
}

type kvIter interface {
	Next() bool
	KeyValue() ([]byte, []byte, error)
	Close()
}

type accountsBatchIter interface {
	Next(ctx context.Context, accountCount int, resourceCount int) ([]encoded.BalanceRecordV6, uint64, error)
	Close()
}

type catchpointFileBalancesChunkV5 struct {
	_struct  struct{}                  `codec:",omitempty,omitemptyarray"`
	Balances []encoded.BalanceRecordV5 `codec:"bl,allocbound=BalancesPerCatchpointFileChunk"`
}

type catchpointFileChunkV6 struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Balances    []encoded.BalanceRecordV6 `codec:"bl,allocbound=BalancesPerCatchpointFileChunk"`
	numAccounts uint64
	KVs         []encoded.KVRecordV6 `codec:"kv,allocbound=BalancesPerCatchpointFileChunk"`
}

func (chunk catchpointFileChunkV6) empty() bool {
	return len(chunk.Balances) == 0 && len(chunk.KVs) == 0
}

type catchpointStateProofVerificationContext struct {
	_struct struct{}                                   `codec:",omitempty,omitemptyarray"`
	Data    []ledgercore.StateProofVerificationContext `codec:"spd,allocbound=SPContextPerCatchpointFile"`
}

func (data catchpointStateProofVerificationContext) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.StateProofVerCtx, protocol.Encode(&data)
}

func makeCatchpointWriter(ctx context.Context, filePath string, tx trackerdb.TransactionScope, maxResourcesPerChunk int) (*catchpointWriter, error) {
	aw, err := tx.MakeAccountsReader()
	if err != nil {
		return nil, err
	}

	totalAccounts, err := aw.TotalAccounts(ctx)
	if err != nil {
		return nil, err
	}

	totalKVs, err := aw.TotalKVs(ctx)
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

	res := &catchpointWriter{
		ctx:                  ctx,
		tx:                   tx,
		filePath:             filePath,
		totalAccounts:        totalAccounts,
		totalKVs:             totalKVs,
		file:                 file,
		compressor:           compressor,
		tar:                  tar,
		accountsIterator:     tx.MakeEncodedAccoutsBatchIter(),
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

func (cw *catchpointWriter) WriteStateProofVerificationContext() (crypto.Digest, error) {
	rawData, err := cw.tx.MakeSpVerificationCtxReader().GetAllSPContexts(cw.ctx)
	if err != nil {
		return crypto.Digest{}, err
	}

	wrappedData := catchpointStateProofVerificationContext{Data: rawData}
	dataHash, encodedData := crypto.EncodeAndHash(wrappedData)

	err = cw.tar.WriteHeader(&tar.Header{
		Name: catchpointSPVerificationFileName,
		Mode: 0600,
		Size: int64(len(encodedData)),
	})

	if err != nil {
		return crypto.Digest{}, err
	}

	_, err = cw.tar.Write(encodedData)
	if err != nil {
		return crypto.Digest{}, err
	}

	if chunkLen := uint64(len(encodedData)); cw.biggestChunkLen < chunkLen {
		cw.biggestChunkLen = chunkLen
	}

	return dataHash, nil
}

// WriteStep works for a short period of time (determined by stepCtx) to get
// some more data (accounts/resources/kvpairs) by using readDatabaseStep, and
// write that data to the open tar file in cw.tar.  The writing is done in
// asyncWriter, so that it can proceed concurrently with reading the data from
// the db. asyncWriter only runs long enough to process the data read during a
// single call to WriteStep, and WriteStep ensures that asyncWriter has finished
// writing by waiting for it in a defer block, collecting any errors that may
// have occurred during writing.  Therefore, WriteStep looks like a simple
// synchronous function to its callers.
func (cw *catchpointWriter) WriteStep(stepCtx context.Context) (more bool, err error) {
	// have we timed-out / canceled by that point ?
	if more, err = hasContextDeadlineExceeded(stepCtx); more || err != nil {
		return
	}

	writerRequest := make(chan catchpointFileChunkV6, 1)
	writerResponse := make(chan error, 2)
	go cw.asyncWriter(writerRequest, writerResponse, cw.chunkNum)
	defer func() {
		// For simplicity, all cleanup is done once, here. The writerRequest is
		// closed, signaling asyncWriter that it can exit, and then
		// writerResponse is drained, ensuring any problems from asyncWriter are
		// noted (and that the writing is done).
		close(writerRequest)
	drain:
		for {
			select {
			case writerError, open := <-writerResponse:
				if open {
					err = writerError
				} else {
					break drain
				}
			}
		}
		if !more {
			// If we're done, close up the tar file and report on size
			cw.tar.Close()
			cw.compressor.Close()
			cw.file.Close()
			fileInfo, statErr := os.Stat(cw.filePath)
			if statErr != nil {
				err = statErr
			}
			cw.writtenBytes = fileInfo.Size()

			// These don't HAVE to be closed, since the "owning" tx will be cmmmitted/rolledback
			cw.accountsIterator.Close()
			if cw.kvRows != nil {
				cw.kvRows.Close()
				cw.kvRows = nil
			}
		}
	}()

	for {
		// have we timed-out or been canceled ?
		if more, err = hasContextDeadlineExceeded(stepCtx); more || err != nil {
			return
		}

		if cw.chunk.empty() {
			err = cw.readDatabaseStep(cw.ctx)
			if err != nil {
				return
			}
			// readDatabaseStep yielded nothing, we're done
			if cw.chunk.empty() {
				return false, nil
			}
		}

		// have we timed-out or been canceled ?
		if more, err = hasContextDeadlineExceeded(stepCtx); more || err != nil {
			return
		}

		// check if we had any error on the writer from previous iterations.
		// this should not be required for correctness, since we'll find the
		// error in the defer block. But this might notice earlier.
		select {
		case err := <-writerResponse:
			return false, err
		default:
		}

		// send the chunk to the asyncWriter channel
		cw.chunkNum++
		writerRequest <- cw.chunk
		// indicate that we need a readDatabaseStep
		cw.chunk = catchpointFileChunkV6{}
	}
}

func (cw *catchpointWriter) asyncWriter(chunks chan catchpointFileChunkV6, response chan error, chunkNum uint64) {
	defer close(response)
	for chk := range chunks {
		chunkNum++
		if chk.empty() {
			break
		}
		encodedChunk := protocol.Encode(&chk)
		err := cw.tar.WriteHeader(&tar.Header{
			Name: fmt.Sprintf(catchpointBalancesFileNameTemplate, chunkNum),
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
	}
}

// readDatabaseStep places the next chunk of records into cw.chunk. It yields
// all of the account chunks first, and then the kv chunks. Even if the accounts
// are evenly divisible by BalancesPerCatchpointFileChunk, it must not return an
// empty chunk between accounts and kvs.
func (cw *catchpointWriter) readDatabaseStep(ctx context.Context) error {
	if !cw.accountsDone {
		balances, numAccounts, err := cw.accountsIterator.Next(ctx, BalancesPerCatchpointFileChunk, cw.maxResourcesPerChunk)
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
		rows, err := cw.tx.MakeKVsIter(ctx)
		if err != nil {
			return err
		}
		cw.kvRows = rows
	}

	kvrs := make([]encoded.KVRecordV6, 0, BalancesPerCatchpointFileChunk)
	for cw.kvRows.Next() {
		k, v, err := cw.kvRows.KeyValue()
		if err != nil {
			return err
		}
		kvrs = append(kvrs, encoded.KVRecordV6{Key: k, Value: v})
		if len(kvrs) == BalancesPerCatchpointFileChunk {
			break
		}
	}
	cw.chunk = catchpointFileChunkV6{KVs: kvrs}
	return nil
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
