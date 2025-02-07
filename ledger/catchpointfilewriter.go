// Copyright (C) 2019-2025 Algorand, Inc.
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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
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

// catchpointFileWriter is the struct managing the persistence of accounts data into the catchpoint file.
// it's designed to work in a step fashion : a caller will call the FileWriteStep method in a loop until
// the writing is complete. It might take multiple steps until the operation is over, and the caller
// has the option of throttling the CPU utilization in between the calls.
type catchpointFileWriter struct {
	ctx                    context.Context
	tx                     trackerdb.SnapshotScope
	params                 config.ConsensusParams
	filePath               string
	totalAccounts          uint64
	totalKVs               uint64
	totalOnlineAccounts    uint64
	totalOnlineRoundParams uint64
	file                   *os.File
	tar                    *tar.Writer
	compressor             io.WriteCloser
	chunk                  CatchpointSnapshotChunkV6
	chunkNum               uint64
	writtenBytes           int64
	biggestChunkLen        uint64
	accountsIterator       trackerdb.EncodedAccountsBatchIter
	maxResourcesPerChunk   int
	accountsRound          basics.Round
	onlineExcludeBefore    basics.Round
	accountsDone           bool
	kvRows                 trackerdb.KVsIter
	kvDone                 bool
	onlineAccountRows      trackerdb.TableIterator[*encoded.OnlineAccountRecordV6]
	onlineAccountsDone     bool
	onlineAccountPrev      *basics.Address
	onlineAccountPrevRound *basics.Round
	onlineRoundParamsRows  trackerdb.TableIterator[*encoded.OnlineRoundParamsRecordV6]
	onlineRoundParamsDone  bool
}

// CatchpointSnapshotChunkV5 defines the encoding of "balances.X.msgpack" files in the catchpoint snapshot
// used before database schema v6, which split accounts from asset/app resource data.
type CatchpointSnapshotChunkV5 struct {
	_struct  struct{}                  `codec:",omitempty,omitemptyarray"`
	Balances []encoded.BalanceRecordV5 `codec:"bl,allocbound=BalancesPerCatchpointFileChunk"`
}

// CatchpointSnapshotChunkV6 defines the current encoding of "balances.X.msgpack" files in the catchpoint snapshot.
type CatchpointSnapshotChunkV6 struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Balances          []encoded.BalanceRecordV6 `codec:"bl,allocbound=BalancesPerCatchpointFileChunk"`
	numAccounts       uint64
	KVs               []encoded.KVRecordV6                `codec:"kv,allocbound=BalancesPerCatchpointFileChunk"`
	OnlineAccounts    []encoded.OnlineAccountRecordV6     `codec:"oa,allocbound=BalancesPerCatchpointFileChunk"`
	OnlineRoundParams []encoded.OnlineRoundParamsRecordV6 `codec:"orp,allocbound=BalancesPerCatchpointFileChunk"`
}

func (chunk CatchpointSnapshotChunkV6) empty() bool {
	return len(chunk.Balances) == 0 && len(chunk.KVs) == 0 && len(chunk.OnlineAccounts) == 0 && len(chunk.OnlineRoundParams) == 0
}

type catchpointStateProofVerificationContext struct {
	_struct struct{}                                   `codec:",omitempty,omitemptyarray"`
	Data    []ledgercore.StateProofVerificationContext `codec:"spd,allocbound=SPContextPerCatchpointFile"`
}

func (data catchpointStateProofVerificationContext) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.StateProofVerCtx, protocol.Encode(&data)
}

func makeCatchpointFileWriter(ctx context.Context, params config.ConsensusParams, filePath string, tx trackerdb.SnapshotScope, maxResourcesPerChunk int, accountsRound, onlineExcludeBefore basics.Round) (*catchpointFileWriter, error) {
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

	var totalOnlineAccounts, totalOnlineRoundParams uint64
	if params.EnableCatchpointsWithOnlineAccounts {
		totalOnlineAccounts, err = aw.TotalOnlineAccountRows(ctx)
		if err != nil {
			return nil, err
		}

		totalOnlineRoundParams, err = aw.TotalOnlineRoundParams(ctx)
		if err != nil {
			return nil, err
		}
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

	res := &catchpointFileWriter{
		ctx:                    ctx,
		tx:                     tx,
		params:                 params,
		filePath:               filePath,
		totalAccounts:          totalAccounts,
		totalKVs:               totalKVs,
		totalOnlineAccounts:    totalOnlineAccounts,
		totalOnlineRoundParams: totalOnlineRoundParams,
		file:                   file,
		compressor:             compressor,
		tar:                    tar,
		accountsIterator:       tx.MakeEncodedAccountsBatchIter(),
		accountsRound:          accountsRound,
		maxResourcesPerChunk:   maxResourcesPerChunk,
		onlineExcludeBefore:    onlineExcludeBefore,
	}
	return res, nil
}

func (cw *catchpointFileWriter) Abort() error {
	cw.accountsIterator.Close()
	cw.tar.Close()
	cw.compressor.Close()
	cw.file.Close()
	return os.Remove(cw.filePath)
}

func (cw *catchpointFileWriter) FileWriteSPVerificationContext(encodedData []byte) error {
	err := cw.tar.WriteHeader(&tar.Header{
		Name: catchpointSPVerificationFileName,
		Mode: 0600,
		Size: int64(len(encodedData)),
	})

	if err != nil {
		return err
	}

	_, err = cw.tar.Write(encodedData)
	if err != nil {
		return err
	}

	if chunkLen := uint64(len(encodedData)); cw.biggestChunkLen < chunkLen {
		cw.biggestChunkLen = chunkLen
	}

	return nil
}

// FileWriteStep works for a short period of time (determined by stepCtx) to get
// some more data (accounts/resources/kvpairs) by using readDatabaseStep, and
// write that data to the open tar file in cw.tar.  The writing is done in
// asyncWriter, so that it can proceed concurrently with reading the data from
// the db. asyncWriter only runs long enough to process the data read during a
// single call to FileWriteStep, and FileWriteStep ensures that asyncWriter has finished
// writing by waiting for it in a defer block, collecting any errors that may
// have occurred during writing.  Therefore, FileWriteStep looks like a simple
// synchronous function to its callers.
func (cw *catchpointFileWriter) FileWriteStep(stepCtx context.Context) (more bool, err error) {
	// have we timed-out / canceled by that point ?
	if more, err = hasContextDeadlineExceeded(stepCtx); more || err != nil {
		return
	}

	writerRequest := make(chan CatchpointSnapshotChunkV6, 1)
	writerResponse := make(chan error, 2)
	go cw.asyncWriter(writerRequest, writerResponse, cw.chunkNum)
	defer func() {
		// For simplicity, all cleanup is done once, here. The writerRequest is
		// closed, signaling asyncWriter that it can exit, and then
		// writerResponse is drained, ensuring any problems from asyncWriter are
		// noted (and that the writing is done).
		close(writerRequest)

		// drain the writerResponse queue
		for {
			writerError, open := <-writerResponse
			if open {
				err = writerError
			} else {
				break
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

			// These don't HAVE to be closed, since the "owning" tx will be committed/rolledback
			cw.accountsIterator.Close()
			if cw.kvRows != nil {
				cw.kvRows.Close()
				cw.kvRows = nil
			}
			if cw.onlineAccountRows != nil {
				cw.onlineAccountRows.Close()
				cw.onlineAccountRows = nil
			}
			if cw.onlineRoundParamsRows != nil {
				cw.onlineRoundParamsRows.Close()
				cw.onlineRoundParamsRows = nil
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
		cw.chunk = CatchpointSnapshotChunkV6{}
	}
}

func (cw *catchpointFileWriter) asyncWriter(chunks chan CatchpointSnapshotChunkV6, response chan error, chunkNum uint64) {
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
func (cw *catchpointFileWriter) readDatabaseStep(ctx context.Context) error {
	if !cw.accountsDone {
		balances, numAccounts, err := cw.accountsIterator.Next(ctx, BalancesPerCatchpointFileChunk, cw.maxResourcesPerChunk)
		if err != nil {
			return err
		}
		if len(balances) > 0 {
			cw.chunk = CatchpointSnapshotChunkV6{Balances: balances, numAccounts: numAccounts}
			return nil
		}
		// It might seem reasonable, but do not close accountsIterator here,
		// else it will start over on the next iteration
		// cw.accountsIterator.Close()
		cw.accountsDone = true
	}

	// Create the kvRows iterator JIT
	if !cw.kvDone {
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
		if len(kvrs) > 0 {
			cw.chunk = CatchpointSnapshotChunkV6{KVs: kvrs}
			return nil
		}
		// Do not close kvRows here, or it will start over on the next iteration
		cw.kvDone = true
	}

	if cw.params.EnableCatchpointsWithOnlineAccounts && !cw.onlineAccountsDone {
		// Create the OnlineAccounts iterator JIT
		if cw.onlineAccountRows == nil {
			// MakeOrderedOnlineAccountsIter orders by (address, updateRound).
			rows, err := cw.tx.MakeOrderedOnlineAccountsIter(ctx, false, cw.onlineExcludeBefore)
			if err != nil {
				return err
			}
			cw.onlineAccountRows = rows
		}

		onlineAccts := make([]encoded.OnlineAccountRecordV6, 0, BalancesPerCatchpointFileChunk)
		for cw.onlineAccountRows.Next() {
			oa, err := cw.onlineAccountRows.GetItem()
			if err != nil {
				return err
			}
			// We set UpdateRound to 0 here, so that all nodes generating catchpoints will have the
			// verification hash for the onlineaccounts table data (which is used to calculate the
			// catchpoint label). Depending on the history of an online account, nodes may not have
			// the same updateRound column value for the oldest "horizon" row for that address,
			// depending on whether the node caught up from genesis, or restored from a
			// catchpoint. This does not have any impact on the correctness of online account
			// lookups, but is due to changes in the database schema over time:
			//
			//   1. For nodes that have been online for a long time, the unlimited assets release
			//   (v3.5.1, PR #3652) introduced a BaseAccountData type with an UpdateRound field,
			//   consensus-flagged to be zero until EnableAccountDataResourceSeparation was enabled
			//   in consensus v32. So accounts that have been inactive since before consensus v32
			//   will continue to have a zero UpdateRound, until a transaction updates the
			//   account. This behavior is consistent for all nodes and validated by the merkle trie
			//   generated each catchpoint round.
			//
			//   2. The onlineaccounts table, introduced later in v3.9.2 (PR #4003), uses a
			//   migration to populate the onlineaccounts table by selecting all online accounts
			//   from the accounts table. This migration copies the BaseAccountData.UpdateRound
			//   field, along with voting data, to set the initial values of the onlineaccounts
			//   table for each address. After that, the onlineaccounts table's updateRound column
			//   would only be updated if voting data changed -- so certain transactions like
			//   receiving a pay txn of 0 algos, or receiving an asset transfer, etc, would not
			//   result in a new onlineaccounts row with a new updateRound (unless it triggered a
			//   balance or voting data change). This criteria is implemented in
			//   onlineAccountsNewRound in acctdeltas.go, separate from accountsNewRound &
			//   makeCompactAccountDeltas, which set the account table's UpdateRound value.
			//
			//   3. Node operators using fast catchup to restore from a catchpoint file version V6
			//   or V7 (used before v4.0.1 and consensus v40, which added the
			//   EnableCatchpointsWithOnlineAccounts flag) initialize the onlineaccounts table by
			//   first restoring the accounts table from the snapshot, then running the same
			//   migration introduced in (2), where updateRound (and account data) comes from
			//   BaseAccountData. This means catchpoint file writers and fast catchup users could
			//   see some addresses have a horizon row with an updateRound that was set to zero
			//   (case 1), or the round of the last account data change (case 2). Since v4.0.1,
			//   catchpoint file version V8 includes the onlineaccounts and onlineroundparams tables
			//   in snapshots, to support the voter_params_get and online_stake opcodes (PR #6177).
			//
			//   4. However, a node catching up from scratch without using fast catchup, running
			//   v3.9.2 or later, must track the online account history to verify block certificates
			//   as it validates each block in turn.  It sets updateRound based on observing all
			//   account voting data changes starting from round 0, whether or not
			//   EnableAccountDataResourceSeparation is set. These nodes will have horizon rows for
			//   addresses with updateRound set to the round of the last actual voting data change,
			//   not zero (case 1) or the round of the last account data change (case 2).
			//

			// Is the updateRound for this row beyond the lookback horizon (R-320)?
			if oa.UpdateRound < catchpointLookbackHorizonForNextRound(cw.accountsRound, cw.params) {
				// Is this the first (and thus oldest) row for this address?
				if cw.onlineAccountPrev == nil || *cw.onlineAccountPrev != oa.Address {
					// Then set it to 0.
					oa.UpdateRound = 0
				} else {
					// This case should never happen: there should only be one horizon row per account.
					var prevUpdRound basics.Round
					if cw.onlineAccountPrevRound != nil {
						prevUpdRound = *cw.onlineAccountPrevRound
					}
					return fmt.Errorf("bad online account data: multiple horizon rows for %s, prev updround %d cur updround %d", oa.Address, prevUpdRound, oa.UpdateRound)
				}
			}

			cw.onlineAccountPrev = &oa.Address
			cw.onlineAccountPrevRound = &oa.UpdateRound
			onlineAccts = append(onlineAccts, *oa)
			if len(onlineAccts) == BalancesPerCatchpointFileChunk {
				break
			}
		}
		if len(onlineAccts) > 0 {
			cw.chunk = CatchpointSnapshotChunkV6{OnlineAccounts: onlineAccts}
			return nil
		}
		// Do not close onlineAccountRows here, or it will start over on the next iteration
		cw.onlineAccountsDone = true
	}

	if cw.params.EnableCatchpointsWithOnlineAccounts && !cw.onlineRoundParamsDone {
		// Create the OnlineRoundParams iterator JIT
		if cw.onlineRoundParamsRows == nil {
			rows, err := cw.tx.MakeOnlineRoundParamsIter(ctx, false, cw.onlineExcludeBefore)
			if err != nil {
				return err
			}
			cw.onlineRoundParamsRows = rows
		}

		onlineRndParams := make([]encoded.OnlineRoundParamsRecordV6, 0, BalancesPerCatchpointFileChunk)
		for cw.onlineRoundParamsRows.Next() {
			or, err := cw.onlineRoundParamsRows.GetItem()
			if err != nil {
				return err
			}
			onlineRndParams = append(onlineRndParams, *or)
			if len(onlineRndParams) == BalancesPerCatchpointFileChunk {
				break
			}
		}
		if len(onlineRndParams) > 0 {
			cw.chunk = CatchpointSnapshotChunkV6{OnlineRoundParams: onlineRndParams}
			return nil
		}
		// Do not close onlineRndParamsRows here, or it will start over on the next iteration
		cw.onlineRoundParamsDone = true
	}

	// Finished the last chunk
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

// catchpointLookbackHorizonForNextRound returns the lookback horizon used to evaluate the next
// round after the provided `rnd`, according to consensus settings in `params`. That is, to evaluate
// blocks starting from rnd+1, this function returns the oldest round that will be needed to evaluate
// votes, certificates or other consensus data. Anything older than the returned round is beyond
// the horizon and needed to evaluate blocks starting from rnd+1.
func catchpointLookbackHorizonForNextRound(rnd basics.Round, params config.ConsensusParams) basics.Round {
	return (rnd + 1).SubSaturate(basics.Round(params.MaxBalLookback))
}
