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
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/algorand/go-algorand/ledger/accountdb"
	"github.com/algorand/go-algorand/ledger/blockdb"
	"strings"
	"sync"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/metrics"
)

// CatchpointCatchupAccessor is an interface for the accessor wrapping the database storage for the catchpoint catchup functionality.
type CatchpointCatchupAccessor interface {
	// GetState returns the current state of the catchpoint catchup
	GetState(ctx context.Context) (state CatchpointCatchupState, err error)

	// SetState set the state of the catchpoint catchup
	SetState(ctx context.Context, state CatchpointCatchupState) (err error)

	// GetLabel returns the current catchpoint catchup label
	GetLabel(ctx context.Context) (label string, err error)

	// SetLabel set the catchpoint catchup label
	SetLabel(ctx context.Context, label string) (err error)

	// ResetStagingBalances resets the current staging balances, preparing for a new set of balances to be added
	ResetStagingBalances(ctx context.Context, newCatchup bool) (err error)

	// ProgressStagingBalances deserialize the given bytes as a temporary staging balances
	ProgressStagingBalances(ctx context.Context, sectionName string, bytes []byte, progress *CatchpointCatchupAccessorProgress) (err error)

	// BuildMerkleTrie inserts the account hashes into the merkle trie
	BuildMerkleTrie(ctx context.Context, progressUpdates func(uint64)) (err error)

	// GetCatchupBlockRound returns the latest block round matching the current catchpoint
	GetCatchupBlockRound(ctx context.Context) (round basics.Round, err error)

	// VerifyCatchpoint verifies that the catchpoint is valid by reconstructing the label.
	VerifyCatchpoint(ctx context.Context, blk *bookkeeping.Block) (err error)

	// StoreBalancesRound calculates the balances round based on the first block and the associated consensus parameters, and
	// store that to the database
	StoreBalancesRound(ctx context.Context, blk *bookkeeping.Block) (err error)

	// StoreFirstBlock stores a single block to the blocks database.
	StoreFirstBlock(ctx context.Context, blk *bookkeeping.Block) (err error)

	// StoreBlock stores a single block to the blocks database.
	StoreBlock(ctx context.Context, blk *bookkeeping.Block) (err error)

	// FinishBlocks concludes the catchup of the blocks database.
	FinishBlocks(ctx context.Context, applyChanges bool) (err error)

	// EnsureFirstBlock ensure that we have a single block in the staging block table, and returns that block
	EnsureFirstBlock(ctx context.Context) (blk bookkeeping.Block, err error)

	// CompleteCatchup completes the catchpoint catchup process by switching the databases tables around
	// and reloading the ledger.
	CompleteCatchup(ctx context.Context) (err error)
}

// CatchpointCatchupAccessorImpl is the concrete implementation of the CatchpointCatchupAccessor interface
type CatchpointCatchupAccessorImpl struct {
	ledger *Ledger

	// log copied from ledger
	log logging.Logger
}

// CatchpointCatchupState is the state of the current catchpoint catchup process
type CatchpointCatchupState int32

const (
	// CatchpointCatchupStateInactive is the common state for the catchpoint catchup - not active.
	CatchpointCatchupStateInactive = iota
	// CatchpointCatchupStateLedgerDownload indicates that we're downloading the ledger
	CatchpointCatchupStateLedgerDownload
	// CatchpointCatchupStateLastestBlockDownload indicates that we're download the latest block
	CatchpointCatchupStateLastestBlockDownload
	// CatchpointCatchupStateBlocksDownload indicates that we're downloading the blocks prior to the latest one ( total of CatchpointLookback blocks )
	CatchpointCatchupStateBlocksDownload
	// CatchpointCatchupStateSwitch indicates that we're switching to use the downloaded ledger/blocks content
	CatchpointCatchupStateSwitch

	// catchpointCatchupStateLast is the last entry in the CatchpointCatchupState enumeration.
	catchpointCatchupStateLast = CatchpointCatchupStateSwitch
)

// MakeCatchpointCatchupAccessor creates a CatchpointCatchupAccessor given a ledger
func MakeCatchpointCatchupAccessor(ledger *Ledger, log logging.Logger) CatchpointCatchupAccessor {
	return &CatchpointCatchupAccessorImpl{
		ledger: ledger,
		log:    log,
	}
}

// GetState returns the current state of the catchpoint catchup
func (c *CatchpointCatchupAccessorImpl) GetState(ctx context.Context) (state CatchpointCatchupState, err error) {
	var istate uint64
	istate, err = accountdb.ReadCatchpointStateUint64(ctx, c.ledger.TrackerDB().Rdb.Handle, accountdb.CatchpointStateCatchupState)
	if err != nil {
		return 0, fmt.Errorf("unable to read catchpoint catchup state '%s': %v", accountdb.CatchpointStateCatchupState, err)
	}
	state = CatchpointCatchupState(istate)
	return
}

// SetState set the state of the catchpoint catchup
func (c *CatchpointCatchupAccessorImpl) SetState(ctx context.Context, state CatchpointCatchupState) (err error) {
	if state < CatchpointCatchupStateInactive || state > catchpointCatchupStateLast {
		return fmt.Errorf("invalid catchpoint catchup state provided : %d", state)
	}
	err = accountdb.WriteCatchpointStateUint64(ctx, c.ledger.TrackerDB().Wdb.Handle, accountdb.CatchpointStateCatchupState, uint64(state))
	if err != nil {
		return fmt.Errorf("unable to write catchpoint catchup state '%s': %v", accountdb.CatchpointStateCatchupState, err)
	}
	return
}

// GetLabel returns the current catchpoint catchup label
func (c *CatchpointCatchupAccessorImpl) GetLabel(ctx context.Context) (label string, err error) {
	label, err = accountdb.ReadCatchpointStateString(ctx, c.ledger.TrackerDB().Rdb.Handle, accountdb.CatchpointStateCatchupLabel)
	if err != nil {
		return "", fmt.Errorf("unable to read catchpoint catchup state '%s': %v", accountdb.CatchpointStateCatchupLabel, err)
	}
	return
}

// SetLabel set the catchpoint catchup label
func (c *CatchpointCatchupAccessorImpl) SetLabel(ctx context.Context, label string) (err error) {
	// verify it's parsable :
	_, _, err = ledgercore.ParseCatchpointLabel(label)
	if err != nil {
		return
	}
	err = accountdb.WriteCatchpointStateString(ctx, c.ledger.TrackerDB().Wdb.Handle, accountdb.CatchpointStateCatchupLabel, label)
	if err != nil {
		return fmt.Errorf("unable to write catchpoint catchup state '%s': %v", accountdb.CatchpointStateCatchupLabel, err)
	}
	return
}

// ResetStagingBalances resets the current staging balances, preparing for a new set of balances to be added
func (c *CatchpointCatchupAccessorImpl) ResetStagingBalances(ctx context.Context, newCatchup bool) (err error) {
	wdb := c.ledger.TrackerDB().Wdb
	if !newCatchup {
		c.ledger.setSynchronousMode(ctx, c.ledger.synchronousMode)
	}
	start := time.Now()
	ledgerResetstagingbalancesCount.Inc(nil)
	err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		err = accountdb.ResetCatchpointStagingBalances(ctx, tx, newCatchup)
		if err != nil {
			return fmt.Errorf("unable to reset catchpoint catchup balances : %v", err)
		}
		if !newCatchup {
			err = accountdb.WriteCatchpointStateUint64(ctx, tx, accountdb.CatchpointStateCatchupBalancesRound, 0)
			if err != nil {
				return err
			}

			err = accountdb.WriteCatchpointStateUint64(ctx, tx, accountdb.CatchpointStateCatchupBlockRound, 0)
			if err != nil {
				return err
			}

			err = accountdb.WriteCatchpointStateString(ctx, tx, accountdb.CatchpointStateCatchupLabel, "")
			if err != nil {
				return err
			}
			err = accountdb.WriteCatchpointStateUint64(ctx, tx, accountdb.CatchpointStateCatchupState, 0)
			if err != nil {
				return fmt.Errorf("unable to write catchpoint catchup state '%s': %v", accountdb.CatchpointStateCatchupState, err)
			}
		}
		return
	})
	ledgerResetstagingbalancesMicros.AddMicrosecondsSince(start, nil)
	return
}

// CatchpointCatchupAccessorProgress is used by the caller of ProgressStagingBalances to obtain progress information
type CatchpointCatchupAccessorProgress struct {
	TotalAccounts      uint64
	ProcessedAccounts  uint64
	ProcessedBytes     uint64
	TotalChunks        uint64
	SeenHeader         bool
	Version            uint64
	TotalAccountHashes uint64

	// Having the cachedTrie here would help to accelerate the catchup process since the trie maintain an internal cache of nodes.
	// While rebuilding the trie, we don't want to force and reload (some) of these nodes into the cache for each catchpoint file chunk.
	cachedTrie *merkletrie.Trie

	BalancesWriteDuration   time.Duration
	CreatablesWriteDuration time.Duration
	HashesWriteDuration     time.Duration
}

// ProgressStagingBalances deserialize the given bytes as a temporary staging balances
func (c *CatchpointCatchupAccessorImpl) ProgressStagingBalances(ctx context.Context, sectionName string, bytes []byte, progress *CatchpointCatchupAccessorProgress) (err error) {
	if sectionName == "content.msgpack" {
		return c.processStagingContent(ctx, bytes, progress)
	}
	if strings.HasPrefix(sectionName, "balances.") && strings.HasSuffix(sectionName, ".msgpack") {
		return c.processStagingBalances(ctx, bytes, progress)
	}
	// we want to allow undefined sections to support backward compatibility.
	c.log.Warnf("CatchpointCatchupAccessorImpl::ProgressStagingBalances encountered unexpected section name '%s' of length %d, which would be ignored", sectionName, len(bytes))
	return nil
}

// processStagingContent deserialize the given bytes as a temporary staging balances content
func (c *CatchpointCatchupAccessorImpl) processStagingContent(ctx context.Context, bytes []byte, progress *CatchpointCatchupAccessorProgress) (err error) {
	if progress.SeenHeader {
		return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingContent: content chunk already seen")
	}
	var fileHeader CatchpointFileHeader
	err = protocol.Decode(bytes, &fileHeader)
	if err != nil {
		return err
	}
	switch fileHeader.Version {
	case CatchpointFileVersionV5:
	case CatchpointFileVersionV6:
	default:
		return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingContent: unable to process catchpoint - version %d is not supported", fileHeader.Version)
	}

	// the following fields are now going to be ignored. We could add these to the database and validate these
	// later on:
	// TotalAccounts, TotalAccounts, Catchpoint, BlockHeaderDigest, BalancesRound
	wdb := c.ledger.TrackerDB().Wdb
	start := time.Now()
	ledgerProcessstagingcontentCount.Inc(nil)
	err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		err = accountdb.WriteCatchpointStateUint64(ctx, tx, accountdb.CatchpointStateCatchupBlockRound, uint64(fileHeader.BlocksRound))
		if err != nil {
			return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingContent: unable to write catchpoint catchup state '%s': %v", accountdb.CatchpointStateCatchupBlockRound, err)
		}
		if fileHeader.Version == CatchpointFileVersionV6 {
			err = accountdb.WriteCatchpointStateUint64(ctx, tx, accountdb.CatchpointStateCatchupHashRound, uint64(fileHeader.BlocksRound))
			if err != nil {
				return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingContent: unable to write catchpoint catchup state '%s': %v", accountdb.CatchpointStateCatchupHashRound, err)
			}
		}
		err = accountdb.AccountsPutTotals(tx, fileHeader.Totals, true)
		return
	})
	ledgerProcessstagingcontentMicros.AddMicrosecondsSince(start, nil)
	if err == nil {
		progress.SeenHeader = true
		progress.TotalAccounts = fileHeader.TotalAccounts
		progress.TotalChunks = fileHeader.TotalChunks
		progress.Version = fileHeader.Version
		c.ledger.setSynchronousMode(ctx, c.ledger.accountsRebuildSynchronousMode)
	}
	return err
}

// processStagingBalances deserialize the given bytes as a temporary staging balances
func (c *CatchpointCatchupAccessorImpl) processStagingBalances(ctx context.Context, bytes []byte, progress *CatchpointCatchupAccessorProgress) (err error) {
	if !progress.SeenHeader {
		return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingBalances: content chunk was missing")
	}

	wdb := c.ledger.TrackerDB().Wdb
	start := time.Now()
	ledgerProcessstagingbalancesCount.Inc(nil)

	var normalizedAccountBalances []accountdb.NormalizedAccountBalance

	switch progress.Version {
	default:
		// unsupported version.
		// we won't get to this point, since we've already verified the version in processStagingContent
		return errors.New("unsupported version")
	case CatchpointFileVersionV5:
		var balances catchpointFileBalancesChunkV5
		err = protocol.Decode(bytes, &balances)
		if err != nil {
			return err
		}

		if len(balances.Balances) == 0 {
			return fmt.Errorf("processStagingBalances received a chunk with no accounts")
		}

		normalizedAccountBalances, err = accountdb.PrepareNormalizedBalancesV5(balances.Balances, c.ledger.GenesisProto())

	case CatchpointFileVersionV6:
		var balances catchpointFileBalancesChunkV6
		err = protocol.Decode(bytes, &balances)
		if err != nil {
			return err
		}

		if len(balances.Balances) == 0 {
			return fmt.Errorf("processStagingBalances received a chunk with no accounts")
		}

		normalizedAccountBalances, err = accountdb.PrepareNormalizedBalancesV6(balances.Balances, c.ledger.GenesisProto())
	}

	if err != nil {
		return fmt.Errorf("processStagingBalances failed to prepare normalized balances : %w", err)
	}

	wg := sync.WaitGroup{}

	var errBalances error
	var errCreatables error
	var errHashes error
	var durBalances time.Duration
	var durCreatables time.Duration
	var durHashes time.Duration

	// start the balances writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		errBalances = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			start := time.Now()
			err := accountdb.WriteCatchpointStagingBalances(ctx, tx, normalizedAccountBalances)
			durBalances = time.Since(start)
			return err
		})
	}()

	// on a in-memory database, wait for the writer to finish before starting the new writer
	if wdb.IsSharedCacheConnection() {
		wg.Wait()
	}

	// starts the creatables writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		hasCreatables := false
		for _, accBal := range normalizedAccountBalances {
			for _, res := range accBal.Resources {
				if res.IsOwning() {
					hasCreatables = true
					break
				}
			}
		}
		if hasCreatables {
			errCreatables = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
				start := time.Now()
				err := accountdb.WriteCatchpointStagingCreatable(ctx, tx, normalizedAccountBalances)
				durCreatables = time.Since(start)
				return err
			})
		}
	}()

	// on a in-memory database, wait for the writer to finish before starting the new writer
	if wdb.IsSharedCacheConnection() {
		wg.Wait()
	}

	// start the accounts pending hashes writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		errHashes = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			start := time.Now()
			err := accountdb.WriteCatchpointStagingHashes(ctx, tx, normalizedAccountBalances)
			durHashes = time.Since(start)
			return err
		})
	}()

	wg.Wait()

	if errBalances != nil {
		return errBalances
	}
	if errCreatables != nil {
		return errCreatables
	}
	if errHashes != nil {
		return errHashes
	}

	progress.BalancesWriteDuration += durBalances
	progress.CreatablesWriteDuration += durCreatables
	progress.HashesWriteDuration += durHashes

	ledgerProcessstagingbalancesMicros.AddMicrosecondsSince(start, nil)
	progress.ProcessedAccounts += uint64(len(normalizedAccountBalances))
	progress.ProcessedBytes += uint64(len(bytes))
	for _, acctBal := range normalizedAccountBalances {
		progress.TotalAccountHashes += uint64(len(acctBal.AccountHashes))
	}

	// not strictly required, but clean up the pointer when we're done.
	if progress.ProcessedAccounts == progress.TotalAccounts {
		progress.cachedTrie = nil
		// restore "normal" synchronous mode
		c.ledger.setSynchronousMode(ctx, c.ledger.synchronousMode)
	}
	return err
}

// BuildMerkleTrie would process the catchpointpendinghashes and insert all the items in it into the merkle trie
func (c *CatchpointCatchupAccessorImpl) BuildMerkleTrie(ctx context.Context, progressUpdates func(uint64)) (err error) {
	wdb := c.ledger.TrackerDB().Wdb
	rdb := c.ledger.TrackerDB().Rdb
	err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		// creating the Index can take a while, so ensure we don't generate false alerts for no good reason.
		db.ResetTransactionWarnDeadline(ctx, tx, time.Now().Add(120*time.Second))
		return accountdb.CreateCatchpointStagingHashesIndex(ctx, tx)
	})
	if err != nil {
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	errChan := make(chan error, 2)

	writerQueue := make(chan [][]byte, 16)
	c.ledger.setSynchronousMode(ctx, c.ledger.accountsRebuildSynchronousMode)
	defer c.ledger.setSynchronousMode(ctx, c.ledger.synchronousMode)

	// starts the hashes reader
	go func() {
		defer wg.Done()
		defer close(writerQueue)

		err := rdb.Atomic(func(transactionCtx context.Context, tx *sql.Tx) (err error) {
			it := accountdb.MakeCatchpointPendingHashesIterator(trieRebuildAccountChunkSize, tx)
			var hashes [][]byte
			for {
				hashes, err = it.Next(transactionCtx)
				if err != nil {
					break
				}
				if len(hashes) > 0 {
					writerQueue <- hashes
				}
				if len(hashes) != trieRebuildAccountChunkSize {
					break
				}
				if ctx.Err() != nil {
					it.Close()
					break
				}
			}
			// disable the warning for over-long atomic operation execution. It's meaningless here since it's
			// co-dependent on the other go-routine.
			db.ResetTransactionWarnDeadline(transactionCtx, tx, time.Now().Add(5*time.Second))
			return err
		})
		if err != nil {
			errChan <- err
		}
	}()

	// starts the merkle trie writer
	go func() {
		defer wg.Done()
		var trie *merkletrie.Trie
		uncommitedHashesCount := 0
		keepWriting := true
		hashesWritten := uint64(0)
		var mc *accountdb.MerkleCommitter
		if progressUpdates != nil {
			progressUpdates(hashesWritten)
		}

		err := wdb.Atomic(func(transactionCtx context.Context, tx *sql.Tx) (err error) {
			// create the merkle trie for the balances
			mc, err = accountdb.MakeMerkleCommitter(tx, true)
			if err != nil {
				return
			}

			trie, err = merkletrie.MakeTrie(mc, ledgercore.TrieMemoryConfig)
			return err
		})
		if err != nil {
			errChan <- err
			return
		}

		for keepWriting {
			var hashesToWrite [][]byte
			select {
			case hashesToWrite = <-writerQueue:
				if hashesToWrite == nil {
					// i.e. the writerQueue is closed.
					keepWriting = false
					continue
				}
			case <-ctx.Done():
				keepWriting = false
				continue
			}

			err = rdb.Atomic(func(transactionCtx context.Context, tx *sql.Tx) (err error) {
				mc, err = accountdb.MakeMerkleCommitter(tx, true)
				if err != nil {
					return
				}
				trie.SetCommitter(mc)
				for _, accountHash := range hashesToWrite {
					var added bool
					added, err = trie.Add(accountHash)
					if !added {
						return fmt.Errorf("CatchpointCatchupAccessorImpl::BuildMerkleTrie: The provided catchpoint file contained the same account more than once. hash '%s'", hex.EncodeToString(accountHash))
					}
					if err != nil {
						return
					}
				}
				uncommitedHashesCount += len(hashesToWrite)
				hashesWritten += uint64(len(hashesToWrite))
				return nil
			})
			if err != nil {
				break
			}

			if uncommitedHashesCount >= trieRebuildCommitFrequency {
				err = wdb.Atomic(func(transactionCtx context.Context, tx *sql.Tx) (err error) {
					// set a long 30-second window for the evict before warning is generated.
					db.ResetTransactionWarnDeadline(transactionCtx, tx, time.Now().Add(30*time.Second))
					mc, err = accountdb.MakeMerkleCommitter(tx, true)
					if err != nil {
						return
					}
					trie.SetCommitter(mc)
					_, err = trie.Evict(true)
					if err != nil {
						return
					}
					uncommitedHashesCount = 0
					return nil
				})
				if err != nil {
					keepWriting = false
					continue
				}
			}
			if progressUpdates != nil {
				progressUpdates(hashesWritten)
			}
		}
		if err != nil {
			errChan <- err
			return
		}
		if uncommitedHashesCount > 0 {
			err = wdb.Atomic(func(transactionCtx context.Context, tx *sql.Tx) (err error) {
				// set a long 30-second window for the evict before warning is generated.
				db.ResetTransactionWarnDeadline(transactionCtx, tx, time.Now().Add(30*time.Second))
				mc, err = accountdb.MakeMerkleCommitter(tx, true)
				if err != nil {
					return
				}
				trie.SetCommitter(mc)
				_, err = trie.Evict(true)
				return
			})
		}

		if err != nil {
			errChan <- err
		}
	}()

	wg.Wait()

	select {
	case err := <-errChan:
		return err
	default:
	}

	return err
}

// GetCatchupBlockRound returns the latest block round matching the current catchpoint
func (c *CatchpointCatchupAccessorImpl) GetCatchupBlockRound(ctx context.Context) (round basics.Round, err error) {
	var iRound uint64
	iRound, err = accountdb.ReadCatchpointStateUint64(ctx, c.ledger.TrackerDB().Rdb.Handle, accountdb.CatchpointStateCatchupBlockRound)
	if err != nil {
		return 0, fmt.Errorf("unable to read catchpoint catchup state '%s': %v", accountdb.CatchpointStateCatchupBlockRound, err)
	}
	return basics.Round(iRound), nil
}

// VerifyCatchpoint verifies that the catchpoint is valid by reconstructing the label.
func (c *CatchpointCatchupAccessorImpl) VerifyCatchpoint(ctx context.Context, blk *bookkeeping.Block) (err error) {
	rdb := c.ledger.TrackerDB().Rdb
	var balancesHash crypto.Digest
	var blockRound basics.Round
	var totals ledgercore.AccountTotals
	var catchpointLabel string

	catchpointLabel, err = accountdb.ReadCatchpointStateString(ctx, rdb.Handle, accountdb.CatchpointStateCatchupLabel)
	if err != nil {
		return fmt.Errorf("unable to read catchpoint catchup state '%s': %v", accountdb.CatchpointStateCatchupLabel, err)
	}

	var iRound uint64
	iRound, err = accountdb.ReadCatchpointStateUint64(ctx, rdb.Handle, accountdb.CatchpointStateCatchupBlockRound)
	if err != nil {
		return fmt.Errorf("unable to read catchpoint catchup state '%s': %v", accountdb.CatchpointStateCatchupBlockRound, err)
	}
	blockRound = basics.Round(iRound)

	start := time.Now()
	ledgerVerifycatchpointCount.Inc(nil)
	err = rdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		// create the merkle trie for the balances
		mc, err0 := accountdb.MakeMerkleCommitter(tx, true)
		if err0 != nil {
			return fmt.Errorf("unable to make MerkleCommitter: %v", err0)
		}
		var trie *merkletrie.Trie
		trie, err = merkletrie.MakeTrie(mc, ledgercore.TrieMemoryConfig)
		if err != nil {
			return fmt.Errorf("unable to make trie: %v", err)
		}

		balancesHash, err = trie.RootHash()
		if err != nil {
			return fmt.Errorf("unable to get trie root hash: %v", err)
		}

		totals, err = accountdb.AccountsTotals(ctx, tx, true)
		if err != nil {
			return fmt.Errorf("unable to get accounts totals: %v", err)
		}
		return
	})
	ledgerVerifycatchpointMicros.AddMicrosecondsSince(start, nil)
	if err != nil {
		return err
	}
	if blockRound != blk.Round() {
		return fmt.Errorf("block round in block header doesn't match block round in catchpoint")
	}

	catchpointLabelMaker := ledgercore.MakeCatchpointLabel(blockRound, blk.Digest(), balancesHash, totals)

	if catchpointLabel != catchpointLabelMaker.String() {
		return fmt.Errorf("catchpoint hash mismatch; expected %s, calculated %s", catchpointLabel, catchpointLabelMaker.String())
	}
	return nil
}

// StoreBalancesRound calculates the balances round based on the first block and the associated consensus parameters, and
// store that to the database
func (c *CatchpointCatchupAccessorImpl) StoreBalancesRound(ctx context.Context, blk *bookkeeping.Block) (err error) {
	// calculate the balances round and store it. It *should* be identical to the one in the catchpoint file header, but we don't want to
	// trust the one in the catchpoint file header, so we'll calculate it ourselves.
	catchpointLookback := config.Consensus[blk.CurrentProtocol].CatchpointLookback
	if catchpointLookback == 0 {
		catchpointLookback = config.Consensus[blk.CurrentProtocol].MaxBalLookback
	}
	balancesRound := blk.Round() - basics.Round(catchpointLookback)
	wdb := c.ledger.TrackerDB().Wdb
	start := time.Now()
	ledgerStorebalancesroundCount.Inc(nil)
	err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		err = accountdb.WriteCatchpointStateUint64(ctx, tx, accountdb.CatchpointStateCatchupBalancesRound, uint64(balancesRound))
		if err != nil {
			return fmt.Errorf("CatchpointCatchupAccessorImpl::StoreBalancesRound: unable to write catchpoint catchup state '%s': %v", accountdb.CatchpointStateCatchupBalancesRound, err)
		}
		return
	})
	ledgerStorebalancesroundMicros.AddMicrosecondsSince(start, nil)
	return
}

// StoreFirstBlock stores a single block to the blocks database.
func (c *CatchpointCatchupAccessorImpl) StoreFirstBlock(ctx context.Context, blk *bookkeeping.Block) (err error) {
	blockDbs := c.ledger.BlockDB()
	start := time.Now()
	ledgerStorefirstblockCount.Inc(nil)
	err = blockDbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		return blockdb.BlockStartCatchupStaging(tx, *blk)
	})
	ledgerStorefirstblockMicros.AddMicrosecondsSince(start, nil)
	if err != nil {
		return err
	}
	return nil
}

// StoreBlock stores a single block to the blocks database.
func (c *CatchpointCatchupAccessorImpl) StoreBlock(ctx context.Context, blk *bookkeeping.Block) (err error) {
	blockDbs := c.ledger.BlockDB()
	start := time.Now()
	ledgerCatchpointStoreblockCount.Inc(nil)
	err = blockDbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		return blockdb.BlockPutStaging(tx, *blk)
	})
	ledgerCatchpointStoreblockMicros.AddMicrosecondsSince(start, nil)
	if err != nil {
		return err
	}
	return nil
}

// FinishBlocks concludes the catchup of the blocks database.
func (c *CatchpointCatchupAccessorImpl) FinishBlocks(ctx context.Context, applyChanges bool) (err error) {
	blockDbs := c.ledger.BlockDB()
	start := time.Now()
	ledgerCatchpointFinishblocksCount.Inc(nil)
	err = blockDbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		if applyChanges {
			return blockdb.BlockCompleteCatchup(tx)
		}
		// TODO: unused, either actually implement cleanup on catchpoint failure, or delete this
		return blockdb.BlockAbortCatchup(tx)
	})
	ledgerCatchpointFinishblocksMicros.AddMicrosecondsSince(start, nil)
	if err != nil {
		return err
	}
	return nil
}

// EnsureFirstBlock ensure that we have a single block in the staging block table, and returns that block
func (c *CatchpointCatchupAccessorImpl) EnsureFirstBlock(ctx context.Context) (blk bookkeeping.Block, err error) {
	blockDbs := c.ledger.BlockDB()
	start := time.Now()
	ledgerCatchpointEnsureblock1Count.Inc(nil)
	err = blockDbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		blk, err = blockdb.BlockEnsureSingleBlock(tx)
		return
	})
	ledgerCatchpointEnsureblock1Micros.AddMicrosecondsSince(start, nil)
	if err != nil {
		return blk, err
	}
	return blk, nil
}

// CompleteCatchup completes the catchpoint catchup process by switching the databases tables around
// and reloading the ledger.
func (c *CatchpointCatchupAccessorImpl) CompleteCatchup(ctx context.Context) (err error) {
	err = c.FinishBlocks(ctx, true)
	if err != nil {
		return err
	}
	err = c.finishBalances(ctx)
	if err != nil {
		return err
	}

	return c.ledger.reloadLedger()
}

// finishBalances concludes the catchup of the balances(tracker) database.
func (c *CatchpointCatchupAccessorImpl) finishBalances(ctx context.Context) (err error) {
	wdb := c.ledger.TrackerDB().Wdb
	start := time.Now()
	ledgerCatchpointFinishBalsCount.Inc(nil)
	err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		var balancesRound, hashRound uint64
		var totals ledgercore.AccountTotals

		balancesRound, err = accountdb.ReadCatchpointStateUint64(ctx, tx, accountdb.CatchpointStateCatchupBalancesRound)
		if err != nil {
			return err
		}

		hashRound, err = accountdb.ReadCatchpointStateUint64(ctx, tx, accountdb.CatchpointStateCatchupHashRound)
		if err != nil {
			return err
		}

		totals, err = accountdb.AccountsTotals(ctx, tx, true)
		if err != nil {
			return err
		}

		if hashRound == 0 {
			err = accountdb.ResetAccountHashes(ctx, tx)
			if err != nil {
				return err
			}
		}

		// Reset the database to version 6. For now, we create a version 6 database from
		// the catchpoint and let `reloadLedger()` run the normal database migration.
		// When implementing a new catchpoint format (e.g. adding a new table),
		// it might be necessary to restore it into the latest database version. To do that, one
		// will need to run the 6->7 migration code manually here or in a similar function to create
		// onlineaccounts and other V7 tables.
		err = accountdb.AccountsReset(ctx, tx)
		if err != nil {
			return err
		}
		{
			tp := accountdb.TrackerDBParams{
				InitAccounts:      c.ledger.GenesisAccounts(),
				InitProto:         c.ledger.GenesisProtoVersion(),
				CatchpointEnabled: c.ledger.catchpoint.catchpointEnabled(),
				DBPathPrefix:      c.ledger.catchpoint.dbDirectory,
				BlockDb:           c.ledger.blockDBs,
			}
			_, err = accountdb.RunMigrations(ctx, tx, tp, c.ledger.log, 6 /*target database version*/)
			if err != nil {
				return err
			}
		}

		err = accountdb.ApplyCatchpointStagingBalances(ctx, tx, basics.Round(balancesRound), basics.Round(hashRound))
		if err != nil {
			return err
		}

		err = accountdb.AccountsPutTotals(tx, totals, false)
		if err != nil {
			return err
		}

		err = accountdb.ResetCatchpointStagingBalances(ctx, tx, false)
		if err != nil {
			return err
		}

		err = accountdb.WriteCatchpointStateUint64(ctx, tx, accountdb.CatchpointStateCatchupBalancesRound, 0)
		if err != nil {
			return err
		}

		err = accountdb.WriteCatchpointStateUint64(ctx, tx, accountdb.CatchpointStateCatchupBlockRound, 0)
		if err != nil {
			return err
		}

		err = accountdb.WriteCatchpointStateString(ctx, tx, accountdb.CatchpointStateCatchupLabel, "")
		if err != nil {
			return err
		}

		if hashRound != 0 {
			err = accountdb.WriteCatchpointStateUint64(ctx, tx, accountdb.CatchpointStateCatchupHashRound, 0)
			if err != nil {
				return err
			}
		}

		err = accountdb.WriteCatchpointStateUint64(ctx, tx, accountdb.CatchpointStateCatchupState, 0)
		if err != nil {
			return fmt.Errorf("unable to write catchpoint catchup state '%s': %v", accountdb.CatchpointStateCatchupState, err)
		}

		return
	})
	ledgerCatchpointFinishBalsMicros.AddMicrosecondsSince(start, nil)
	return err
}

var ledgerResetstagingbalancesCount = metrics.NewCounter("ledger_catchup_resetstagingbalances_count", "calls")
var ledgerResetstagingbalancesMicros = metrics.NewCounter("ledger_catchup_resetstagingbalances_micros", "µs spent")
var ledgerProcessstagingcontentCount = metrics.NewCounter("ledger_catchup_processstagingcontent_count", "calls")
var ledgerProcessstagingcontentMicros = metrics.NewCounter("ledger_catchup_processstagingcontent_micros", "µs spent")
var ledgerProcessstagingbalancesCount = metrics.NewCounter("ledger_catchup_processstagingbalances_count", "calls")
var ledgerProcessstagingbalancesMicros = metrics.NewCounter("ledger_catchup_processstagingbalances_micros", "µs spent")
var ledgerVerifycatchpointCount = metrics.NewCounter("ledger_catchup_verifycatchpoint_count", "calls")
var ledgerVerifycatchpointMicros = metrics.NewCounter("ledger_catchup_verifycatchpoint_micros", "µs spent")
var ledgerStorebalancesroundCount = metrics.NewCounter("ledger_catchup_storebalancesround_count", "calls")
var ledgerStorebalancesroundMicros = metrics.NewCounter("ledger_catchup_storebalancesround_micros", "µs spent")
var ledgerStorefirstblockCount = metrics.NewCounter("ledger_catchup_storefirstblock_count", "calls")
var ledgerStorefirstblockMicros = metrics.NewCounter("ledger_catchup_storefirstblock_micros", "µs spent")
var ledgerCatchpointStoreblockCount = metrics.NewCounter("ledger_catchup_catchpoint_storeblock_count", "calls")
var ledgerCatchpointStoreblockMicros = metrics.NewCounter("ledger_catchup_catchpoint_storeblock_micros", "µs spent")
var ledgerCatchpointFinishblocksCount = metrics.NewCounter("ledger_catchup_catchpoint_finishblocks_count", "calls")
var ledgerCatchpointFinishblocksMicros = metrics.NewCounter("ledger_catchup_catchpoint_finishblocks_micros", "µs spent")
var ledgerCatchpointEnsureblock1Count = metrics.NewCounter("ledger_catchup_catchpoint_ensureblock1_count", "calls")
var ledgerCatchpointEnsureblock1Micros = metrics.NewCounter("ledger_catchup_catchpoint_ensureblock1_micros", "µs spent")
var ledgerCatchpointFinishBalsCount = metrics.NewCounter("ledger_catchup_catchpoint_finish_bals_count", "calls")
var ledgerCatchpointFinishBalsMicros = metrics.NewCounter("ledger_catchup_catchpoint_finish_bals_micros", "µs spent")
