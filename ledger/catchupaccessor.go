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
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
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

	// GetCatchupBlockRound returns the latest block round matching the current catchpoint
	GetCatchupBlockRound(ctx context.Context) (round basics.Round, err error)

	// VerifyCatchpoint verifies that the catchpoint is valid by reconstructing the label.
	VerifyCatchpoint(ctx context.Context, blk *bookkeeping.Block) (err error)

	// StoreBalancesRound calculates the balances round based on the first block and the associated consensus parametets, and
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

	// Prepared SQL statements for fast accounts DB lookups.
	accountsq *accountsDbQueries
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
	// CatchpointCatchupStateBlocksDownload indicates that we're downloading the blocks prior to the latest one ( total of MaxBalLookback blocks )
	CatchpointCatchupStateBlocksDownload
	// CatchpointCatchupStateSwitch indicates that we're switching to use the downloaded ledger/blocks content
	CatchpointCatchupStateSwitch

	// catchpointCatchupStateLast is the last entry in the CatchpointCatchupState enumeration.
	catchpointCatchupStateLast = CatchpointCatchupStateSwitch
)

// MakeCatchpointCatchupAccessor creates a CatchpointCatchupAccessor given a ledger
func MakeCatchpointCatchupAccessor(ledger *Ledger, log logging.Logger) CatchpointCatchupAccessor {
	rdb := ledger.trackerDB().rdb
	wdb := ledger.trackerDB().wdb
	accountsq, err := accountsDbInit(rdb.Handle, wdb.Handle)
	if err != nil {
		log.Warnf("unable to initialize account db in MakeCatchpointCatchupAccessor : %v", err)
		return nil
	}
	return &CatchpointCatchupAccessorImpl{
		ledger:    ledger,
		log:       log,
		accountsq: accountsq,
	}
}

// GetState returns the current state of the catchpoint catchup
func (c *CatchpointCatchupAccessorImpl) GetState(ctx context.Context) (state CatchpointCatchupState, err error) {
	var istate uint64
	istate, _, err = c.accountsq.readCatchpointStateUint64(ctx, catchpointStateCatchupState)
	if err != nil {
		return 0, fmt.Errorf("unable to read catchpoint catchup state '%s': %v", catchpointStateCatchupState, err)
	}
	state = CatchpointCatchupState(istate)
	return
}

// SetState set the state of the catchpoint catchup
func (c *CatchpointCatchupAccessorImpl) SetState(ctx context.Context, state CatchpointCatchupState) (err error) {
	if state < CatchpointCatchupStateInactive || state > catchpointCatchupStateLast {
		return fmt.Errorf("invalid catchpoint catchup state provided : %d", state)
	}
	_, err = c.accountsq.writeCatchpointStateUint64(ctx, catchpointStateCatchupState, uint64(state))
	if err != nil {
		return fmt.Errorf("unable to write catchpoint catchup state '%s': %v", catchpointStateCatchupState, err)
	}
	return
}

// GetLabel returns the current catchpoint catchup label
func (c *CatchpointCatchupAccessorImpl) GetLabel(ctx context.Context) (label string, err error) {
	label, _, err = c.accountsq.readCatchpointStateString(ctx, catchpointStateCatchupLabel)
	if err != nil {
		return "", fmt.Errorf("unable to read catchpoint catchup state '%s': %v", catchpointStateCatchupLabel, err)
	}
	return
}

// SetLabel set the catchpoint catchup label
func (c *CatchpointCatchupAccessorImpl) SetLabel(ctx context.Context, label string) (err error) {
	// verify it's parsable :
	_, _, err = ParseCatchpointLabel(label)
	if err != nil {
		return
	}
	_, err = c.accountsq.writeCatchpointStateString(ctx, catchpointStateCatchupLabel, label)
	if err != nil {
		return fmt.Errorf("unable to write catchpoint catchup state '%s': %v", catchpointStateCatchupLabel, err)
	}
	return
}

// ResetStagingBalances resets the current staging balances, preparing for a new set of balances to be added
func (c *CatchpointCatchupAccessorImpl) ResetStagingBalances(ctx context.Context, newCatchup bool) (err error) {
	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		err = resetCatchpointStagingBalances(ctx, tx, newCatchup)
		if err != nil {
			return fmt.Errorf("unable to reset catchpoint catchup balances : %v", err)
		}
		if !newCatchup {
			sq, err := accountsDbInit(tx, tx)
			if err != nil {
				return fmt.Errorf("unable to initialize accountsDbInit: %v", err)
			}
			defer sq.close()
			_, err = sq.writeCatchpointStateUint64(ctx, catchpointStateCatchupBalancesRound, 0)
			if err != nil {
				return err
			}

			_, err = sq.writeCatchpointStateUint64(ctx, catchpointStateCatchupBlockRound, 0)
			if err != nil {
				return err
			}

			_, err = sq.writeCatchpointStateString(ctx, catchpointStateCatchupLabel, "")
			if err != nil {
				return err
			}
			_, err = sq.writeCatchpointStateUint64(ctx, catchpointStateCatchupState, 0)
			if err != nil {
				return fmt.Errorf("unable to write catchpoint catchup state '%s': %v", catchpointStateCatchupState, err)
			}
		}
		return
	})
	return
}

// CatchpointCatchupAccessorProgress is used by the caller of ProgressStagingBalances to obtain progress information
type CatchpointCatchupAccessorProgress struct {
	TotalAccounts     uint64
	ProcessedAccounts uint64
	ProcessedBytes    uint64
	TotalChunks       uint64
	SeenHeader        bool
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
	if fileHeader.Version != catchpointFileVersion {
		return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingContent: unable to process catchpoint - version %d is not supported", fileHeader.Version)
	}

	// the following fields are now going to be ignored. We could add these to the database and validate these
	// later on:
	// TotalAccounts, TotalAccounts, Catchpoint, BlockHeaderDigest, BalancesRound
	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		sq, err := accountsDbInit(tx, tx)
		if err != nil {
			return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingContent: unable to initialize accountsDbInit: %v", err)
		}
		defer sq.close()
		_, err = sq.writeCatchpointStateUint64(ctx, catchpointStateCatchupBlockRound, uint64(fileHeader.BlocksRound))
		if err != nil {
			return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingContent: unable to write catchpoint catchup state '%s': %v", catchpointStateCatchupBlockRound, err)
		}
		err = accountsPutTotals(tx, fileHeader.Totals, true)
		return
	})
	if err == nil {
		progress.SeenHeader = true
		progress.TotalAccounts = fileHeader.TotalAccounts
		progress.TotalChunks = fileHeader.TotalChunks
	}
	return err
}

// processStagingBalances deserialize the given bytes as a temporary staging balances
func (c *CatchpointCatchupAccessorImpl) processStagingBalances(ctx context.Context, bytes []byte, progress *CatchpointCatchupAccessorProgress) (err error) {
	if !progress.SeenHeader {
		return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingBalances: content chunk was missing")
	}

	var balances catchpointFileBalancesChunk
	err = protocol.Decode(bytes, &balances)
	if err != nil {
		return err
	}

	if len(balances.Balances) == 0 {
		return fmt.Errorf("processStagingBalances received a chunk with no accounts")
	}

	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		// create the merkle trie for the balances
		mc, err0 := makeMerkleCommitter(tx, true)
		if err0 != nil {
			return err0
		}
		trie, err := merkletrie.MakeTrie(mc, trieCachedNodesCount)
		if err != nil {
			return err
		}

		err = writeCatchpointStagingBalances(ctx, tx, balances.Balances)
		if err != nil {
			return
		}

		for _, balance := range balances.Balances {
			var accountData basics.AccountData
			err = protocol.Decode(balance.AccountData, &accountData)
			if err != nil {
				return err
			}

			// if the account has any asset params, it means that it's the creator of an asset.
			if len(accountData.AssetParams) > 0 {
				for aidx := range accountData.AssetParams {
					err = writeCatchpointStagingCreatable(ctx, tx, balance.Address, basics.CreatableIndex(aidx), basics.AssetCreatable)
					if err != nil {
						return err
					}
				}
			}

			if len(accountData.AppParams) > 0 {
				for aidx := range accountData.AppParams {
					err = writeCatchpointStagingCreatable(ctx, tx, balance.Address, basics.CreatableIndex(aidx), basics.AppCreatable)
					if err != nil {
						return err
					}
				}
			}

			hash := accountHashBuilder(balance.Address, accountData, balance.AccountData)
			added, err := trie.Add(hash)
			if !added {
				return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingBalances: The provided catchpoint file contained the same account more than once. Account address %#v, account data %#v, hash '%s'", balance.Address, accountData, hex.EncodeToString(hash))
			}
			if err != nil {
				return err
			}
		}
		err = trie.Commit()
		if err != nil {
			return
		}
		return
	})
	if err == nil {
		progress.ProcessedAccounts += uint64(len(balances.Balances))
		progress.ProcessedBytes += uint64(len(bytes))
	}
	return err
}

// GetCatchupBlockRound returns the latest block round matching the current catchpoint
func (c *CatchpointCatchupAccessorImpl) GetCatchupBlockRound(ctx context.Context) (round basics.Round, err error) {
	var iRound uint64
	iRound, _, err = c.accountsq.readCatchpointStateUint64(ctx, catchpointStateCatchupBlockRound)
	if err != nil {
		return 0, fmt.Errorf("unable to read catchpoint catchup state '%s': %v", catchpointStateCatchupBlockRound, err)
	}
	return basics.Round(iRound), nil
}

// VerifyCatchpoint verifies that the catchpoint is valid by reconstructing the label.
func (c *CatchpointCatchupAccessorImpl) VerifyCatchpoint(ctx context.Context, blk *bookkeeping.Block) (err error) {
	rdb := c.ledger.trackerDB().rdb
	var balancesHash crypto.Digest
	var blockRound basics.Round
	var totals AccountTotals
	var catchpointLabel string

	catchpointLabel, _, err = c.accountsq.readCatchpointStateString(ctx, catchpointStateCatchupLabel)
	if err != nil {
		return fmt.Errorf("unable to read catchpoint catchup state '%s': %v", catchpointStateCatchupLabel, err)
	}

	var iRound uint64
	iRound, _, err = c.accountsq.readCatchpointStateUint64(ctx, catchpointStateCatchupBlockRound)
	if err != nil {
		return fmt.Errorf("unable to read catchpoint catchup state '%s': %v", catchpointStateCatchupBlockRound, err)
	}
	blockRound = basics.Round(iRound)

	err = rdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		// create the merkle trie for the balances
		mc, err0 := makeMerkleCommitter(tx, true)
		if err0 != nil {
			return fmt.Errorf("unable to make MerkleCommitter: %v", err0)
		}
		var trie *merkletrie.Trie
		trie, err = merkletrie.MakeTrie(mc, trieCachedNodesCount)
		if err != nil {
			return fmt.Errorf("unable to make trie: %v", err)
		}

		balancesHash, err = trie.RootHash()
		if err != nil {
			return fmt.Errorf("unable to get trie root hash: %v", err)
		}

		totals, err = accountsTotals(tx, true)
		if err != nil {
			return fmt.Errorf("unable to get accounts totals: %v", err)
		}
		return
	})
	if err != nil {
		return err
	}
	if blockRound != blk.Round() {
		return fmt.Errorf("block round in block header doesn't match block round in catchpoint")
	}

	catchpointLabelMaker := makeCatchpointLabel(blockRound, blk.Digest(), balancesHash, totals)

	if catchpointLabel != catchpointLabelMaker.String() {
		return fmt.Errorf("catchpoint hash mismatch; expected %s, calculated %s", catchpointLabel, catchpointLabelMaker.String())
	}
	return nil
}

// StoreBalancesRound calculates the balances round based on the first block and the associated consensus parametets, and
// store that to the database
func (c *CatchpointCatchupAccessorImpl) StoreBalancesRound(ctx context.Context, blk *bookkeeping.Block) (err error) {
	// calculate the balances round and store it. It *should* be identical to the one in the catchpoint file header, but we don't want to
	// trust the one in the catchpoint file header, so we'll calculate it ourselves.
	balancesRound := blk.Round() - basics.Round(config.Consensus[blk.CurrentProtocol].MaxBalLookback)
	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		sq, err := accountsDbInit(tx, tx)
		if err != nil {
			return fmt.Errorf("CatchpointCatchupAccessorImpl::StoreBalancesRound: unable to initialize accountsDbInit: %v", err)
		}
		defer sq.close()
		_, err = sq.writeCatchpointStateUint64(ctx, catchpointStateCatchupBalancesRound, uint64(balancesRound))
		if err != nil {
			return fmt.Errorf("CatchpointCatchupAccessorImpl::StoreBalancesRound: unable to write catchpoint catchup state '%s': %v", catchpointStateCatchupBalancesRound, err)
		}
		return
	})
	return
}

// StoreFirstBlock stores a single block to the blocks database.
func (c *CatchpointCatchupAccessorImpl) StoreFirstBlock(ctx context.Context, blk *bookkeeping.Block) (err error) {
	blockDbs := c.ledger.blockDB()
	err = blockDbs.wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		return blockStartCatchupStaging(tx, *blk)
	})
	if err != nil {
		return err
	}
	return nil
}

// StoreBlock stores a single block to the blocks database.
func (c *CatchpointCatchupAccessorImpl) StoreBlock(ctx context.Context, blk *bookkeeping.Block) (err error) {
	blockDbs := c.ledger.blockDB()
	err = blockDbs.wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		return blockPutStaging(tx, *blk)
	})
	if err != nil {
		return err
	}
	return nil
}

// FinishBlocks concludes the catchup of the blocks database.
func (c *CatchpointCatchupAccessorImpl) FinishBlocks(ctx context.Context, applyChanges bool) (err error) {
	blockDbs := c.ledger.blockDB()
	err = blockDbs.wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		if applyChanges {
			return blockCompleteCatchup(tx)
		}
		return blockAbortCatchup(tx)
	})
	if err != nil {
		return err
	}
	return nil
}

// EnsureFirstBlock ensure that we have a single block in the staging block table, and returns that block
func (c *CatchpointCatchupAccessorImpl) EnsureFirstBlock(ctx context.Context) (blk bookkeeping.Block, err error) {
	blockDbs := c.ledger.blockDB()
	err = blockDbs.wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		blk, err = blockEnsureSingleBlock(tx)
		return
	})
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
	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		var balancesRound uint64
		var totals AccountTotals

		sq, err := accountsDbInit(tx, tx)
		if err != nil {
			return fmt.Errorf("unable to initialize accountsDbInit: %v", err)
		}
		defer sq.close()

		balancesRound, _, err = sq.readCatchpointStateUint64(ctx, catchpointStateCatchupBalancesRound)
		if err != nil {
			return err
		}

		totals, err = accountsTotals(tx, true)
		if err != nil {
			return err
		}

		err = applyCatchpointStagingBalances(ctx, tx, basics.Round(balancesRound))
		if err != nil {
			return err
		}

		err = accountsPutTotals(tx, totals, false)
		if err != nil {
			return err
		}

		err = resetCatchpointStagingBalances(ctx, tx, false)
		if err != nil {
			return err
		}

		_, err = sq.writeCatchpointStateUint64(ctx, catchpointStateCatchupBalancesRound, 0)
		if err != nil {
			return err
		}

		_, err = sq.writeCatchpointStateUint64(ctx, catchpointStateCatchupBlockRound, 0)
		if err != nil {
			return err
		}

		_, err = sq.writeCatchpointStateString(ctx, catchpointStateCatchupLabel, "")
		if err != nil {
			return err
		}

		_, err = sq.writeCatchpointStateUint64(ctx, catchpointStateCatchupState, 0)
		if err != nil {
			return fmt.Errorf("unable to write catchpoint catchup state '%s': %v", catchpointStateCatchupState, err)
		}

		return
	})
	return err
}
