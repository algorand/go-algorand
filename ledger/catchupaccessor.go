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
	"fmt"
	"strings"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// CatchpointCatchupAccessor is an accessor wrapping the database storage for the catchpoint catchup functionality.
type CatchpointCatchupAccessor struct {
	ledger *Ledger
	log    logging.Logger
}

// CatchpointCatchupState is the state of the current catchpoint catchup process
type CatchpointCatchupState int

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
func MakeCatchpointCatchupAccessor(ledger *Ledger, log logging.Logger) *CatchpointCatchupAccessor {
	return &CatchpointCatchupAccessor{
		ledger: ledger,
		log:    log,
	}
}

// GetState returns the current state of the catchpoint catchup
func (c *CatchpointCatchupAccessor) GetState(ctx context.Context) (state CatchpointCatchupState, err error) {
	rdb := c.ledger.trackerDB().rdb
	err = rdb.Atomic(func(tx *sql.Tx) (err error) {
		var istate uint64
		istate, _, err = readCatchpointStateUint64(ctx, tx, "catchpointCatchupState")
		if err != nil {
			return fmt.Errorf("unable to read catchpoint catchup state 'catchpointCatchupState': %v", err)
		}
		state = CatchpointCatchupState(istate)
		return
	})
	return
}

// SetState set the state of the catchpoint catchup
func (c *CatchpointCatchupAccessor) SetState(ctx context.Context, state CatchpointCatchupState) (err error) {
	if state < CatchpointCatchupStateInactive || state > catchpointCatchupStateLast {
		return fmt.Errorf("invalid catchpoint catchup state provided : %d", state)
	}
	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(tx *sql.Tx) (err error) {
		_, err = writeCatchpointStateUint64(ctx, tx, "catchpointCatchupState", uint64(state))
		if err != nil {
			return fmt.Errorf("unable to write catchpoint catchup state 'catchpointCatchupState': %v", err)
		}
		return
	})
	return
}

// GetLabel returns the current catchpoint catchup label
func (c *CatchpointCatchupAccessor) GetLabel(ctx context.Context) (label string, err error) {
	rdb := c.ledger.trackerDB().rdb
	err = rdb.Atomic(func(tx *sql.Tx) (err error) {
		label, _, err = readCatchpointStateString(ctx, tx, "catchpointCatchupLabel")
		if err != nil {
			return fmt.Errorf("unable to read catchpoint catchup state 'catchpointCatchupLabel': %v", err)
		}
		return
	})
	return
}

// SetLabel set the catchpoint catchup label
func (c *CatchpointCatchupAccessor) SetLabel(ctx context.Context, label string) (err error) {
	wdb := c.ledger.trackerDB().wdb
	// verify it's parsable :
	_, _, err = ParseCatchpointLabel(label)
	if err != nil {
		return
	}
	err = wdb.Atomic(func(tx *sql.Tx) (err error) {
		_, err = writeCatchpointStateString(ctx, tx, "catchpointCatchupLabel", label)
		if err != nil {
			return fmt.Errorf("unable to write catchpoint catchup state 'catchpointCatchupLabel': %v", err)
		}
		return
	})
	return
}

// ResetStagingBalances resets the current staging balances, preparing for a new set of balances to be added
func (c *CatchpointCatchupAccessor) ResetStagingBalances(ctx context.Context, newCatchup bool) (err error) {
	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(tx *sql.Tx) (err error) {
		err = resetCatchpointStagingBalances(ctx, tx, newCatchup)
		if err != nil {
			return fmt.Errorf("unable to reset catchpoint catchup balances : %v", err)
		}
		if !newCatchup {
			_, err = writeCatchpointStateUint64(ctx, tx, "catchpointCatchupBalancesRound", 0)
			if err != nil {
				return err
			}

			_, err = writeCatchpointStateUint64(ctx, tx, "catchpointCatchupBlockRound", 0)
			if err != nil {
				return err
			}

			_, err = writeCatchpointStateString(ctx, tx, "catchpointCatchupLabel", "")
			if err != nil {
				return err
			}
			_, err = writeCatchpointStateUint64(ctx, tx, "catchpointCatchupState", 0)
			if err != nil {
				return fmt.Errorf("unable to write catchpoint catchup state 'catchpointCatchupState': %v", err)
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
	TotalChunks       uint64
	SeenHeader        bool
}

// ProgressStagingBalances deserialize the given bytes as a temporary staging balances
func (c *CatchpointCatchupAccessor) ProgressStagingBalances(ctx context.Context, sectionName string, bytes []byte, progress *CatchpointCatchupAccessorProgress) (err error) {
	if sectionName == "content.msgpack" {
		return c.processStagingContent(ctx, bytes, progress)
	}
	if strings.HasPrefix(sectionName, "balances.") && strings.HasSuffix(sectionName, ".msgpack") {
		return c.processStagingBalances(ctx, bytes, progress)
	}
	// we want to allow undefined sections to support backward compatibility.
	c.log.Warnf("CatchpointCatchupAccessor::ProgressStagingBalances encountered unexpected section name '%s' of length %d, which would be ignored", sectionName, len(bytes))
	return nil
}

// ProgressStagingBalances deserialize the given bytes as a temporary staging balances
func (c *CatchpointCatchupAccessor) processStagingContent(ctx context.Context, bytes []byte, progress *CatchpointCatchupAccessorProgress) (err error) {
	if progress.SeenHeader {
		return fmt.Errorf("content chunk already seen")
	}
	var fileHeader catchpointFileHeader
	err = protocol.DecodeReflect(bytes, &fileHeader)
	if err != nil {
		return err
	}
	if fileHeader.Version != initialVersion {
		return fmt.Errorf("unable to process catchpoint - version %d is not supported", fileHeader.Version)
	}

	// the following fields are now going to be ignored. We should add these to the database and validate these
	// later on:
	// TotalAccounts, TotalAccounts, Catchpoint, BlockHeaderDigest
	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(tx *sql.Tx) (err error) {
		_, err = writeCatchpointStateUint64(ctx, tx, "catchpointCatchupBlockRound", uint64(fileHeader.BlocksRound))
		if err != nil {
			return fmt.Errorf("unable to write catchpoint catchup state 'catchpointCatchupBlockRound': %v", err)
		}
		_, err = writeCatchpointStateUint64(ctx, tx, "catchpointCatchupBalancesRound", uint64(fileHeader.BalancesRound))
		if err != nil {
			return fmt.Errorf("unable to write catchpoint catchup state 'catchpointCatchupBalancesRound': %v", err)
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

// ProgressStagingBalances deserialize the given bytes as a temporary staging balances
func (c *CatchpointCatchupAccessor) processStagingBalances(ctx context.Context, bytes []byte, progress *CatchpointCatchupAccessorProgress) (err error) {
	if !progress.SeenHeader {
		return fmt.Errorf("content chunk was missing")
	}
	var balances catchpointFileBalancesChunk
	err = protocol.DecodeReflect(bytes, &balances)
	if err != nil {
		return err
	}

	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(tx *sql.Tx) (err error) {
		// create the merkle trie for the balances
		mc, err0 := makeMerkleCommitter(tx, true)
		if err0 != nil {
			return err0
		}
		trie, err := merkletrie.MakeTrie(mc, trieCachedNodesCount)
		if err != nil {
			return err
		}

		err = writeCatchpointStagingBalances(ctx, tx, balances)
		if err != nil {
			return
		}

		for _, balance := range balances {
			var accountData basics.AccountData
			err = protocol.Decode(balance.AccountData, &accountData)
			if err != nil {
				return err
			}

			// if the account has any asset params, it means that it's the creator of an asset.
			if len(accountData.AssetParams) > 0 {
				for aidx := range accountData.AssetParams {
					err = writeCatchpointStagingAssets(ctx, tx, balance.Address, aidx)
					if err != nil {
						return err
					}
				}
			}

			var addr basics.Address
			copy(addr[:], balance.Address)
			hash := accountHashBuilder(addr, accountData, balance.AccountData)
			added, err := trie.Add(hash)
			if !added {
				panic("attempted to add duplicate hash '%v' to merkle trie.")
				//c.log.Warnf("attempted to add duplicate hash '%v' to merkle trie.", hash)
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
		progress.ProcessedAccounts += uint64(len(balances))
	}
	return err
}

// GetCatchupBlockRound returns the latest block round matching the current catchpoint
func (c *CatchpointCatchupAccessor) GetCatchupBlockRound(ctx context.Context) (round basics.Round, err error) {
	rdb := c.ledger.trackerDB().rdb
	err = rdb.Atomic(func(tx *sql.Tx) (err error) {
		var iRound uint64
		iRound, _, err = readCatchpointStateUint64(ctx, tx, "catchpointCatchupBlockRound")
		if err != nil {
			return fmt.Errorf("unable to read catchpoint catchup state 'catchpointCatchupBlockRound': %v", err)
		}
		round = basics.Round(iRound)
		return
	})
	return
}

// VerifyCatchpoint verifies that the catchpoint is valid by reconstructing the label.
func (c *CatchpointCatchupAccessor) VerifyCatchpoint(ctx context.Context, blk *bookkeeping.Block) (err error) {
	rdb := c.ledger.trackerDB().rdb
	var balancesHash crypto.Digest
	var blockRound basics.Round
	var totals AccountTotals
	var catchpointLabel string
	err = rdb.Atomic(func(tx *sql.Tx) (err error) {
		catchpointLabel, _, err = readCatchpointStateString(ctx, tx, "catchpointCatchupLabel")
		if err != nil {
			return fmt.Errorf("unable to read catchpoint catchup state 'catchpointCatchupLabel': %v", err)
		}

		var iRound uint64
		iRound, _, err = readCatchpointStateUint64(ctx, tx, "catchpointCatchupBlockRound")
		if err != nil {
			return fmt.Errorf("unable to read catchpoint catchup state 'catchpointCatchupBlockRound': %v", err)
		}
		blockRound = basics.Round(iRound)

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

// StoreFirstBlock stores a single block to the blocks database.
func (c *CatchpointCatchupAccessor) StoreFirstBlock(ctx context.Context, blk *bookkeeping.Block) (err error) {
	blockDbs := c.ledger.blockDB()
	err = blockDbs.wdb.Atomic(func(tx *sql.Tx) (err error) {
		return blockStartCatchupStaging(tx, *blk)
	})
	if err != nil {
		return err
	}
	return nil
}

// StoreBlock stores a single block to the blocks database.
func (c *CatchpointCatchupAccessor) StoreBlock(ctx context.Context, blk *bookkeeping.Block) (err error) {
	blockDbs := c.ledger.blockDB()
	err = blockDbs.wdb.Atomic(func(tx *sql.Tx) (err error) {
		return blockPutStaging(tx, *blk)
	})
	if err != nil {
		return err
	}
	return nil
}

// FinishBlocks concludes the catchup of the blocks database.
func (c *CatchpointCatchupAccessor) FinishBlocks(ctx context.Context, applyChanges bool) (err error) {
	blockDbs := c.ledger.blockDB()
	err = blockDbs.wdb.Atomic(func(tx *sql.Tx) (err error) {
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
func (c *CatchpointCatchupAccessor) EnsureFirstBlock(ctx context.Context) (blk bookkeeping.Block, err error) {
	blockDbs := c.ledger.blockDB()
	err = blockDbs.wdb.Atomic(func(tx *sql.Tx) (err error) {
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
func (c *CatchpointCatchupAccessor) CompleteCatchup(ctx context.Context) (err error) {
	err = c.FinishBlocks(ctx, true)
	if err != nil {
		return err
	}
	err = c.FinishBlalances(ctx)
	if err != nil {
		return err
	}

	return c.ledger.reloadLedger()
}

// FinishBlalances concludes the catchup of the balances(tracker) database.
func (c *CatchpointCatchupAccessor) FinishBlalances(ctx context.Context) (err error) {
	wdb := c.ledger.trackerDB().wdb
	err = wdb.Atomic(func(tx *sql.Tx) (err error) {
		var balancesRound uint64
		var totals AccountTotals

		balancesRound, _, err = readCatchpointStateUint64(ctx, tx, "catchpointCatchupBalancesRound")
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

		_, err = writeCatchpointStateUint64(ctx, tx, "catchpointCatchupBalancesRound", 0)
		if err != nil {
			return err
		}

		_, err = writeCatchpointStateUint64(ctx, tx, "catchpointCatchupBlockRound", 0)
		if err != nil {
			return err
		}

		_, err = writeCatchpointStateString(ctx, tx, "catchpointCatchupLabel", "")
		if err != nil {
			return err
		}

		_, err = writeCatchpointStateUint64(ctx, tx, "catchpointCatchupState", 0)
		if err != nil {
			return fmt.Errorf("unable to write catchpoint catchup state 'catchpointCatchupState': %v", err)
		}

		return
	})
	return err
}
