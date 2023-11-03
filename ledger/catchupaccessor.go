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
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/encoded"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/blockdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
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

	// ProcessStagingBalances deserialize the given bytes as a temporary staging balances
	ProcessStagingBalances(ctx context.Context, sectionName string, bytes []byte, progress *CatchpointCatchupAccessorProgress) (err error)

	// BuildMerkleTrie inserts the account hashes into the merkle trie
	BuildMerkleTrie(ctx context.Context, progressUpdates func(uint64, uint64)) (err error)

	// GetCatchupBlockRound returns the latest block round matching the current catchpoint
	GetCatchupBlockRound(ctx context.Context) (round basics.Round, err error)

	// GetVerifyData returns the balances hash, spver hash and totals used by VerifyCatchpoint
	GetVerifyData(ctx context.Context) (balancesHash crypto.Digest, spverHash crypto.Digest, totals ledgercore.AccountTotals, err error)

	// VerifyCatchpoint verifies that the catchpoint is valid by reconstructing the label.
	VerifyCatchpoint(ctx context.Context, blk *bookkeeping.Block) (err error)

	// StoreBalancesRound calculates the balances round based on the first block and the associated consensus parameters, and
	// store that to the database
	StoreBalancesRound(ctx context.Context, blk *bookkeeping.Block) (err error)

	// StoreFirstBlock stores a single block to the blocks database.
	StoreFirstBlock(ctx context.Context, blk *bookkeeping.Block, cert *agreement.Certificate) (err error)

	// StoreBlock stores a single block to the blocks database.
	StoreBlock(ctx context.Context, blk *bookkeeping.Block, cert *agreement.Certificate) (err error)

	// FinishBlocks concludes the catchup of the blocks database.
	FinishBlocks(ctx context.Context, applyChanges bool) (err error)

	// EnsureFirstBlock ensure that we have a single block in the staging block table, and returns that block
	EnsureFirstBlock(ctx context.Context) (blk bookkeeping.Block, err error)

	// CompleteCatchup completes the catchpoint catchup process by switching the databases tables around
	// and reloading the ledger.
	CompleteCatchup(ctx context.Context) (err error)

	// Ledger returns a narrow subset of Ledger methods needed by CatchpointCatchupAccessor clients
	Ledger() (l CatchupAccessorClientLedger)
}

type stagingWriter interface {
	writeBalances(context.Context, []trackerdb.NormalizedAccountBalance) error
	writeCreatables(context.Context, []trackerdb.NormalizedAccountBalance) error
	writeHashes(context.Context, []trackerdb.NormalizedAccountBalance) error
	writeKVs(context.Context, []encoded.KVRecordV6) error
	isShared() bool
}

type stagingWriterImpl struct {
	wdb trackerdb.Store
}

func (w *stagingWriterImpl) writeBalances(ctx context.Context, balances []trackerdb.NormalizedAccountBalance) error {
	return w.wdb.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		crw, err := tx.MakeCatchpointReaderWriter()
		if err != nil {
			return err
		}
		return crw.WriteCatchpointStagingBalances(ctx, balances)
	})
}

func (w *stagingWriterImpl) writeKVs(ctx context.Context, kvrs []encoded.KVRecordV6) error {
	return w.wdb.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		crw, err := tx.MakeCatchpointReaderWriter()
		if err != nil {
			return err
		}

		keys := make([][]byte, len(kvrs))
		values := make([][]byte, len(kvrs))
		hashes := make([][]byte, len(kvrs))
		for i := 0; i < len(kvrs); i++ {
			keys[i] = kvrs[i].Key

			// Since `encoded.KVRecordV6` is `omitempty` and `omitemptyarray`,
			// when we have an instance of `encoded.KVRecordV6` with nil value,
			// an empty box is unmarshalled to have `nil` value,
			// while this might be mistaken to be a box deletion.
			//
			// We don't want to mistake this to be a deleted box:
			// We are (and should be) during Fast Catchup (FC)
			// writing to DB with empty byte string, rather than writing nil.
			//
			// This matters in sqlite3,
			// for sqlite3 differs on writing nil byte slice to table from writing []byte{}:
			// - writing nil byte slice is true that `value is NULL`
			// - writing []byte{} is false on `value is NULL`.
			//
			// For the sake of consistency, we convert nil to []byte{}.
			//
			// Also, from a round by round catchup perspective,
			// when we delete a box, in accountsNewRoundImpl method,
			// the kv pair with value = nil will be deleted from kvstore table.
			// Thus, it seems more consistent and appropriate to write as []byte{}.

			if kvrs[i].Value == nil {
				kvrs[i].Value = []byte{}
			}
			values[i] = kvrs[i].Value
			hashes[i] = trackerdb.KvHashBuilderV6(string(keys[i]), values[i])
		}

		return crw.WriteCatchpointStagingKVs(ctx, keys, values, hashes)
	})
}

func (w *stagingWriterImpl) writeCreatables(ctx context.Context, balances []trackerdb.NormalizedAccountBalance) error {
	return w.wdb.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {
		crw, err := tx.MakeCatchpointReaderWriter()
		if err != nil {
			return err
		}

		return crw.WriteCatchpointStagingCreatable(ctx, balances)
	})
}

func (w *stagingWriterImpl) writeHashes(ctx context.Context, balances []trackerdb.NormalizedAccountBalance) error {
	return w.wdb.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {
		crw, err := tx.MakeCatchpointReaderWriter()
		if err != nil {
			return err
		}

		return crw.WriteCatchpointStagingHashes(ctx, balances)
	})
}

func (w *stagingWriterImpl) isShared() bool {
	return w.wdb.IsSharedCacheConnection()
}

// catchpointCatchupAccessorImpl is the concrete implementation of the CatchpointCatchupAccessor interface
type catchpointCatchupAccessorImpl struct {
	ledger          *Ledger
	catchpointStore trackerdb.CatchpointReaderWriter

	stagingWriter stagingWriter

	// log copied from ledger
	log logging.Logger

	acctResCnt catchpointAccountResourceCounter

	// expecting next account to be a specific account
	expectingSpecificAccount bool
	// next expected balance account, empty address if not expecting specific account
	nextExpectedAccount basics.Address
}

// catchpointAccountResourceCounter keeps track of the resources processed for the current account
type catchpointAccountResourceCounter struct {
	totalAppParams      uint64
	totalAppLocalStates uint64
	totalAssetParams    uint64
	totalAssets         uint64
}

// CatchpointCatchupState is the state of the current catchpoint catchup process
type CatchpointCatchupState int32

const (
	// CatchpointCatchupStateInactive is the common state for the catchpoint catchup - not active.
	CatchpointCatchupStateInactive = iota
	// CatchpointCatchupStateLedgerDownload indicates that we're downloading the ledger
	CatchpointCatchupStateLedgerDownload
	// CatchpointCatchupStateLatestBlockDownload indicates that we're download the latest block
	CatchpointCatchupStateLatestBlockDownload
	// CatchpointCatchupStateBlocksDownload indicates that we're downloading the blocks prior to the latest one ( total of CatchpointLookback blocks )
	CatchpointCatchupStateBlocksDownload
	// CatchpointCatchupStateSwitch indicates that we're switching to use the downloaded ledger/blocks content
	CatchpointCatchupStateSwitch

	// catchpointCatchupStateLast is the last entry in the CatchpointCatchupState enumeration.
	catchpointCatchupStateLast = CatchpointCatchupStateSwitch
)

// CatchupAccessorClientLedger represents ledger interface needed for catchpoint accessor clients
type CatchupAccessorClientLedger interface {
	Block(rnd basics.Round) (blk bookkeeping.Block, err error)
	GenesisHash() crypto.Digest
	BlockHdr(rnd basics.Round) (blk bookkeeping.BlockHeader, err error)
	Latest() (rnd basics.Round)
}

// MakeCatchpointCatchupAccessor creates a CatchpointCatchupAccessor given a ledger
func MakeCatchpointCatchupAccessor(ledger *Ledger, log logging.Logger) CatchpointCatchupAccessor {
	crw, _ := ledger.trackerDB().MakeCatchpointReaderWriter()
	return &catchpointCatchupAccessorImpl{
		ledger:          ledger,
		catchpointStore: crw,
		stagingWriter:   &stagingWriterImpl{wdb: ledger.trackerDB()},
		log:             log,
	}
}

// GetState returns the current state of the catchpoint catchup
func (c *catchpointCatchupAccessorImpl) GetState(ctx context.Context) (state CatchpointCatchupState, err error) {
	var istate uint64
	istate, err = c.catchpointStore.ReadCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupState)
	if err != nil {
		return 0, fmt.Errorf("unable to read catchpoint catchup state '%s': %v", trackerdb.CatchpointStateCatchupState, err)
	}
	state = CatchpointCatchupState(istate)
	return
}

// SetState set the state of the catchpoint catchup
func (c *catchpointCatchupAccessorImpl) SetState(ctx context.Context, state CatchpointCatchupState) (err error) {
	if state < CatchpointCatchupStateInactive || state > catchpointCatchupStateLast {
		return fmt.Errorf("invalid catchpoint catchup state provided : %d", state)
	}
	err = c.catchpointStore.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupState, uint64(state))
	if err != nil {
		return fmt.Errorf("unable to write catchpoint catchup state '%s': %v", trackerdb.CatchpointStateCatchupState, err)
	}
	return
}

// GetLabel returns the current catchpoint catchup label
func (c *catchpointCatchupAccessorImpl) GetLabel(ctx context.Context) (label string, err error) {
	label, err = c.catchpointStore.ReadCatchpointStateString(ctx, trackerdb.CatchpointStateCatchupLabel)
	if err != nil {
		return "", fmt.Errorf("unable to read catchpoint catchup state '%s': %v", trackerdb.CatchpointStateCatchupLabel, err)
	}
	return
}

// SetLabel set the catchpoint catchup label
func (c *catchpointCatchupAccessorImpl) SetLabel(ctx context.Context, label string) (err error) {
	// verify it's parsable :
	_, _, err = ledgercore.ParseCatchpointLabel(label)
	if err != nil {
		return
	}
	err = c.catchpointStore.WriteCatchpointStateString(ctx, trackerdb.CatchpointStateCatchupLabel, label)
	if err != nil {
		return fmt.Errorf("unable to write catchpoint catchup state '%s': %v", trackerdb.CatchpointStateCatchupLabel, err)
	}
	return
}

// ResetStagingBalances resets the current staging balances, preparing for a new set of balances to be added
func (c *catchpointCatchupAccessorImpl) ResetStagingBalances(ctx context.Context, newCatchup bool) (err error) {
	if !newCatchup {
		c.ledger.setSynchronousMode(ctx, c.ledger.synchronousMode)
	}
	start := time.Now()
	ledgerResetstagingbalancesCount.Inc(nil)
	err = c.ledger.trackerDB().Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		crw, err := tx.MakeCatchpointWriter()
		if err != nil {
			return err
		}

		err = crw.ResetCatchpointStagingBalances(ctx, newCatchup)
		if err != nil {
			return fmt.Errorf("unable to reset catchpoint catchup balances : %v", err)
		}
		if !newCatchup {
			err = crw.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupBalancesRound, 0)
			if err != nil {
				return err
			}

			err = crw.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupBlockRound, 0)
			if err != nil {
				return err
			}

			err = crw.WriteCatchpointStateString(ctx, trackerdb.CatchpointStateCatchupLabel, "")
			if err != nil {
				return err
			}
			err = crw.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupState, 0)
			if err != nil {
				return fmt.Errorf("unable to write catchpoint catchup state '%s': %v", trackerdb.CatchpointStateCatchupState, err)
			}
		}
		return
	})
	ledgerResetstagingbalancesMicros.AddMicrosecondsSince(start, nil)
	return
}

// CatchpointCatchupAccessorProgress is used by the caller of ProcessStagingBalances to obtain progress information
type CatchpointCatchupAccessorProgress struct {
	TotalAccounts      uint64
	ProcessedAccounts  uint64
	ProcessedBytes     uint64
	TotalKVs           uint64
	ProcessedKVs       uint64
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
	KVWriteDuration         time.Duration
}

// ProcessStagingBalances deserialize the given bytes as a temporary staging balances
func (c *catchpointCatchupAccessorImpl) ProcessStagingBalances(ctx context.Context, sectionName string, bytes []byte, progress *CatchpointCatchupAccessorProgress) (err error) {
	// content.msgpack comes first, followed by stateProofVerificationContext.msgpack and then by balances.x.msgpack.
	if sectionName == CatchpointContentFileName {
		return c.processStagingContent(ctx, bytes, progress)
	}
	if sectionName == catchpointSPVerificationFileName {
		return c.processStagingStateProofVerificationContext(bytes)
	}
	if strings.HasPrefix(sectionName, catchpointBalancesFileNamePrefix) && strings.HasSuffix(sectionName, catchpointBalancesFileNameSuffix) {
		return c.processStagingBalances(ctx, bytes, progress)
	}
	// we want to allow undefined sections to support backward compatibility.
	c.log.Warnf("CatchpointCatchupAccessorImpl::ProcessStagingBalances encountered unexpected section name '%s' of length %d, which would be ignored", sectionName, len(bytes))
	return nil
}

// processStagingStateProofVerificationContext deserialize the given bytes as a temporary staging state proof verification data
func (c *catchpointCatchupAccessorImpl) processStagingStateProofVerificationContext(bytes []byte) (err error) {
	var decodedData catchpointStateProofVerificationContext
	err = protocol.Decode(bytes, &decodedData)
	if err != nil {
		return err
	}

	if len(decodedData.Data) == 0 {
		return
	}

	// 6 months of stuck state proofs should lead to about 1.5 MB of data, so we avoid redundant timers
	// and progress reports.
	err = c.ledger.trackerDB().Batch(func(ctx context.Context, tx trackerdb.BatchScope) (err error) {
		return tx.MakeSpVerificationCtxWriter().StoreSPContextsToCatchpointTbl(ctx, decodedData.Data)
	})

	return err
}

// processStagingContent deserialize the given bytes as a temporary staging balances content
func (c *catchpointCatchupAccessorImpl) processStagingContent(ctx context.Context, bytes []byte, progress *CatchpointCatchupAccessorProgress) (err error) {
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
	case CatchpointFileVersionV7:
	default:
		return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingContent: unable to process catchpoint - version %d is not supported", fileHeader.Version)
	}

	// the following fields are now going to be ignored. We could add these to the database and validate these
	// later on:
	// TotalAccounts, TotalAccounts, Catchpoint, BlockHeaderDigest, BalancesRound
	start := time.Now()
	ledgerProcessstagingcontentCount.Inc(nil)
	err = c.ledger.trackerDB().Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		cw, err := tx.MakeCatchpointWriter()
		if err != nil {
			return err
		}
		err = cw.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupVersion, fileHeader.Version)
		if err != nil {
			return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingContent: unable to write catchpoint catchup version '%s': %v", trackerdb.CatchpointStateCatchupVersion, err)
		}
		aw, err := tx.MakeAccountsWriter()
		if err != nil {
			return err
		}

		err = cw.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupBlockRound, uint64(fileHeader.BlocksRound))
		if err != nil {
			return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingContent: unable to write catchpoint catchup state '%s': %v", trackerdb.CatchpointStateCatchupBlockRound, err)
		}
		if fileHeader.Version >= CatchpointFileVersionV6 {
			err = cw.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupHashRound, uint64(fileHeader.BlocksRound))
			if err != nil {
				return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingContent: unable to write catchpoint catchup state '%s': %v", trackerdb.CatchpointStateCatchupHashRound, err)
			}
		}
		err = aw.AccountsPutTotals(fileHeader.Totals, true)
		return
	})
	ledgerProcessstagingcontentMicros.AddMicrosecondsSince(start, nil)
	if err == nil {
		progress.SeenHeader = true
		progress.TotalAccounts = fileHeader.TotalAccounts
		progress.TotalKVs = fileHeader.TotalKVs

		progress.TotalChunks = fileHeader.TotalChunks
		progress.Version = fileHeader.Version
		c.ledger.setSynchronousMode(ctx, c.ledger.accountsRebuildSynchronousMode)
	}

	return err
}

// processStagingBalances deserialize the given bytes as a temporary staging balances
func (c *catchpointCatchupAccessorImpl) processStagingBalances(ctx context.Context, bytes []byte, progress *CatchpointCatchupAccessorProgress) (err error) {
	if !progress.SeenHeader {
		return fmt.Errorf("CatchpointCatchupAccessorImpl::processStagingBalances: content chunk was missing")
	}

	start := time.Now()
	ledgerProcessstagingbalancesCount.Inc(nil)

	var normalizedAccountBalances []trackerdb.NormalizedAccountBalance
	var expectingMoreEntries []bool
	var chunkKVs []encoded.KVRecordV6

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

		normalizedAccountBalances, err = prepareNormalizedBalancesV5(balances.Balances, c.ledger.GenesisProto())
		expectingMoreEntries = make([]bool, len(balances.Balances))

	case CatchpointFileVersionV6:
		fallthrough
	case CatchpointFileVersionV7:
		var chunk catchpointFileChunkV6
		err = protocol.Decode(bytes, &chunk)
		if err != nil {
			return err
		}

		if len(chunk.Balances) == 0 && len(chunk.KVs) == 0 {
			return fmt.Errorf("processStagingBalances received a chunk with no accounts or KVs")
		}

		normalizedAccountBalances, err = prepareNormalizedBalancesV6(chunk.Balances, c.ledger.GenesisProto())
		expectingMoreEntries = make([]bool, len(chunk.Balances))
		for i, balance := range chunk.Balances {
			expectingMoreEntries[i] = balance.ExpectingMoreEntries
		}
		chunkKVs = chunk.KVs
	}

	if err != nil {
		return fmt.Errorf("processStagingBalances failed to prepare normalized balances : %w", err)
	}

	expectingSpecificAccount := c.expectingSpecificAccount
	nextExpectedAccount := c.nextExpectedAccount

	// keep track of number of resources processed for each account
	for i, balance := range normalizedAccountBalances {
		// missing resources for this account
		if expectingSpecificAccount && balance.Address != nextExpectedAccount {
			return fmt.Errorf("processStagingBalances received incomplete chunks for account %v", nextExpectedAccount)
		}

		for _, resData := range balance.Resources {
			if resData.IsApp() && resData.IsOwning() {
				c.acctResCnt.totalAppParams++
			}
			if resData.IsApp() && resData.IsHolding() {
				c.acctResCnt.totalAppLocalStates++
			}
			if resData.IsAsset() && resData.IsOwning() {
				c.acctResCnt.totalAssetParams++
			}
			if resData.IsAsset() && resData.IsHolding() {
				c.acctResCnt.totalAssets++
			}
		}
		// check that counted resources adds up for this account
		if !expectingMoreEntries[i] {
			if c.acctResCnt.totalAppParams != balance.AccountData.TotalAppParams {
				return fmt.Errorf(
					"processStagingBalances received %d appParams for account %v, expected %d",
					c.acctResCnt.totalAppParams,
					balance.Address,
					balance.AccountData.TotalAppParams,
				)
			}
			if c.acctResCnt.totalAppLocalStates != balance.AccountData.TotalAppLocalStates {
				return fmt.Errorf(
					"processStagingBalances received %d appLocalStates for account %v, expected %d",
					c.acctResCnt.totalAppParams,
					balance.Address,
					balance.AccountData.TotalAppLocalStates,
				)
			}
			if c.acctResCnt.totalAssetParams != balance.AccountData.TotalAssetParams {
				return fmt.Errorf(
					"processStagingBalances received %d assetParams for account %v, expected %d",
					c.acctResCnt.totalAppParams,
					balance.Address,
					balance.AccountData.TotalAssetParams,
				)
			}
			if c.acctResCnt.totalAssets != balance.AccountData.TotalAssets {
				return fmt.Errorf(
					"processStagingBalances received %d assets for account %v, expected %d",
					c.acctResCnt.totalAppParams,
					balance.Address,
					balance.AccountData.TotalAssets,
				)
			}
			c.acctResCnt = catchpointAccountResourceCounter{}
			nextExpectedAccount = basics.Address{}
			expectingSpecificAccount = false
		} else {
			nextExpectedAccount = balance.Address
			expectingSpecificAccount = true
		}
	}

	wg := sync.WaitGroup{}

	var errBalances error
	var errCreatables error
	var errHashes error
	var errKVs error
	var durBalances time.Duration
	var durCreatables time.Duration
	var durHashes time.Duration
	var durKVs time.Duration

	// start the balances writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		writeBalancesStart := time.Now()
		errBalances = c.stagingWriter.writeBalances(ctx, normalizedAccountBalances)
		durBalances = time.Since(writeBalancesStart)
	}()

	// on a in-memory database, wait for the writer to finish before starting the new writer
	if c.stagingWriter.isShared() {
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
			writeCreatablesStart := time.Now()
			errCreatables = c.stagingWriter.writeCreatables(ctx, normalizedAccountBalances)
			durCreatables = time.Since(writeCreatablesStart)
		}
	}()

	// on a in-memory database, wait for the writer to finish before starting the new writer
	if c.stagingWriter.isShared() {
		wg.Wait()
	}

	// start the accounts pending hashes writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		writeHashesStart := time.Now()
		errHashes = c.stagingWriter.writeHashes(ctx, normalizedAccountBalances)
		durHashes = time.Since(writeHashesStart)
	}()

	// on a in-memory database, wait for the writer to finish before starting the new writer
	if c.stagingWriter.isShared() {
		wg.Wait()
	}

	// start the kv store writer
	wg.Add(1)
	go func() {
		defer wg.Done()

		writeKVsStart := time.Now()
		errKVs = c.stagingWriter.writeKVs(ctx, chunkKVs)
		durKVs = time.Since(writeKVsStart)
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
	if errKVs != nil {
		return errKVs
	}

	progress.BalancesWriteDuration += durBalances
	progress.CreatablesWriteDuration += durCreatables
	progress.HashesWriteDuration += durHashes
	progress.KVWriteDuration += durKVs

	ledgerProcessstagingbalancesMicros.AddMicrosecondsSince(start, nil)
	progress.ProcessedBytes += uint64(len(bytes))
	progress.ProcessedKVs += uint64(len(chunkKVs))
	for _, acctBal := range normalizedAccountBalances {
		progress.TotalAccountHashes += uint64(len(acctBal.AccountHashes))
		if !acctBal.PartialBalance {
			progress.ProcessedAccounts++
		}
	}

	// not strictly required, but clean up the pointer when we're done.
	if progress.ProcessedAccounts == progress.TotalAccounts {
		progress.cachedTrie = nil
		// restore "normal" synchronous mode
		c.ledger.setSynchronousMode(ctx, c.ledger.synchronousMode)
	}

	c.expectingSpecificAccount = expectingSpecificAccount
	c.nextExpectedAccount = nextExpectedAccount
	return err
}

// countHashes disambiguates the 2 hash types included in the merkle trie:
// * accounts + createables (assets + apps)
// * KVs
//
// The function is _not_ a general purpose way to count hashes by hash kind.
func countHashes(hashes [][]byte) (accountCount, kvCount uint64) {
	for _, hash := range hashes {
		if hash[trackerdb.HashKindEncodingIndex] == byte(trackerdb.KvHK) {
			kvCount++
		} else {
			accountCount++
		}
	}
	return accountCount, kvCount
}

// BuildMerkleTrie would process the catchpointpendinghashes and insert all the items in it into the merkle trie
func (c *catchpointCatchupAccessorImpl) BuildMerkleTrie(ctx context.Context, progressUpdates func(uint64, uint64)) (err error) {
	dbs := c.ledger.trackerDB()
	err = dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		crw, err := tx.MakeCatchpointWriter()
		if err != nil {
			return err
		}

		// creating the index can take a while, so ensure we don't generate false alerts for no good reason.
		_, err = tx.ResetTransactionWarnDeadline(ctx, time.Now().Add(120*time.Second))
		if err != nil {
			return err
		}

		return crw.CreateCatchpointStagingHashesIndex(ctx)
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

		// Note: this needs to be accessed on a snapshot to guarantee a concurrent read-only access to the sqlite db
		dbErr := dbs.Snapshot(func(transactionCtx context.Context, tx trackerdb.SnapshotScope) (err error) {
			it := tx.MakeCatchpointPendingHashesIterator(trieRebuildAccountChunkSize)
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
		if dbErr != nil {
			errChan <- dbErr
		}
	}()

	// starts the merkle trie writer
	go func() {
		defer wg.Done()
		var trie *merkletrie.Trie
		uncommitedHashesCount := 0
		keepWriting := true
		accountHashesWritten, kvHashesWritten := uint64(0), uint64(0)
		var mc trackerdb.MerkleCommitter

		txErr := dbs.Transaction(func(transactionCtx context.Context, tx trackerdb.TransactionScope) (err error) {
			// create the merkle trie for the balances
			mc, err = tx.MakeMerkleCommitter(true)
			if err != nil {
				return
			}

			trie, err = merkletrie.MakeTrie(mc, trackerdb.TrieMemoryConfig)
			return err
		})
		if txErr != nil {
			errChan <- txErr
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

			txErr = dbs.Transaction(func(transactionCtx context.Context, tx trackerdb.TransactionScope) (err error) {
				mc, err = tx.MakeMerkleCommitter(true)
				if err != nil {
					return
				}
				trie.SetCommitter(mc)
				for _, hash := range hashesToWrite {
					var added bool
					added, err = trie.Add(hash)
					if !added {
						return fmt.Errorf("CatchpointCatchupAccessorImpl::BuildMerkleTrie: The provided catchpoint file contained the same account more than once. hash = '%s' hash kind = %s", hex.EncodeToString(hash), trackerdb.HashKind(hash[trackerdb.HashKindEncodingIndex]))
					}
					if err != nil {
						return
					}

				}
				uncommitedHashesCount += len(hashesToWrite)

				accounts, kvs := countHashes(hashesToWrite)
				kvHashesWritten += kvs
				accountHashesWritten += accounts

				return nil
			})
			if txErr != nil {
				break
			}

			if uncommitedHashesCount >= trieRebuildCommitFrequency {
				txErr = dbs.Transaction(func(transactionCtx context.Context, tx trackerdb.TransactionScope) (err error) {
					// set a long 30-second window for the evict before warning is generated.
					_, err = tx.ResetTransactionWarnDeadline(transactionCtx, time.Now().Add(30*time.Second))
					if err != nil {
						return
					}
					mc, err = tx.MakeMerkleCommitter(true)
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
				if txErr != nil {
					keepWriting = false
					continue
				}
			}

			if progressUpdates != nil {
				progressUpdates(accountHashesWritten, kvHashesWritten)
			}
		}
		if txErr != nil {
			errChan <- txErr
			return
		}
		if uncommitedHashesCount > 0 {
			txErr = dbs.Transaction(func(transactionCtx context.Context, tx trackerdb.TransactionScope) (err error) {
				// set a long 30-second window for the evict before warning is generated.
				_, err = tx.ResetTransactionWarnDeadline(transactionCtx, time.Now().Add(30*time.Second))
				if err != nil {
					return
				}
				mc, err = tx.MakeMerkleCommitter(true)
				if err != nil {
					return
				}
				trie.SetCommitter(mc)
				_, err = trie.Evict(true)
				return
			})
		}

		if txErr != nil {
			errChan <- txErr
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
func (c *catchpointCatchupAccessorImpl) GetCatchupBlockRound(ctx context.Context) (round basics.Round, err error) {
	var iRound uint64
	iRound, err = c.catchpointStore.ReadCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupBlockRound)
	if err != nil {
		return 0, fmt.Errorf("unable to read catchpoint catchup state '%s': %v", trackerdb.CatchpointStateCatchpointLookback, err)
	}
	return basics.Round(iRound), nil
}

func (c *catchpointCatchupAccessorImpl) GetVerifyData(ctx context.Context) (balancesHash crypto.Digest, spverHash crypto.Digest, totals ledgercore.AccountTotals, err error) {
	var rawStateProofVerificationContext []ledgercore.StateProofVerificationContext

	err = c.ledger.trackerDB().Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		ar, err := tx.MakeAccountsReader()
		if err != nil {
			return err
		}

		// create the merkle trie for the balances
		mc, err0 := tx.MakeMerkleCommitter(true)
		if err0 != nil {
			return fmt.Errorf("unable to make MerkleCommitter: %v", err0)
		}
		var trie *merkletrie.Trie
		trie, err = merkletrie.MakeTrie(mc, trackerdb.TrieMemoryConfig)
		if err != nil {
			return fmt.Errorf("unable to make trie: %v", err)
		}

		balancesHash, err = trie.RootHash()
		if err != nil {
			return fmt.Errorf("unable to get trie root hash: %v", err)
		}

		totals, err = ar.AccountsTotals(ctx, true)
		if err != nil {
			return fmt.Errorf("unable to get accounts totals: %v", err)
		}

		rawStateProofVerificationContext, err = tx.MakeSpVerificationCtxReader().GetAllSPContextsFromCatchpointTbl(ctx)
		if err != nil {
			return fmt.Errorf("unable to get state proof verification data: %v", err)
		}

		return
	})
	if err != nil {
		return crypto.Digest{}, crypto.Digest{}, ledgercore.AccountTotals{}, err
	}

	wrappedContext := catchpointStateProofVerificationContext{Data: rawStateProofVerificationContext}
	spverHash = crypto.HashObj(wrappedContext)

	return balancesHash, spverHash, totals, err
}

// VerifyCatchpoint verifies that the catchpoint is valid by reconstructing the label.
func (c *catchpointCatchupAccessorImpl) VerifyCatchpoint(ctx context.Context, blk *bookkeeping.Block) (err error) {
	var blockRound basics.Round
	var catchpointLabel string
	var version uint64

	catchpointLabel, err = c.catchpointStore.ReadCatchpointStateString(ctx, trackerdb.CatchpointStateCatchupLabel)
	if err != nil {
		return fmt.Errorf("unable to read catchpoint catchup state '%s': %v", trackerdb.CatchpointStateCatchupLabel, err)
	}

	version, err = c.catchpointStore.ReadCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupVersion)
	if err != nil {
		return fmt.Errorf("unable to retrieve catchpoint version: %v", err)
	}

	var iRound uint64
	iRound, err = c.catchpointStore.ReadCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupBlockRound)
	if err != nil {
		return fmt.Errorf("unable to read catchpoint catchup state '%s': %v", trackerdb.CatchpointStateCatchupBlockRound, err)
	}
	blockRound = basics.Round(iRound)

	start := time.Now()
	ledgerVerifycatchpointCount.Inc(nil)
	balancesHash, spVerificationHash, totals, err := c.GetVerifyData(ctx)
	ledgerVerifycatchpointMicros.AddMicrosecondsSince(start, nil)
	if err != nil {
		return err
	}
	if blockRound != blk.Round() {
		return fmt.Errorf("block round in block header doesn't match block round in catchpoint:  %d != %d", blockRound, blk.Round())
	}

	var catchpointLabelMaker ledgercore.CatchpointLabelMaker
	blockDigest := blk.Digest()
	if version <= CatchpointFileVersionV6 {
		catchpointLabelMaker = ledgercore.MakeCatchpointLabelMakerV6(blockRound, &blockDigest, &balancesHash, totals)
	} else {
		catchpointLabelMaker = ledgercore.MakeCatchpointLabelMakerCurrent(blockRound, &blockDigest, &balancesHash, totals, &spVerificationHash)
	}
	generatedLabel := ledgercore.MakeLabel(catchpointLabelMaker)

	if catchpointLabel != generatedLabel {
		return fmt.Errorf("catchpoint hash mismatch; expected %s, calculated %s", catchpointLabel, generatedLabel)
	}
	return nil
}

// StoreBalancesRound calculates the balances round based on the first block and the associated consensus parameters, and
// store that to the database
func (c *catchpointCatchupAccessorImpl) StoreBalancesRound(ctx context.Context, blk *bookkeeping.Block) (err error) {
	// calculate the balances round and store it. It *should* be identical to the one in the catchpoint file header, but we don't want to
	// trust the one in the catchpoint file header, so we'll calculate it ourselves.
	catchpointLookback := config.Consensus[blk.CurrentProtocol].CatchpointLookback
	if catchpointLookback == 0 {
		catchpointLookback = config.Consensus[blk.CurrentProtocol].MaxBalLookback
	}
	balancesRound := blk.Round() - basics.Round(catchpointLookback)
	start := time.Now()
	ledgerStorebalancesroundCount.Inc(nil)
	err = c.ledger.trackerDB().Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		crw, err := tx.MakeCatchpointWriter()
		if err != nil {
			return err
		}

		err = crw.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupBalancesRound, uint64(balancesRound))
		if err != nil {
			return fmt.Errorf("CatchpointCatchupAccessorImpl::StoreBalancesRound: unable to write catchpoint catchup state '%s': %v", trackerdb.CatchpointStateCatchupBalancesRound, err)
		}
		return
	})
	ledgerStorebalancesroundMicros.AddMicrosecondsSince(start, nil)
	return
}

// StoreFirstBlock stores a single block to the blocks database.
func (c *catchpointCatchupAccessorImpl) StoreFirstBlock(ctx context.Context, blk *bookkeeping.Block, cert *agreement.Certificate) (err error) {
	blockDbs := c.ledger.blockDB()
	start := time.Now()
	ledgerStorefirstblockCount.Inc(nil)
	err = blockDbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		return blockdb.BlockStartCatchupStaging(tx, *blk, *cert)
	})
	ledgerStorefirstblockMicros.AddMicrosecondsSince(start, nil)
	if err != nil {
		return err
	}
	return nil
}

// StoreBlock stores a single block to the blocks database.
func (c *catchpointCatchupAccessorImpl) StoreBlock(ctx context.Context, blk *bookkeeping.Block, cert *agreement.Certificate) (err error) {
	blockDbs := c.ledger.blockDB()
	start := time.Now()
	ledgerCatchpointStoreblockCount.Inc(nil)
	err = blockDbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) (err error) {
		return blockdb.BlockPutStaging(tx, *blk, *cert)
	})
	ledgerCatchpointStoreblockMicros.AddMicrosecondsSince(start, nil)
	if err != nil {
		return err
	}
	return nil
}

// FinishBlocks concludes the catchup of the blocks database.
func (c *catchpointCatchupAccessorImpl) FinishBlocks(ctx context.Context, applyChanges bool) (err error) {
	blockDbs := c.ledger.blockDB()
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
func (c *catchpointCatchupAccessorImpl) EnsureFirstBlock(ctx context.Context) (blk bookkeeping.Block, err error) {
	blockDbs := c.ledger.blockDB()
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
func (c *catchpointCatchupAccessorImpl) CompleteCatchup(ctx context.Context) (err error) {
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
func (c *catchpointCatchupAccessorImpl) finishBalances(ctx context.Context) (err error) {
	start := time.Now()
	ledgerCatchpointFinishBalsCount.Inc(nil)
	err = c.ledger.trackerDB().Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		crw, err := tx.MakeCatchpointReaderWriter()
		if err != nil {
			return err
		}

		ar, err := tx.MakeAccountsReader()
		if err != nil {
			return err
		}

		aw, err := tx.MakeAccountsWriter()
		if err != nil {
			return err
		}

		var balancesRound, hashRound uint64
		var totals ledgercore.AccountTotals

		balancesRound, err = crw.ReadCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupBalancesRound)
		if err != nil {
			return err
		}

		hashRound, err = crw.ReadCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupHashRound)
		if err != nil {
			return err
		}

		totals, err = ar.AccountsTotals(ctx, true)
		if err != nil {
			return err
		}

		if hashRound == 0 {
			err = aw.ResetAccountHashes(ctx)
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
		err = aw.AccountsReset(ctx)
		if err != nil {
			return err
		}
		{
			tp := trackerdb.Params{
				InitAccounts:      c.ledger.GenesisAccounts(),
				InitProto:         c.ledger.GenesisProtoVersion(),
				GenesisHash:       c.ledger.GenesisHash(),
				FromCatchpoint:    true,
				CatchpointEnabled: c.ledger.catchpoint.catchpointEnabled(),
				DbPathPrefix:      c.ledger.catchpoint.dbDirectory,
				BlockDb:           c.ledger.blockDBs,
			}
			_, err = tx.RunMigrations(ctx, tp, c.ledger.log, 6 /*target database version*/)
			if err != nil {
				return err
			}
		}

		err = crw.ApplyCatchpointStagingBalances(ctx, basics.Round(balancesRound), basics.Round(hashRound))
		if err != nil {
			return err
		}

		err = aw.AccountsPutTotals(totals, false)
		if err != nil {
			return err
		}

		err = crw.ResetCatchpointStagingBalances(ctx, false)
		if err != nil {
			return err
		}

		err = crw.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupBalancesRound, 0)
		if err != nil {
			return err
		}

		err = crw.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupBlockRound, 0)
		if err != nil {
			return err
		}

		err = crw.WriteCatchpointStateString(ctx, trackerdb.CatchpointStateCatchupLabel, "")
		if err != nil {
			return err
		}

		if hashRound != 0 {
			err = crw.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupHashRound, 0)
			if err != nil {
				return err
			}
		}

		err = crw.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateCatchupState, 0)
		if err != nil {
			return fmt.Errorf("unable to write catchpoint catchup state '%s': %v", trackerdb.CatchpointStateCatchupState, err)
		}

		return
	})
	ledgerCatchpointFinishBalsMicros.AddMicrosecondsSince(start, nil)
	return err
}

// Ledger returns ledger instance as CatchupAccessorClientLedger interface
func (c *catchpointCatchupAccessorImpl) Ledger() (l CatchupAccessorClientLedger) {
	return c.ledger
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
