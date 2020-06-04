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
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

const (
	// balancesFlushInterval defines how frequently we want to flush our balances to disk.
	balancesFlushInterval = 5 * time.Second
	// pendingDeltasFlushThreshold is the deltas count threshold above we flush the pending balances regardless of the flush interval.
	pendingDeltasFlushThreshold = 128
	// trieRebuildAccountChunkSize defines the number of accounts that would get read at a single chunk
	// before added to the trie during trie construction
	trieRebuildAccountChunkSize = 512
)

// trieCachedNodesCount defines how many balances trie nodes we would like to keep around in memory.
// value was calibrated using BenchmarkCalibrateCacheNodeSize
var trieCachedNodesCount = 9000

// A modifiedAccount represents an account that has been modified since
// the persistent state stored in the account DB (i.e., in the range of
// rounds covered by the accountUpdates tracker).
type modifiedAccount struct {
	// data stores the most recent AccountData for this modified
	// account.
	data basics.AccountData

	// ndelta keeps track of how many times this account appears in
	// accountUpdates.deltas.  This is used to evict modifiedAccount
	// entries when all changes to an account have been reflected in
	// the account DB, and no outstanding modifications remain.
	ndeltas int
}

type modifiedAsset struct {
	// Created if true, deleted if false
	created bool

	// Creator is the creator of the asset
	creator basics.Address

	// Keeps track of how many times this asset appears in
	// accountUpdates.assetDeltas
	ndeltas int
}

type accountUpdates struct {
	// constant variables ( initialized on initialize, and never changed afterward )

	// initAccounts specifies initial account values for database.
	initAccounts map[basics.Address]basics.AccountData

	// initProto specifies the initial consensus parameters.
	initProto config.ConsensusParams

	// dbDirectory is the directory where the ledger and block sql file resides as well as the parent directroy for the catchup files to be generated
	dbDirectory string

	// catchpointInterval is the configured interval at which the accountUpdates would generate catchpoint labels and catchpoint files.
	catchpointInterval uint64

	// archivalLedger determines whether the associated ledger was configured as archival ledger or not.
	archivalLedger bool

	// catchpointFileHistoryLength defines how many catchpoint files we want to store back.
	// 0 means don't store any, -1 mean unlimited and positive number suggest the number of most recent catchpoint files.
	catchpointFileHistoryLength int

	// dynamic variables

	// Connection to the database.
	dbs dbPair

	// Prepared SQL statements for fast accounts DB lookups.
	accountsq *accountsDbQueries

	// dbRound is always exactly accountsRound(),
	// cached to avoid SQL queries.
	dbRound basics.Round

	// deltas stores updates for every round after dbRound.
	deltas []map[basics.Address]accountDelta

	// accounts stores the most recent account state for every
	// address that appears in deltas.
	accounts map[basics.Address]modifiedAccount

	// assetDeltas stores asset updates for every round after dbRound.
	assetDeltas []map[basics.AssetIndex]modifiedAsset

	// assets stores the most recent asset state for every asset
	// that appears in assetDeltas
	assets map[basics.AssetIndex]modifiedAsset

	// protos stores consensus parameters dbRound and every
	// round after it; i.e., protos is one longer than deltas.
	protos []config.ConsensusParams

	// totals stores the totals for dbRound and every round after it;
	// i.e., totals is one longer than deltas.
	roundTotals []AccountTotals

	// roundDigest stores the digest of the block for every round starting with dbRound and every round after it.
	roundDigest []crypto.Digest

	// log copied from ledger
	log logging.Logger

	// lastFlushTime is the time we last flushed updates to
	// the accounts DB (bumping dbRound).
	lastFlushTime time.Time

	// ledger is the source ledger, which is used to syncronize
	// the rounds at which we need to flush the balances to disk
	// in favor of the catchpoint to be generated.
	ledger ledgerForTracker

	// The Trie tracking the current account balances. Always matches the balances that were
	// written to the database.
	balancesTrie *merkletrie.Trie

	// The last catchpoint label that was writted to the database. Should always align with what's in the database.
	// note that this is the last catchpoint *label* and not the catchpoint file.
	lastCatchpointLabel string

	// catchpointWriting help to syncronize the catchpoint file writing. When this channel is closed, no writting is going on.
	// the channel is non-closed while writing the current accounts state to disk.
	catchpointWriting chan struct{}

	// catchpointSlowWriting suggest to the accounts writer that it should finish writing up the catchpoint file ASAP.
	// when this channel is closed, the accounts writer would try and complete the writing as soon as possible.
	// otherwise, it would take it's time and perform periodic sleeps between chunks processing.
	catchpointSlowWriting chan struct{}

	// ctx is the context for canceling any pending catchpoint generation operation
	ctx context.Context

	// ctxCancel is the canceling function canceling any pending catchpoint generation operation
	ctxCancel context.CancelFunc

	// deltasAccum stores the accumulated deltas for every round starting dbRound-1.
	deltasAccum []int

	// committedOffset is the offset at which we'd like to persist all the previous account information to disk.
	committedOffset chan deferedCommit

	// accountsMu is the syncronization mutex for accessing the various non-static varaibles.
	accountsMu deadlock.RWMutex

	// accountsWriting provides syncronization around the background writing of account balances.
	accountsWriting sync.WaitGroup
}

type deferedCommit struct {
	offset   uint64
	dbRound  basics.Round
	lookback basics.Round
}

// initialize initializes the accountUpdates structure
func (au *accountUpdates) initialize(cfg config.Local, dbPathPrefix string, genesisProto config.ConsensusParams, genesisAccounts map[basics.Address]basics.AccountData) {
	au.initProto = genesisProto
	au.initAccounts = genesisAccounts
	au.dbDirectory = filepath.Dir(dbPathPrefix)
	au.archivalLedger = cfg.Archival
	au.catchpointInterval = cfg.CatchpointInterval
	au.catchpointFileHistoryLength = cfg.CatchpointFileHistoryLength
	if cfg.CatchpointFileHistoryLength < -1 {
		au.catchpointFileHistoryLength = -1
	}
}

// loadFromDisk is the 2nd level initializtion, and is required before the accountUpdates becomes functional
// The close function is expected to be call in pair with loadFromDisk
func (au *accountUpdates) loadFromDisk(l ledgerForTracker) error {
	var writingCatchpointRound uint64
	lastBalancesRound, lastestBlockRound, err := au.initializeFromDisk(l)

	if err != nil {
		return err
	}

	var writingCatchpointDigest crypto.Digest

	writingCatchpointRound, _, err = au.accountsq.readCatchpointStateUint64(context.Background(), catchpointStateWritingCatchpoint)
	if err != nil {
		au.accountsMu.Unlock()
		return err
	}

	writingCatchpointDigest, err = au.initializeCaches(lastBalancesRound, lastestBlockRound, basics.Round(writingCatchpointRound))

	if writingCatchpointRound != 0 && au.catchpointInterval != 0 {
		au.generateCatchpoint(basics.Round(writingCatchpointRound), au.lastCatchpointLabel, writingCatchpointDigest)
	}

	return nil
}

// waitAccountsWriting waits for all the pending ( or current ) account writing to be completed.
func (au *accountUpdates) waitAccountsWriting() {
	au.accountsWriting.Wait()
}

func (au *accountUpdates) close() {
	if au.ctxCancel != nil {
		au.ctxCancel()
	}
	au.waitAccountsWriting()
}

func (au *accountUpdates) lookup(rnd basics.Round, addr basics.Address, withRewards bool) (data basics.AccountData, err error) {
	au.accountsMu.RLock()
	defer au.accountsMu.RUnlock()
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return
	}

	offsetForRewards := offset

	defer func() {
		if withRewards {
			totals := au.roundTotals[offsetForRewards]
			proto := au.protos[offsetForRewards]
			data = data.WithUpdatedRewards(proto, totals.RewardsLevel)
		}
	}()

	// Check if this is the most recent round, in which case, we can
	// use a cache of the most recent account state.
	if offset == uint64(len(au.deltas)) {
		macct, ok := au.accounts[addr]
		if ok {
			return macct.data, nil
		}
	} else {
		// Check if the account has been updated recently.  Traverse the deltas
		// backwards to ensure that later updates take priority if present.
		for offset > 0 {
			offset--
			d, ok := au.deltas[offset][addr]
			if ok {
				return d.new, nil
			}
		}
	}

	// No updates of this account in the in-memory deltas; use on-disk DB.
	// The check in roundOffset() made sure the round is exactly the one
	// present in the on-disk DB.  As an optimization, we avoid creating
	// a separate transaction here, and directly use a prepared SQL query
	// against the database.
	return au.accountsq.lookup(addr)
}

func (au *accountUpdates) listAssets(maxAssetIdx basics.AssetIndex, maxResults uint64) ([]basics.CreatableLocator, error) {
	au.accountsMu.RLock()
	defer au.accountsMu.RUnlock()

	// Sort indices for assets that have been created/deleted. If this
	// turns out to be too inefficient, we could keep around a heap of
	// created/deleted asset indices in memory.
	keys := make([]basics.AssetIndex, 0, len(au.assets))
	for aidx := range au.assets {
		if aidx <= maxAssetIdx {
			keys = append(keys, aidx)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] > keys[j] })

	// Check for assets that haven't been synced to disk yet.
	var unsyncedAssets []basics.CreatableLocator
	deletedAssets := make(map[basics.AssetIndex]bool)
	for _, aidx := range keys {
		delta := au.assets[aidx]
		if delta.created {
			// Created asset that only exists in memory
			unsyncedAssets = append(unsyncedAssets, basics.CreatableLocator{
				Index:   basics.CreatableIndex(aidx),
				Creator: delta.creator,
			})
		} else {
			// Mark deleted assets for exclusion from the results set
			deletedAssets[aidx] = true
		}
	}

	// Check in-memory created assets, which will always be newer than anything
	// in the database
	var res []basics.CreatableLocator
	for _, loc := range unsyncedAssets {
		if uint64(len(res)) == maxResults {
			return res, nil
		}
		res = append(res, loc)
	}

	// Fetch up to maxResults - len(res) + len(deletedAssets) from the database, so we
	// have enough extras in case assets were deleted
	numToFetch := maxResults - uint64(len(res)) + uint64(len(deletedAssets))
	dbResults, err := au.accountsq.listAssets(maxAssetIdx, numToFetch)
	if err != nil {
		return nil, err
	}

	// Now we merge the database results with the in-memory results
	for _, loc := range dbResults {
		// Check if we have enough results
		if uint64(len(res)) == maxResults {
			return res, nil
		}

		// Asset was deleted
		if _, ok := deletedAssets[basics.AssetIndex(loc.Index)]; ok {
			continue
		}

		// We're OK to include this result
		res = append(res, loc)
	}

	return res, nil
}

// getLastCatchpointLabel retrieves the last catchpoint label that was stored to the database.
func (au *accountUpdates) getLastCatchpointLabel() string {
	au.accountsMu.RLock()
	defer au.accountsMu.RUnlock()
	return au.lastCatchpointLabel
}

// getAssetCreatorForRound returns the asset creator for a given asset index at a given round
func (au *accountUpdates) getAssetCreatorForRound(rnd basics.Round, aidx basics.AssetIndex) (basics.Address, error) {
	au.accountsMu.RLock()
	defer au.accountsMu.RUnlock()
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return basics.Address{}, err
	}

	// If this is the most recent round, au.assets has will have the latest
	// state and we can skip scanning backwards over assetDeltas
	if offset == uint64(len(au.deltas)) {
		// Check if we already have the asset/creator in cache
		assetDelta, ok := au.assets[aidx]
		if ok {
			if assetDelta.created {
				return assetDelta.creator, nil
			}
			return basics.Address{}, fmt.Errorf("asset %v has been deleted", aidx)
		}
	} else {
		for offset > 0 {
			offset--
			assetDelta, ok := au.assetDeltas[offset][aidx]
			if ok {
				if assetDelta.created {
					return assetDelta.creator, nil
				}
				return basics.Address{}, fmt.Errorf("asset %v has been deleted", aidx)
			}
		}
	}

	// Check the database
	return au.accountsq.lookupAssetCreator(aidx)
}

// committedUpTo enqueues commiting the balances for round committedRound-lookback.
// The defered committing is done so that we could calculate the historical balances lookback rounds back.
// Since we don't want to hold off the tracker's mutex for too long, we'll defer the database persistance of this
// operation to a syncer goroutine. The one caviat is that when storing a catchpoint round, we would want to
// wait until the catchpoint creation is done, so that the persistance of the catchpoint file would have an
// uninterrupted view of the balances at a given point of time.
func (au *accountUpdates) committedUpTo(committedRound basics.Round) (retRound basics.Round) {
	var isCatchpointRound, hasMultipleIntermediateCatchpoint bool
	var offset uint64
	var dc deferedCommit
	au.accountsMu.RLock()
	defer func() {
		au.accountsMu.RUnlock()
		if dc.offset != 0 {
			au.committedOffset <- dc
		}
	}()

	retRound = basics.Round(0)
	var pendingDeltas int

	lookback := basics.Round(au.protos[len(au.protos)-1].MaxBalLookback)
	if committedRound < lookback {
		return
	}

	retRound = au.dbRound
	newBase := committedRound - lookback
	if newBase <= au.dbRound {
		// Already forgotten
		return
	}

	if newBase > au.dbRound+basics.Round(len(au.deltas)) {
		au.log.Panicf("committedUpTo: block %d too far in the future, lookback %d, dbRound %d, deltas %d", committedRound, lookback, au.dbRound, len(au.deltas))
	}

	hasIntermediateCatchpoint := false
	hasMultipleIntermediateCatchpoint = false
	// check if there was a catchpoint between au.dbRound+lookback and newBase+lookback
	if au.catchpointInterval > 0 {
		nextCatchpointRound := ((uint64(au.dbRound+lookback) + au.catchpointInterval) / au.catchpointInterval) * au.catchpointInterval

		if nextCatchpointRound < uint64(newBase+lookback) {
			mostRecentCatchpointRound := (uint64(committedRound) / au.catchpointInterval) * au.catchpointInterval
			newBase = basics.Round(nextCatchpointRound) - lookback
			if mostRecentCatchpointRound > nextCatchpointRound {
				hasMultipleIntermediateCatchpoint = true
				// skip if there is more than one catchpoint in queue
				newBase = basics.Round(mostRecentCatchpointRound) - lookback
			}
			hasIntermediateCatchpoint = true
		}
	}

	// if we're still writing the previous balances, we can't move forward yet.
	select {
	case <-au.catchpointWriting:
		// the channel catchpointWriting is currently closed, meaning that we're currently not writing any
		// catchpoint file. At this point, we should attempt to enqueue further tasks as usual.
	default:
		// if we hit this path, it means that the channel is currently non-closed, which means that we're still writing a catchpoint.
		// see if we're writing a catchpoint in that range.
		if hasIntermediateCatchpoint {
			// check if we're already attempting to perform fast-writing.
			select {
			case <-au.catchpointSlowWriting:
				// yes, we're already doing fast-writing.
			default:
				// no, we're not yet doing fast writing, make it so.
				close(au.catchpointSlowWriting)
			}
		}
		return
	}

	offset = uint64(newBase - au.dbRound)

	// check to see if this is a catchpoint round
	isCatchpointRound = ((offset + uint64(lookback+au.dbRound)) > 0) && (au.catchpointInterval != 0) && (0 == (uint64((offset + uint64(lookback+au.dbRound))) % au.catchpointInterval))

	// calculate the number of pending deltas
	pendingDeltas = au.deltasAccum[offset] - au.deltasAccum[0]

	// If we recently flushed, wait to aggregate some more blocks.
	// ( unless we're creating a catchpoint, in which case we want to flush it right away
	//   so that all the instances of the catchpoint would contain the exacy same data )
	flushTime := time.Now()
	if !flushTime.After(au.lastFlushTime.Add(balancesFlushInterval)) && !isCatchpointRound && pendingDeltas < pendingDeltasFlushThreshold {
		return au.dbRound
	}

	if isCatchpointRound && au.archivalLedger {
		au.catchpointWriting = make(chan struct{}, 1)
		au.catchpointSlowWriting = make(chan struct{}, 1)
		if hasMultipleIntermediateCatchpoint {
			close(au.catchpointSlowWriting)
		}
	}

	dc = deferedCommit{
		offset:   offset,
		dbRound:  au.dbRound,
		lookback: lookback,
	}
	au.accountsWriting.Add(1)
	return
}

func (au *accountUpdates) newBlock(blk bookkeeping.Block, delta StateDelta) {
	au.accountsMu.Lock()
	defer au.accountsMu.Unlock()

	proto := config.Consensus[blk.CurrentProtocol]
	rnd := blk.Round()

	if rnd <= au.latest() {
		// Duplicate, ignore.
		return
	}

	if rnd != au.latest()+1 {
		au.log.Panicf("accountUpdates: newBlock %d too far in the future, dbRound %d, deltas %d", rnd, au.dbRound, len(au.deltas))
	}
	au.deltas = append(au.deltas, delta.accts)
	au.protos = append(au.protos, proto)
	au.assetDeltas = append(au.assetDeltas, delta.assets)
	au.roundDigest = append(au.roundDigest, blk.Digest())
	au.deltasAccum = append(au.deltasAccum, len(delta.accts)+au.deltasAccum[len(au.deltasAccum)-1])

	var ot basics.OverflowTracker
	newTotals := au.roundTotals[len(au.roundTotals)-1]
	allBefore := newTotals.All()
	newTotals.applyRewards(delta.hdr.RewardsLevel, &ot)

	for addr, data := range delta.accts {
		newTotals.delAccount(proto, data.old, &ot)
		newTotals.addAccount(proto, data.new, &ot)

		macct := au.accounts[addr]
		macct.ndeltas++
		macct.data = data.new
		au.accounts[addr] = macct
	}

	for aidx, adelta := range delta.assets {
		masset := au.assets[aidx]
		masset.creator = adelta.creator
		masset.created = adelta.created
		masset.ndeltas++
		au.assets[aidx] = masset
	}

	if ot.Overflowed {
		au.log.Panicf("accountUpdates: newBlock %d overflowed totals", rnd)
	}
	allAfter := newTotals.All()
	if allBefore != allAfter {
		au.log.Panicf("accountUpdates: sum of money changed from %d to %d", allBefore.Raw, allAfter.Raw)
	}

	au.roundTotals = append(au.roundTotals, newTotals)
}

func (au *accountUpdates) totals(rnd basics.Round) (totals AccountTotals, err error) {
	au.accountsMu.RLock()
	defer au.accountsMu.RUnlock()
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return
	}

	totals = au.roundTotals[offset]
	return
}

func (au *accountUpdates) getCatchpointStream(round basics.Round) (io.ReadCloser, error) {
	dbFileName := ""
	err := au.dbs.rdb.Atomic(func(tx *sql.Tx) (err error) {
		dbFileName, _, _, err = getCatchpoint(tx, round)
		return
	})
	if err != nil && err != sql.ErrNoRows {
		// we had some sql error.
		return nil, fmt.Errorf("accountUpdates: getCatchpointStream: unable to lookup catchpoint %d: %v", round, err)
	}
	if dbFileName != "" {
		catchpointPath := filepath.Join(au.dbDirectory, dbFileName)
		file, err := os.OpenFile(catchpointPath, os.O_RDONLY, 0666)
		if err == nil && file != nil {
			return file, nil
		}
		// else, see if this is a file-not-found error
		if os.IsNotExist(err) {
			// the database told us that we have this file.. but we couldn't find it.
			// delete it from the database.
			err := au.saveCatchpointFile(round, "", 0, "")
			if err != nil {
				au.log.Warnf("accountUpdates: getCatchpointStream: unable to delete missing catchpoint entry: %v", err)
				return nil, err
			}

			return nil, ErrNoEntry{}
		}
		// it's some other error.
		return nil, fmt.Errorf("accountUpdates: getCatchpointStream: unable to open catchpoint file '%s' %v", catchpointPath, err)
	}

	// if the database doesn't know about that round, see if we have that file anyway:
	fileName := filepath.Join("catchpoints", catchpointRoundToPath(round))
	catchpointPath := filepath.Join(au.dbDirectory, fileName)
	file, err := os.OpenFile(catchpointPath, os.O_RDONLY, 0666)
	if err == nil && file != nil {
		// great, if found that we should have had this in the database.. add this one now :
		fileInfo, err := file.Stat()
		if err != nil {
			// we couldn't get the stat, so just return with the file.
			return file, nil
		}

		err = au.saveCatchpointFile(round, fileName, fileInfo.Size(), "")
		if err != nil {
			au.log.Warnf("accountUpdates: getCatchpointStream: unable to save missing catchpoint entry: %v", err)
		}
		return file, nil
	}
	return nil, ErrNoEntry{}
}

// functions below this line are all internal functions

// initializeCaches fills up the accountUpdates cache with the most recent ~320 blocks
func (au *accountUpdates) initializeCaches(lastBalancesRound, lastestBlockRound, writingCatchpointRound basics.Round) (catchpointBlockDigest crypto.Digest, err error) {
	var blk bookkeeping.Block
	var delta StateDelta

	for lastBalancesRound < lastestBlockRound {
		next := lastBalancesRound + 1

		blk, err = au.ledger.Block(next)
		if err != nil {
			return
		}

		delta, err = au.ledger.trackerEvalVerified(blk)
		if err != nil {
			return
		}

		au.newBlock(blk, delta)
		lastBalancesRound = next

		if next == basics.Round(writingCatchpointRound) {
			catchpointBlockDigest = blk.Digest()
		}
	}
	return
}

// initializeFromDisk performs the atomic operation of loading the accounts data information from disk
// and preparing the accountUpdates for operation, including initlizating the commitSyncer goroutine.
func (au *accountUpdates) initializeFromDisk(l ledgerForTracker) (lastBalancesRound, lastestBlockRound basics.Round, err error) {
	au.accountsMu.Lock()
	defer au.accountsMu.Unlock()

	au.dbs = l.trackerDB()
	au.log = l.trackerLog()
	au.ledger = l

	if au.initAccounts == nil {
		err = fmt.Errorf("accountUpdates.loadFromDisk: initAccounts not set")
		return
	}

	lastestBlockRound = l.Latest()
	err = au.dbs.wdb.Atomic(func(tx *sql.Tx) error {
		var err0 error
		au.dbRound, err0 = au.accountsInitialize(tx)
		if err0 != nil {
			return err0
		}
		// Check for blocks DB and tracker DB un-sync
		if au.dbRound > lastestBlockRound {
			au.log.Warnf("resetting accounts DB (on round %v, but blocks DB's latest is %v)", au.dbRound, lastestBlockRound)
			err0 = accountsReset(tx)
			if err0 != nil {
				return err0
			}
			au.dbRound, err0 = au.accountsInitialize(tx)
			if err0 != nil {
				return err0
			}
		}

		totals, err0 := accountsTotals(tx, false)
		if err0 != nil {
			return err0
		}

		au.roundTotals = []AccountTotals{totals}
		return nil
	})
	if err != nil {
		return
	}

	au.accountsq, err = accountsDbInit(au.dbs.rdb.Handle, au.dbs.wdb.Handle)
	if err != nil {
		return
	}

	au.lastCatchpointLabel, _, err = au.accountsq.readCatchpointStateString(context.Background(), catchpointStateLastCatchpoint)
	if err != nil {
		return
	}

	hdr, err := l.BlockHdr(au.dbRound)
	if err != nil {
		return
	}
	au.protos = []config.ConsensusParams{config.Consensus[hdr.CurrentProtocol]}
	au.deltas = nil
	au.assetDeltas = nil
	au.accounts = make(map[basics.Address]modifiedAccount)
	au.assets = make(map[basics.AssetIndex]modifiedAsset)
	au.deltasAccum = []int{0}

	// keep these channel closed if we're not generating catchpoint
	au.catchpointWriting = make(chan struct{}, 1)
	au.catchpointSlowWriting = make(chan struct{}, 1)
	close(au.catchpointSlowWriting)
	close(au.catchpointWriting)
	au.ctx, au.ctxCancel = context.WithCancel(context.Background())
	au.committedOffset = make(chan deferedCommit, 1)
	go au.commitSyncer(au.committedOffset)

	lastBalancesRound = au.dbRound

	return
}

// accountHashBuilder calculates the hash key used for the trie by combining the account address and the account data
func accountHashBuilder(addr basics.Address, accountData basics.AccountData, encodedAccountData []byte) []byte {
	hash := make([]byte, 4+crypto.DigestSize)
	// write out the lowest 32 bits of the reward base. This should improve the caching of the trie by allowing
	// recent updated to be in-cache, and "older" nodes will be left alone.
	for i, rewards := 3, accountData.RewardsBase; i >= 0; i, rewards = i-1, rewards>>8 {
		// the following takes the rewards & 255 -> hash[i]
		hash[i] = byte(rewards)
	}
	entryHash := crypto.Hash(append(addr[:], encodedAccountData[:]...))
	copy(hash[4:], entryHash[:])
	return hash[:]
}

// Initialize accounts DB if needed and return account round
func (au *accountUpdates) accountsInitialize(tx *sql.Tx) (basics.Round, error) {
	err := accountsInit(tx, au.initAccounts, au.initProto)
	if err != nil {
		return 0, err
	}

	rnd, hashRound, err := accountsRound(tx)
	if err != nil {
		return 0, err
	}

	if hashRound != rnd {
		// if the hashed round is different then the base round, something was modified, and the accounts aren't in sync
		// with the hashes.
		err = resetAccountHashes(tx)
		if err != nil {
			return 0, err
		}
		// if catchpoint is disabled on this node, we could complete the initialization right here.
		if au.catchpointInterval == 0 {
			return rnd, nil
		}
	}

	// create the merkle trie for the balances
	committer, err := makeMerkleCommitter(tx, false)
	if err != nil {
		return 0, fmt.Errorf("accountsInitialize was unable to makeMerkleCommitter: %v", err)
	}
	trie, err := merkletrie.MakeTrie(committer, trieCachedNodesCount)
	if err != nil {
		return 0, fmt.Errorf("accountsInitialize was unable to MakeTrie: %v", err)
	}

	// we migth have a database that was previously initialized, and now we're adding the balances trie. In that case, we need to add all the existing balances to this trie.
	// we can figure this out by examinine the hash of the root:
	rootHash, err := trie.RootHash()
	if err != nil {
		return rnd, fmt.Errorf("accountsInitialize was unable to retrieve trie root hash: %v", err)
	}
	if rootHash.IsZero() {
		accountIdx := 0
		for {
			bal, err := encodedAccountsRange(tx, accountIdx, trieRebuildAccountChunkSize)
			if err != nil {
				return rnd, err
			}
			if len(bal) == 0 {
				break
			}
			for _, balance := range bal {
				var accountData basics.AccountData
				err = protocol.Decode(balance.AccountData, &accountData)
				if err != nil {
					return rnd, err
				}
				hash := accountHashBuilder(balance.Address, accountData, balance.AccountData)
				added, err := trie.Add(hash)
				if err != nil {
					return rnd, fmt.Errorf("accountsInitialize was unable to add changes to trie: %v", err)
				}
				if !added {
					au.log.Warnf("attempted to add duplicate hash '%v' to merkle trie.", hash)
				}
			}

			// this trie Evict will commit using the current transaction.
			// if anything goes wrong, it will still get rolled back.
			_, err = trie.Evict(true)
			if err != nil {
				return 0, fmt.Errorf("accountsInitialize was unable to commit changes to trie: %v", err)
			}
			if len(bal) < trieRebuildAccountChunkSize {
				break
			}
			accountIdx += trieRebuildAccountChunkSize
		}
	}
	au.balancesTrie = trie
	return rnd, nil
}

func (au *accountUpdates) accountsUpdateBalances(accountsDeltas map[basics.Address]accountDelta) (err error) {
	if au.catchpointInterval == 0 {
		return nil
	}
	var added, deleted bool
	for addr, delta := range accountsDeltas {
		if !delta.old.IsZero() {
			deleteHash := accountHashBuilder(addr, delta.old, protocol.Encode(&delta.old))
			deleted, err = au.balancesTrie.Delete(deleteHash)
			if err != nil {
				return err
			}
			if !deleted {
				au.log.Warnf("failed to delete hash '%v' from merkle trie", deleteHash)
			}
		}
		if !delta.new.IsZero() {
			addHash := accountHashBuilder(addr, delta.new, protocol.Encode(&delta.new))
			added, err = au.balancesTrie.Add(addHash)
			if err != nil {
				return err
			}
			if !added {
				au.log.Warnf("attempted to add duplicate hash '%v' to merkle trie", addHash)
			}
		}
	}
	// write it all to disk.
	err = au.balancesTrie.Commit()
	return
}

func (au *accountUpdates) accountsCreateCatchpointLabel(committedRound basics.Round, totals AccountTotals, ledgerBlockDigest crypto.Digest) (label string, err error) {
	var balancesHash crypto.Digest

	balancesHash, err = au.balancesTrie.RootHash()
	if err != nil {
		return
	}

	cpLabel := makeCatchpointLabel(committedRound, ledgerBlockDigest, balancesHash, totals)
	label = cpLabel.String()

	_, err = au.accountsq.writeCatchpointStateString(context.Background(), catchpointStateLastCatchpoint, label)
	return
}

func (au *accountUpdates) roundOffset(rnd basics.Round) (offset uint64, err error) {
	if rnd < au.dbRound {
		err = fmt.Errorf("round %d before dbRound %d", rnd, au.dbRound)
		return
	}

	off := uint64(rnd - au.dbRound)
	if off > uint64(len(au.deltas)) {
		err = fmt.Errorf("round %d too high: dbRound %d, deltas %d", rnd, au.dbRound, len(au.deltas))
		return
	}

	return off, nil
}

func (au *accountUpdates) commitSyncer(deferedCommits chan deferedCommit) {
	for {
		select {
		case committedOffset, ok := <-deferedCommits:
			if !ok {
				return
			}
			au.commitRound(committedOffset.offset, committedOffset.dbRound, committedOffset.lookback)
		case <-au.ctx.Done():
			// drain the pending commits queue:
			drained := false
			for !drained {
				select {
				case <-deferedCommits:
					au.accountsWriting.Done()
				default:
					drained = true
				}
			}
			return
		}
	}
}

func (au *accountUpdates) commitRound(offset uint64, dbRound basics.Round, lookback basics.Round) {
	defer au.accountsWriting.Done()
	au.accountsMu.RLock()

	// we can exit right away, as this is the result of mis-ordered call to committedUpTo.
	if au.dbRound < dbRound || offset < uint64(au.dbRound-dbRound) {
		// if this is an archival ledger, we might need to close the catchpointWriting channel
		if au.archivalLedger {
			// determine if this was a catchpoint round
			isCatchpointRound := ((offset + uint64(lookback+dbRound)) > 0) && (au.catchpointInterval != 0) && (0 == (uint64((offset + uint64(lookback+dbRound))) % au.catchpointInterval))
			if isCatchpointRound {
				// it was a catchpoint round, so close the channel.
				close(au.catchpointWriting)
			}
		}
		au.accountsMu.RUnlock()
		return
	}

	// adjust the offset according to what happend meanwhile..
	offset -= uint64(au.dbRound - dbRound)
	dbRound = au.dbRound

	newBase := basics.Round(offset) + dbRound
	flushTime := time.Now()
	isCatchpointRound := ((offset + uint64(lookback+dbRound)) > 0) && (au.catchpointInterval != 0) && (0 == (uint64((offset + uint64(lookback+dbRound))) % au.catchpointInterval))

	// create a copy of the deltas, round totals and protos for the range we're going to flush.
	deltas := make([]map[basics.Address]accountDelta, offset, offset)
	roundTotals := make([]AccountTotals, offset+1, offset+1)
	protos := make([]config.ConsensusParams, offset+1, offset+1)
	copy(deltas, au.deltas[:offset])
	copy(roundTotals, au.roundTotals[:offset+1])
	copy(protos, au.protos[:offset+1])

	// Keep track of how many changes to each account we flush to the
	// account DB, so that we can drop the corresponding refcounts in
	// au.accounts.
	flushcount := make(map[basics.Address]int)
	assetFlushcount := make(map[basics.AssetIndex]int)
	for i := uint64(0); i < offset; i++ {
		for aidx := range au.assetDeltas[i] {
			assetFlushcount[aidx] = assetFlushcount[aidx] + 1
		}
	}

	var committedRoundDigest crypto.Digest

	if isCatchpointRound {
		committedRoundDigest = au.roundDigest[offset+uint64(lookback)-1]
	}

	au.accountsMu.RUnlock()

	// in committedUpTo, we expect that this function we close the catchpointWriting when
	// it's on a catchpoint round and it's an archival ledger. Doing this in a defered function
	// here would prevent us from "forgetting" to close that channel later on.
	defer func() {
		if isCatchpointRound && au.archivalLedger {
			close(au.catchpointWriting)
		}
	}()

	for i := uint64(0); i < offset; i++ {
		for addr := range deltas[i] {
			flushcount[addr] = flushcount[addr] + 1
		}
	}

	var catchpointLabel string

	err := au.dbs.wdb.Atomic(func(tx *sql.Tx) (err error) {
		treeTargetRound := basics.Round(0)
		if au.catchpointInterval > 0 {
			mc, err0 := makeMerkleCommitter(tx, false)
			if err0 != nil {
				return err0
			}
			if au.balancesTrie == nil {
				trie, err := merkletrie.MakeTrie(mc, trieCachedNodesCount)
				if err != nil {
					au.log.Warnf("unable to create merkle trie during committedUpTo: %v", err)
					return err
				}
				au.balancesTrie = trie
			} else {
				au.balancesTrie.SetCommitter(mc)
			}
			treeTargetRound = dbRound + basics.Round(offset)
		}
		for i := uint64(0); i < offset; i++ {
			err = accountsNewRound(tx, deltas[i], roundTotals[i+1].RewardsLevel, protos[i+1])
			if err != nil {
				return err
			}

			err = au.accountsUpdateBalances(deltas[i])
			if err != nil {
				return err
			}
		}
		err = updateAccountsRound(tx, dbRound+basics.Round(offset), treeTargetRound)
		return err
	})

	if err != nil {
		au.balancesTrie = nil
		au.log.Warnf("unable to advance account snapshot: %v", err)
		return
	}
	if isCatchpointRound {
		catchpointLabel, err = au.accountsCreateCatchpointLabel(dbRound+basics.Round(offset)+lookback, roundTotals[offset], committedRoundDigest)
		if err != nil {
			au.log.Warnf("commitRound : unable to create a catchpoint label: %v", err)
		}
	}
	if au.balancesTrie != nil {
		_, err = au.balancesTrie.Evict(false)
		if err != nil {
			au.log.Warnf("merkle trie failed to evict: %v", err)
		}
	}

	au.accountsMu.Lock()
	if isCatchpointRound && catchpointLabel != "" {
		au.lastCatchpointLabel = catchpointLabel
	}

	// Drop reference counts to modified accounts, and evict them
	// from in-memory cache when no references remain.
	for addr, cnt := range flushcount {
		macct, ok := au.accounts[addr]
		if !ok {
			au.log.Panicf("inconsistency: flushed %d changes to %s, but not in au.accounts", cnt, addr)
		}

		if cnt > macct.ndeltas {
			au.log.Panicf("inconsistency: flushed %d changes to %s, but au.accounts had %d", cnt, addr, macct.ndeltas)
		}

		macct.ndeltas -= cnt
		if macct.ndeltas == 0 {
			delete(au.accounts, addr)
		} else {
			au.accounts[addr] = macct
		}
	}

	for aidx, cnt := range assetFlushcount {
		masset, ok := au.assets[aidx]
		if !ok {
			au.log.Panicf("inconsistency: flushed %d changes to asset %d, but not in au.assets", cnt, aidx)
		}

		if cnt > masset.ndeltas {
			au.log.Panicf("inconsistency: flushed %d changes to asset %d, but au.assets had %d", cnt, aidx, masset.ndeltas)
		}

		masset.ndeltas -= cnt
		if masset.ndeltas == 0 {
			delete(au.assets, aidx)
		} else {
			au.assets[aidx] = masset
		}
	}

	au.deltas = au.deltas[offset:]
	au.deltasAccum = au.deltasAccum[offset:]
	au.roundDigest = au.roundDigest[offset:]
	au.protos = au.protos[offset:]
	au.roundTotals = au.roundTotals[offset:]
	au.assetDeltas = au.assetDeltas[offset:]
	au.dbRound = newBase
	au.lastFlushTime = flushTime
	au.accountsMu.Unlock()

	if isCatchpointRound && au.archivalLedger && catchpointLabel != "" {
		// start generating the catchpoint on a separate goroutine.
		au.generateCatchpoint(basics.Round(offset)+dbRound+lookback, catchpointLabel, committedRoundDigest)
	}

}

func (au *accountUpdates) latest() basics.Round {
	return au.dbRound + basics.Round(len(au.deltas))
}

func (au *accountUpdates) generateCatchpoint(committedRound basics.Round, label string, committedRoundDigest crypto.Digest) {
	// the retryCatchpointCreation is used to repeat the catchpoint file generation in case the node crashed / aborted during startup
	// before the catchpoint file generation could be completed.
	retryCatchpointCreation := false
	au.log.Debugf("accountUpdates: generateCatchpoint: generating catchpoint for round %d", committedRound)
	defer func() {
		if !retryCatchpointCreation {
			// clear the writingCatchpoint flag
			_, err := au.accountsq.writeCatchpointStateUint64(context.Background(), catchpointStateWritingCatchpoint, uint64(0))
			if err != nil {
				au.log.Warnf("accountUpdates: generateCatchpoint unable to clear catchpoint state '%s' for round %d: %v", catchpointStateWritingCatchpoint, committedRound, err)
			}
		}
	}()

	_, err := au.accountsq.writeCatchpointStateUint64(context.Background(), catchpointStateWritingCatchpoint, uint64(committedRound))
	if err != nil {
		au.log.Warnf("accountUpdates: generateCatchpoint unable to write catchpoint state '%s' for round %d: %v", catchpointStateWritingCatchpoint, committedRound, err)
		return
	}

	relCatchpointFileName := filepath.Join("catchpoints", catchpointRoundToPath(committedRound))
	absCatchpointFileName := filepath.Join(au.dbDirectory, relCatchpointFileName)

	catchpointWriter := makeCatchpointWriter(absCatchpointFileName, au.dbs.rdb, committedRound, committedRoundDigest, label)

	more := true
	const shortChunkExecutionDuration = 50 * time.Millisecond
	const longChunkExecutionDuration = 1 * time.Second
	var chunkExecutionDuration time.Duration
	select {
	case <-au.catchpointSlowWriting:
		chunkExecutionDuration = longChunkExecutionDuration
	default:
		chunkExecutionDuration = shortChunkExecutionDuration
	}
	for more {
		stepCtx, stepCancelFunction := context.WithTimeout(au.ctx, chunkExecutionDuration)
		more, err = catchpointWriter.WriteStep(stepCtx)
		stepCancelFunction()
		if more && err == nil {
			// we just wrote some data, but there is more to be written.
			// go to sleep for while.
			select {
			case <-time.After(100 * time.Millisecond):
			case <-au.ctx.Done():
				retryCatchpointCreation = true
				err2 := catchpointWriter.Abort()
				if err2 != nil {
					au.log.Warnf("accountUpdates: generateCatchpoint: error removing catchpoint file : %v", err2)
				}
				return
			case <-au.catchpointSlowWriting:
				chunkExecutionDuration = longChunkExecutionDuration
			}
		}
		if err != nil {
			au.log.Warnf("accountUpdates: generateCatchpoint: unable to create catchpoint : %v", err)
			err2 := catchpointWriter.Abort()
			if err2 != nil {
				au.log.Warnf("accountUpdates: generateCatchpoint: error removing catchpoint file : %v", err2)
			}
			return
		}
	}

	err = au.saveCatchpointFile(committedRound, relCatchpointFileName, catchpointWriter.GetSize(), catchpointWriter.GetCatchpoint())
	if err != nil {
		au.log.Warnf("accountUpdates: generateCatchpoint: unable to save catchpoint: %v", err)
		return
	}
}

func catchpointRoundToPath(rnd basics.Round) string {
	irnd := int64(rnd) / 256
	outStr := ""
	for irnd > 0 {
		outStr = filepath.Join(outStr, fmt.Sprintf("%02x", irnd%256))
		irnd = irnd / 256
	}
	outStr = filepath.Join(outStr, strconv.FormatInt(int64(rnd), 10)+".catchpoint")
	return outStr
}

// saveCatchpointFile stores the provided fileName as the stored catchpoint for the given round.
// after a successfull insert operation to the database, it would delete up to 2 old entries, as needed.
// deleting 2 entries while inserting single entry allow us to adjust the size of the backing storage and have the
// database and storage realign.
func (au *accountUpdates) saveCatchpointFile(round basics.Round, fileName string, fileSize int64, catchpoint string) (err error) {
	if au.catchpointFileHistoryLength != 0 {
		err = au.accountsq.storeCatchpoint(context.Background(), round, fileName, catchpoint, fileSize)
		if err != nil {
			au.log.Warnf("accountUpdates: saveCatchpoint: unable to save catchpoint: %v", err)
			return
		}
	} else {
		err = os.Remove(fileName)
		if err != nil {
			au.log.Warnf("accountUpdates: saveCatchpoint: unable to remove file (%s): %v", fileName, err)
			return
		}
	}
	if au.catchpointFileHistoryLength == -1 {
		return
	}
	var filesToDelete map[basics.Round]string
	filesToDelete, err = au.accountsq.getOldestCatchpointFiles(context.Background(), 2, au.catchpointFileHistoryLength)
	if err != nil {
		return fmt.Errorf("unable to delete catchpoint file, getOldestCatchpointFiles failed : %v", err)
	}
	for round, fileToDelete := range filesToDelete {
		absCatchpointFileName := filepath.Join(au.dbDirectory, fileToDelete)
		err = os.Remove(absCatchpointFileName)
		if err == nil || os.IsNotExist(err) {
			// it's ok if the file doesn't exist. just remove it from the database and we'll be good to go.
			err = nil
		} else {
			// we can't delete the file, abort -
			return fmt.Errorf("unable to delete old catchpoint file '%s' : %v", absCatchpointFileName, err)
		}
		err = au.accountsq.storeCatchpoint(context.Background(), round, "", "", 0)
		if err != nil {
			return fmt.Errorf("unable to delete old catchpoint entry '%s' : %v", fileToDelete, err)
		}
	}
	return
}
