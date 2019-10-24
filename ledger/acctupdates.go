// Copyright (C) 2019 Algorand, Inc.
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
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
)

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

	// initAccounts specifies initial account values for database.
	initAccounts map[basics.Address]basics.AccountData

	// initProto specifies the initial consensus parameters.
	initProto config.ConsensusParams

	// log copied from ledger
	log logging.Logger

	// lastFlushTime is the time we last flushed updates to
	// the accounts DB (bumping dbRound).
	lastFlushTime time.Time
}

func (au *accountUpdates) loadFromDisk(l ledgerForTracker) error {
	au.dbs = l.trackerDB()
	au.log = l.trackerLog()

	if au.initAccounts == nil {
		return fmt.Errorf("accountUpdates.loadFromDisk: initAccounts not set")
	}

	latest := l.Latest()
	err := au.dbs.wdb.Atomic(func(tx *sql.Tx) error {
		var err0 error
		au.dbRound, err0 = au.accountsInitialize(tx)
		if err0 != nil {
			return err0
		}
		// Check for blocks DB and tracker DB un-sync
		if au.dbRound > latest {
			au.log.Warnf("resetting accounts DB (on round %v, but blocks DB's latest is %v)", au.dbRound, latest)
			err0 = accountsReset(tx)
			if err0 != nil {
				return err0
			}
			au.dbRound, err0 = au.accountsInitialize(tx)
			if err0 != nil {
				return err0
			}
		}

		totals, err0 := accountsTotals(tx)
		if err0 != nil {
			return err0
		}

		au.roundTotals = []AccountTotals{totals}
		return nil
	})
	if err != nil {
		return err
	}

	au.accountsq, err = accountsDbInit(au.dbs.rdb.Handle)
	if err != nil {
		return err
	}

	hdr, err := l.BlockHdr(au.dbRound)
	if err != nil {
		return err
	}
	au.protos = []config.ConsensusParams{config.Consensus[hdr.CurrentProtocol]}

	au.deltas = nil
	au.assetDeltas = nil
	au.accounts = make(map[basics.Address]modifiedAccount)
	au.assets = make(map[basics.AssetIndex]modifiedAsset)
	loaded := au.dbRound
	for loaded < latest {
		next := loaded + 1

		blk, aux, err := l.blockAux(next)
		if err != nil {
			return err
		}

		delta, err := l.trackerEvalVerified(blk, aux)
		if err != nil {
			return err
		}

		au.newBlock(blk, delta)
		loaded = next
	}

	return nil
}

// Initialize accounts DB if needed and return account round
func (au *accountUpdates) accountsInitialize(tx *sql.Tx) (basics.Round, error) {
	err := accountsInit(tx, au.initAccounts, au.initProto)
	if err != nil {
		return 0, err
	}

	rnd, err := accountsRound(tx)
	if err != nil {
		return 0, err
	}
	return rnd, nil
}

func (au *accountUpdates) close() {
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

func (au *accountUpdates) lookup(rnd basics.Round, addr basics.Address, withRewards bool) (data basics.AccountData, err error) {
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

func (au *accountUpdates) allBalances(rnd basics.Round) (bals map[basics.Address]basics.AccountData, err error) {
	offsetLimit, err := au.roundOffset(rnd)
	if err != nil {
		return
	}

	err = au.dbs.rdb.Atomic(func(tx *sql.Tx) error {
		var err0 error
		bals, err0 = accountsAll(tx)
		return err0
	})
	if err != nil {
		return
	}

	for offset := uint64(0); offset < offsetLimit; offset++ {
		for addr, delta := range au.deltas[offset] {
			bals[addr] = delta.new
		}
	}
	return
}

func (au *accountUpdates) listAssets(maxAssetIdx basics.AssetIndex, maxResults uint64) ([]basics.AssetLocator, error) {
	// Sort indices for assets that have been created/deleted. If this
	// turns out to be too inefficient, we could keep around a heap of
	// created/deleted asset indices in memory.
	keys := make([]basics.AssetIndex, 0, len(au.assets))
	for aidx := range au.assets {
		keys = append(keys, aidx)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] > keys[j] })

	// Check for assets that haven't been synced to disk yet.
	var unsyncedAssets []basics.AssetLocator
	deletedAssets := make(map[basics.AssetIndex]bool)
	for _, aidx := range keys {
		delta := au.assets[aidx]
		if delta.created && aidx <= maxAssetIdx {
			// Created asset that only exists in memory
			unsyncedAssets = append(unsyncedAssets, basics.AssetLocator{
				Index:   aidx,
				Creator: delta.creator,
			})
		} else {
			// Mark deleted assets for exclusion from the results set
			deletedAssets[aidx] = true
		}
	}

	// Check in-memory created assets, which will always be larger than anything
	// in the database
	var res []basics.AssetLocator
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
		if _, ok := deletedAssets[loc.Index]; ok {
			continue
		}

		// We're OK to include this result
		res = append(res, loc)
	}

	return res, nil
}

func (au *accountUpdates) getAssetCreatorForRound(rnd basics.Round, aidx basics.AssetIndex) (basics.Address, error) {
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

func (au *accountUpdates) committedUpTo(rnd basics.Round) basics.Round {
	lookback := basics.Round(au.protos[len(au.protos)-1].MaxBalLookback)
	if rnd < lookback {
		return 0
	}

	newBase := rnd - lookback
	if newBase <= au.dbRound {
		// Already forgotten
		return au.dbRound
	}

	if newBase > au.dbRound+basics.Round(len(au.deltas)) {
		au.log.Panicf("committedUpTo: block %d too far in the future, lookback %d, dbRound %d, deltas %d", rnd, lookback, au.dbRound, len(au.deltas))
	}

	// If we recently flushed, wait to aggregate some more blocks.
	flushTime := time.Now()
	if !flushTime.After(au.lastFlushTime.Add(5 * time.Second)) {
		return au.dbRound
	}

	// Keep track of how many changes to each account we flush to the
	// account DB, so that we can drop the corresponding refcounts in
	// au.accounts.
	var flushcount map[basics.Address]int
	var assetFlushcount map[basics.AssetIndex]int

	offset := uint64(newBase - au.dbRound)
	err := au.dbs.wdb.Atomic(func(tx *sql.Tx) error {
		flushcount = make(map[basics.Address]int)
		assetFlushcount = make(map[basics.AssetIndex]int)
		for i := uint64(0); i < offset; i++ {
			rnd := au.dbRound + basics.Round(i) + 1
			err := accountsNewRound(tx, rnd, au.deltas[i], au.roundTotals[i+1].RewardsLevel, au.protos[i+1])
			if err != nil {
				return err
			}

			for aidx := range au.assetDeltas[i] {
				assetFlushcount[aidx] = assetFlushcount[aidx] + 1
			}

			for addr := range au.deltas[i] {
				flushcount[addr] = flushcount[addr] + 1
			}
		}
		return nil
	})
	if err != nil {
		au.log.Warnf("unable to advance account snapshot: %v", err)
		return au.dbRound
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
	au.protos = au.protos[offset:]
	au.roundTotals = au.roundTotals[offset:]
	au.assetDeltas = au.assetDeltas[offset:]
	au.dbRound = newBase
	au.lastFlushTime = flushTime
	return au.dbRound
}

func (au *accountUpdates) newBlock(blk bookkeeping.Block, delta stateDelta) {
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
	au.assetDeltas = append(au.assetDeltas, make(map[basics.AssetIndex]modifiedAsset))

	var ot basics.OverflowTracker
	newTotals := au.roundTotals[len(au.roundTotals)-1]
	allBefore := newTotals.All()
	newTotals.applyRewards(delta.hdr.RewardsLevel, &ot)
	newAssetDeltas := au.assetDeltas[len(au.assetDeltas)-1]

	for addr, data := range delta.accts {
		newTotals.delAccount(proto, data.old, &ot)
		newTotals.addAccount(proto, data.new, &ot)

		macct := au.accounts[addr]
		macct.ndeltas++
		macct.data = data.new
		au.accounts[addr] = macct

		adeltas := getChangedAssetIndices(addr, data)
		for aidx, delta := range adeltas {
			masset := au.assets[aidx]
			masset.creator = addr
			masset.created = delta.created
			masset.ndeltas++
			au.assets[aidx] = masset

			newAssetDeltas[aidx] = delta
		}
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

func (au *accountUpdates) latest() basics.Round {
	return au.dbRound + basics.Round(len(au.deltas))
}

func (au *accountUpdates) totals(rnd basics.Round) (totals AccountTotals, err error) {
	offset, err := au.roundOffset(rnd)
	if err != nil {
		return
	}

	totals = au.roundTotals[offset]
	return
}
