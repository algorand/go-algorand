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
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store"
	"github.com/algorand/go-algorand/protocol"
)

// resourceDelta is used as part of the compactResourcesDeltas to describe a change to a single resource.
type resourceDelta struct {
	oldResource store.PersistedResourcesData
	newResource store.ResourcesData
	nAcctDeltas int
	address     basics.Address
}

// compactResourcesDeltas and resourceDelta are extensions to ledgercore.AccountDeltas that is being used by the commitRound function for counting the
// number of changes we've made per account. The ndeltas is used exclusively for consistency checking - making sure that
// all the pending changes were written and that there are no outstanding writes missing.
type compactResourcesDeltas struct {
	// actual account deltas
	deltas []resourceDelta
	// cache for addr to deltas index resolution
	cache map[accountCreatable]int
	// misses holds indices of addresses for which old portion of delta needs to be loaded from disk
	misses []int
}

type accountDelta struct {
	oldAcct     store.PersistedAccountData
	newAcct     store.BaseAccountData
	nAcctDeltas int
	address     basics.Address
}

// compactAccountDeltas and accountDelta are extensions to ledgercore.AccountDeltas that is being used by the commitRound function for counting the
// number of changes we've made per account. The ndeltas is used exclusively for consistency checking - making sure that
// all the pending changes were written and that there are no outstanding writes missing.
type compactAccountDeltas struct {
	// actual account deltas
	deltas []accountDelta
	// cache for addr to deltas index resolution
	cache map[basics.Address]int
	// misses holds indices of addresses for which old portion of delta needs to be loaded from disk
	misses []int
}

// onlineAccountDelta track all changes of account state within a range,
// used in conjunction with compactOnlineAccountDeltas to group and represent per-account changes.
// oldAcct represents the "old" state of the account in the DB, and compared against newAcct[0]
// to determine if the acct became online or went offline.
type onlineAccountDelta struct {
	oldAcct           store.PersistedOnlineAccountData
	newAcct           []store.BaseOnlineAccountData
	nOnlineAcctDeltas int
	address           basics.Address
	updRound          []uint64
	newStatus         []basics.Status
}

type compactOnlineAccountDeltas struct {
	// actual account deltas
	deltas []onlineAccountDelta
	// cache for addr to deltas index resolution
	cache map[basics.Address]int
	// misses holds indices of addresses for which old portion of delta needs to be loaded from disk
	misses []int
}

// MaxEncodedBaseAccountDataSize is a rough estimate for the worst-case scenario we're going to have of the base account data serialized.
// this number is verified by the TestEncodedBaseAccountDataSize function.
const MaxEncodedBaseAccountDataSize = 350

// MaxEncodedBaseResourceDataSize is a rough estimate for the worst-case scenario we're going to have of the base resource data serialized.
// this number is verified by the TestEncodedBaseResourceSize function.
const MaxEncodedBaseResourceDataSize = 20000

// prepareNormalizedBalancesV5 converts an array of encodedBalanceRecordV5 into an equal size array of normalizedAccountBalances.
func prepareNormalizedBalancesV5(bals []encodedBalanceRecordV5, proto config.ConsensusParams) (normalizedAccountBalances []store.NormalizedAccountBalance, err error) {
	normalizedAccountBalances = make([]store.NormalizedAccountBalance, len(bals))
	for i, balance := range bals {
		normalizedAccountBalances[i].Address = balance.Address
		var accountDataV5 basics.AccountData
		err = protocol.Decode(balance.AccountData, &accountDataV5)
		if err != nil {
			return nil, err
		}
		normalizedAccountBalances[i].AccountData.SetAccountData(&accountDataV5)
		normalizedAccountBalances[i].NormalizedBalance = accountDataV5.NormalizedOnlineBalance(proto)
		type resourcesRow struct {
			aidx basics.CreatableIndex
			store.ResourcesData
		}
		var resources []resourcesRow
		addResourceRow := func(_ context.Context, _ int64, aidx basics.CreatableIndex, rd *store.ResourcesData) error {
			resources = append(resources, resourcesRow{aidx: aidx, ResourcesData: *rd})
			return nil
		}
		if err = store.AccountDataResources(context.Background(), &accountDataV5, 0, addResourceRow); err != nil {
			return nil, err
		}
		normalizedAccountBalances[i].AccountHashes = make([][]byte, 1)
		normalizedAccountBalances[i].AccountHashes[0] = store.AccountHashBuilder(balance.Address, accountDataV5, balance.AccountData)
		if len(resources) > 0 {
			normalizedAccountBalances[i].Resources = make(map[basics.CreatableIndex]store.ResourcesData, len(resources))
			normalizedAccountBalances[i].EncodedResources = make(map[basics.CreatableIndex][]byte, len(resources))
		}
		for _, resource := range resources {
			normalizedAccountBalances[i].Resources[resource.aidx] = resource.ResourcesData
			normalizedAccountBalances[i].EncodedResources[resource.aidx] = protocol.Encode(&resource.ResourcesData)
		}
		normalizedAccountBalances[i].EncodedAccountData = protocol.Encode(&normalizedAccountBalances[i].AccountData)
	}
	return
}

// prepareNormalizedBalancesV6 converts an array of encodedBalanceRecordV6 into an equal size array of normalizedAccountBalances.
func prepareNormalizedBalancesV6(bals []encodedBalanceRecordV6, proto config.ConsensusParams) (normalizedAccountBalances []store.NormalizedAccountBalance, err error) {
	normalizedAccountBalances = make([]store.NormalizedAccountBalance, len(bals))
	for i, balance := range bals {
		normalizedAccountBalances[i].Address = balance.Address
		err = protocol.Decode(balance.AccountData, &(normalizedAccountBalances[i].AccountData))
		if err != nil {
			return nil, err
		}
		normalizedAccountBalances[i].NormalizedBalance = basics.NormalizedOnlineAccountBalance(
			normalizedAccountBalances[i].AccountData.Status,
			normalizedAccountBalances[i].AccountData.RewardsBase,
			normalizedAccountBalances[i].AccountData.MicroAlgos,
			proto)
		normalizedAccountBalances[i].EncodedAccountData = balance.AccountData
		curHashIdx := 0
		if balance.ExpectingMoreEntries {
			// There is a single chunk in the catchpoint file with ExpectingMoreEntries
			// set to false for this account. There may be multiple chunks with
			// ExpectingMoreEntries set to true. In this case, we do not have to add the
			// account's own hash to accountHashes.
			normalizedAccountBalances[i].AccountHashes = make([][]byte, len(balance.Resources))
			normalizedAccountBalances[i].PartialBalance = true
		} else {
			normalizedAccountBalances[i].AccountHashes = make([][]byte, 1+len(balance.Resources))
			normalizedAccountBalances[i].AccountHashes[0] = store.AccountHashBuilderV6(balance.Address, &normalizedAccountBalances[i].AccountData, balance.AccountData)
			curHashIdx++
		}
		if len(balance.Resources) > 0 {
			normalizedAccountBalances[i].Resources = make(map[basics.CreatableIndex]store.ResourcesData, len(balance.Resources))
			normalizedAccountBalances[i].EncodedResources = make(map[basics.CreatableIndex][]byte, len(balance.Resources))
			for cidx, res := range balance.Resources {
				var resData store.ResourcesData
				err = protocol.Decode(res, &resData)
				if err != nil {
					return nil, err
				}
				normalizedAccountBalances[i].AccountHashes[curHashIdx], err = store.ResourcesHashBuilderV6(&resData, balance.Address, basics.CreatableIndex(cidx), resData.UpdateRound, res)
				if err != nil {
					return nil, err
				}
				normalizedAccountBalances[i].Resources[basics.CreatableIndex(cidx)] = resData
				normalizedAccountBalances[i].EncodedResources[basics.CreatableIndex(cidx)] = res
				curHashIdx++
			}
		}
	}
	return
}

// makeCompactResourceDeltas takes an array of StateDeltas containing AccountDeltas ( one array entry per round ), and compacts the resource portions of the AccountDeltas into a single
// data structure that contains all the resources deltas changes. While doing that, the function eliminate any intermediate resources changes.
// It counts the number of changes each account get modified across the round range by specifying it in the nAcctDeltas field of the resourcesDeltas.
// As an optimization, stateDeltas is passed as a slice and must not be modified.
func makeCompactResourceDeltas(stateDeltas []ledgercore.StateDelta, baseRound basics.Round, setUpdateRound bool, baseAccounts lruAccounts, baseResources lruResources) (outResourcesDeltas compactResourcesDeltas) {
	if len(stateDeltas) == 0 {
		return
	}

	// the sizes of the maps here aren't super accurate, but would hopefully be a rough estimate for a reasonable starting point.
	size := stateDeltas[0].Accts.Len()*len(stateDeltas) + 1
	outResourcesDeltas.cache = make(map[accountCreatable]int, size)
	outResourcesDeltas.deltas = make([]resourceDelta, 0, size)
	outResourcesDeltas.misses = make([]int, 0, size)

	deltaRound := uint64(baseRound)
	// the updateRoundMultiplier is used when setting the UpdateRound, so that we can set the
	// value without creating any branching. Avoiding branching in the code provides (marginal)
	// performance gain since CPUs can speculate ahead more efficiently.
	updateRoundMultiplier := uint64(0)
	if setUpdateRound {
		updateRoundMultiplier = 1
	}
	for _, stateDelta := range stateDeltas {
		roundDelta := stateDelta.Accts
		deltaRound++
		// assets
		for _, res := range roundDelta.GetAllAssetResources() {
			if prev, idx := outResourcesDeltas.get(res.Addr, basics.CreatableIndex(res.Aidx)); idx != -1 {
				// update existing entry with new data.
				updEntry := resourceDelta{
					oldResource: prev.oldResource,
					newResource: prev.newResource,
					nAcctDeltas: prev.nAcctDeltas + 1,
					address:     prev.address,
				}
				updEntry.newResource.SetAssetData(res.Params, res.Holding)
				updEntry.newResource.UpdateRound = deltaRound * updateRoundMultiplier
				outResourcesDeltas.update(idx, updEntry)
			} else {
				// it's a new entry.
				newEntry := resourceDelta{
					nAcctDeltas: 1,
					address:     res.Addr,
					newResource: store.MakeResourcesData(deltaRound * updateRoundMultiplier),
				}
				newEntry.newResource.SetAssetData(res.Params, res.Holding)
				// baseResources caches deleted entries, and they have addrid = 0
				// need to handle this and prevent such entries to be treated as fully resolved
				baseResourceData, has := baseResources.read(res.Addr, basics.CreatableIndex(res.Aidx))
				existingAcctCacheEntry := has && baseResourceData.Addrid != 0
				if existingAcctCacheEntry {
					newEntry.oldResource = baseResourceData
					outResourcesDeltas.insert(newEntry)
				} else {
					if pad, has := baseAccounts.read(res.Addr); has {
						newEntry.oldResource = store.PersistedResourcesData{Addrid: pad.Rowid}
					}
					newEntry.oldResource.Aidx = basics.CreatableIndex(res.Aidx)
					outResourcesDeltas.insertMissing(newEntry)
				}
			}
		}

		// application
		for _, res := range roundDelta.GetAllAppResources() {
			if prev, idx := outResourcesDeltas.get(res.Addr, basics.CreatableIndex(res.Aidx)); idx != -1 {
				// update existing entry with new data.
				updEntry := resourceDelta{
					oldResource: prev.oldResource,
					newResource: prev.newResource,
					nAcctDeltas: prev.nAcctDeltas + 1,
					address:     prev.address,
				}
				updEntry.newResource.SetAppData(res.Params, res.State)
				updEntry.newResource.UpdateRound = deltaRound * updateRoundMultiplier
				outResourcesDeltas.update(idx, updEntry)
			} else {
				// it's a new entry.
				newEntry := resourceDelta{
					nAcctDeltas: 1,
					address:     res.Addr,
					newResource: store.MakeResourcesData(deltaRound * updateRoundMultiplier),
				}
				newEntry.newResource.SetAppData(res.Params, res.State)
				baseResourceData, has := baseResources.read(res.Addr, basics.CreatableIndex(res.Aidx))
				existingAcctCacheEntry := has && baseResourceData.Addrid != 0
				if existingAcctCacheEntry {
					newEntry.oldResource = baseResourceData
					outResourcesDeltas.insert(newEntry)
				} else {
					if pad, has := baseAccounts.read(res.Addr); has {
						newEntry.oldResource = store.PersistedResourcesData{Addrid: pad.Rowid}
					}
					newEntry.oldResource.Aidx = basics.CreatableIndex(res.Aidx)
					outResourcesDeltas.insertMissing(newEntry)
				}
			}
		}
	}
	return
}

// resourcesLoadOld updates the entries on the deltas.oldResource map that matches the provided addresses.
// The round number of the persistedAccountData is not updated by this function, and the caller is responsible
// for populating this field.
func (a *compactResourcesDeltas) resourcesLoadOld(tx *sql.Tx, knownAddresses map[basics.Address]int64) (err error) {
	if len(a.misses) == 0 {
		return nil
	}
	selectStmt, err := tx.Prepare("SELECT data FROM resources WHERE addrid = ? AND aidx = ?")
	if err != nil {
		return
	}
	defer selectStmt.Close()

	addrRowidStmt, err := tx.Prepare("SELECT rowid FROM accountbase WHERE address=?")
	if err != nil {
		return
	}
	defer addrRowidStmt.Close()

	defer func() {
		a.misses = nil
	}()
	var addrid int64
	var aidx basics.CreatableIndex
	var resDataBuf []byte
	var ok bool
	for _, missIdx := range a.misses {
		delta := a.deltas[missIdx]
		addr := delta.address
		aidx = delta.oldResource.Aidx
		if delta.oldResource.Addrid != 0 {
			addrid = delta.oldResource.Addrid
		} else if addrid, ok = knownAddresses[addr]; !ok {
			err = addrRowidStmt.QueryRow(addr[:]).Scan(&addrid)
			if err != nil {
				if err != sql.ErrNoRows {
					err = fmt.Errorf("base account cannot be read while processing resource for addr=%s, aidx=%d: %w", addr.String(), aidx, err)
					return err

				}
				// not having an account could be legit : the account might not have been created yet, which is why it won't
				// have a rowid. We will be able to re-test that after all the baseAccountData would be written to disk.
				err = nil
				continue
			}
		}
		resDataBuf = nil
		err = selectStmt.QueryRow(addrid, aidx).Scan(&resDataBuf)
		switch err {
		case nil:
			if len(resDataBuf) > 0 {
				persistedResData := store.PersistedResourcesData{Addrid: addrid, Aidx: aidx}
				err = protocol.Decode(resDataBuf, &persistedResData.Data)
				if err != nil {
					return err
				}
				a.updateOld(missIdx, persistedResData)
			} else {
				err = fmt.Errorf("empty resource record: addrid=%d, aidx=%d", addrid, aidx)
				return err
			}
		case sql.ErrNoRows:
			// we don't have that account, just return an empty record.
			a.updateOld(missIdx, store.PersistedResourcesData{Addrid: addrid, Aidx: aidx})
			err = nil
		default:
			// unexpected error - let the caller know that we couldn't complete the operation.
			return err
		}
	}
	return
}

// get returns accountDelta by address and its position.
// if no such entry -1 returned
func (a *compactResourcesDeltas) get(addr basics.Address, index basics.CreatableIndex) (resourceDelta, int) {
	idx, ok := a.cache[accountCreatable{address: addr, index: index}]
	if !ok {
		return resourceDelta{}, -1
	}
	return a.deltas[idx], idx
}

func (a *compactResourcesDeltas) len() int {
	return len(a.deltas)
}

func (a *compactResourcesDeltas) getByIdx(i int) resourceDelta {
	return a.deltas[i]
}

// update replaces specific entry by idx
func (a *compactResourcesDeltas) update(idx int, delta resourceDelta) {
	a.deltas[idx] = delta
}

func (a *compactResourcesDeltas) insert(delta resourceDelta) int {
	last := len(a.deltas)
	a.deltas = append(a.deltas, delta)

	if a.cache == nil {
		a.cache = make(map[accountCreatable]int)
	}
	a.cache[accountCreatable{address: delta.address, index: delta.oldResource.Aidx}] = last
	return last
}

func (a *compactResourcesDeltas) insertMissing(delta resourceDelta) {
	a.misses = append(a.misses, a.insert(delta))
}

// updateOld updates existing or inserts a new partial entry with only old field filled
func (a *compactResourcesDeltas) updateOld(idx int, old store.PersistedResourcesData) {
	a.deltas[idx].oldResource = old
}

// makeCompactAccountDeltas takes an array of account StateDeltas with AccountDeltas ( one array entry per round ), and compacts the AccountDeltas into a single
// data structure that contains all the account deltas changes. While doing that, the function eliminate any intermediate account changes.
// It counts the number of changes each account get modified across the round range by specifying it in the nAcctDeltas field of the accountDeltaCount/modifiedCreatable.
// As an optimization, stateDeltas is passed as a slice and must not be modified.
func makeCompactAccountDeltas(stateDeltas []ledgercore.StateDelta, baseRound basics.Round, setUpdateRound bool, baseAccounts lruAccounts) (outAccountDeltas compactAccountDeltas) {
	if len(stateDeltas) == 0 {
		return
	}

	// the sizes of the maps here aren't super accurate, but would hopefully be a rough estimate for a reasonable starting point.
	size := stateDeltas[0].Accts.Len()*len(stateDeltas) + 1
	outAccountDeltas.cache = make(map[basics.Address]int, size)
	outAccountDeltas.deltas = make([]accountDelta, 0, size)
	outAccountDeltas.misses = make([]int, 0, size)

	deltaRound := uint64(baseRound)
	// the updateRoundMultiplier is used when setting the UpdateRound, so that we can set the
	// value without creating any branching. Avoiding branching in the code provides (marginal)
	// performance gain since CPUs can speculate ahead more efficiently.
	updateRoundMultiplier := uint64(0)
	if setUpdateRound {
		updateRoundMultiplier = 1
	}
	for _, stateDelta := range stateDeltas {
		roundDelta := stateDelta.Accts
		deltaRound++
		for i := 0; i < roundDelta.Len(); i++ {
			addr, acctDelta := roundDelta.GetByIdx(i)
			if prev, idx := outAccountDeltas.get(addr); idx != -1 {
				updEntry := accountDelta{
					oldAcct:     prev.oldAcct,
					nAcctDeltas: prev.nAcctDeltas + 1,
					address:     prev.address,
				}
				updEntry.newAcct.SetCoreAccountData(&acctDelta)
				updEntry.newAcct.UpdateRound = deltaRound * updateRoundMultiplier
				outAccountDeltas.update(idx, updEntry)
			} else {
				// it's a new entry.
				newEntry := accountDelta{
					nAcctDeltas: 1,
					newAcct: store.BaseAccountData{
						UpdateRound: deltaRound * updateRoundMultiplier,
					},
					address: addr,
				}
				newEntry.newAcct.SetCoreAccountData(&acctDelta)
				if baseAccountData, has := baseAccounts.read(addr); has {
					newEntry.oldAcct = baseAccountData
					outAccountDeltas.insert(newEntry) // insert instead of upsert economizes one map lookup
				} else {
					outAccountDeltas.insertMissing(newEntry)
				}
			}
		}
	}
	return
}

// accountsLoadOld updates the entries on the deltas.old map that matches the provided addresses.
// The round number of the persistedAccountData is not updated by this function, and the caller is responsible
// for populating this field.
func (a *compactAccountDeltas) accountsLoadOld(tx *sql.Tx) (err error) {
	if len(a.misses) == 0 {
		return nil
	}
	selectStmt, err := tx.Prepare("SELECT rowid, data FROM accountbase WHERE address=?")
	if err != nil {
		return
	}
	defer selectStmt.Close()
	defer func() {
		a.misses = nil
	}()
	var rowid sql.NullInt64
	var acctDataBuf []byte
	for _, idx := range a.misses {
		addr := a.deltas[idx].address
		err = selectStmt.QueryRow(addr[:]).Scan(&rowid, &acctDataBuf)
		switch err {
		case nil:
			if len(acctDataBuf) > 0 {
				persistedAcctData := &store.PersistedAccountData{Addr: addr, Rowid: rowid.Int64}
				err = protocol.Decode(acctDataBuf, &persistedAcctData.AccountData)
				if err != nil {
					return err
				}
				a.updateOld(idx, *persistedAcctData)
			} else {
				// to retain backward compatibility, we will treat this condition as if we don't have the account.
				a.updateOld(idx, store.PersistedAccountData{Addr: addr, Rowid: rowid.Int64})
			}
		case sql.ErrNoRows:
			// we don't have that account, just return an empty record.
			a.updateOld(idx, store.PersistedAccountData{Addr: addr})
			err = nil
		default:
			// unexpected error - let the caller know that we couldn't complete the operation.
			return err
		}
	}
	return
}

// get returns accountDelta by address and its position.
// if no such entry -1 returned
func (a *compactAccountDeltas) get(addr basics.Address) (accountDelta, int) {
	idx, ok := a.cache[addr]
	if !ok {
		return accountDelta{}, -1
	}
	return a.deltas[idx], idx
}

func (a *compactAccountDeltas) len() int {
	return len(a.deltas)
}

func (a *compactAccountDeltas) getByIdx(i int) accountDelta {
	return a.deltas[i]
}

// update replaces specific entry by idx
func (a *compactAccountDeltas) update(idx int, delta accountDelta) {
	a.deltas[idx] = delta
}

func (a *compactAccountDeltas) insert(delta accountDelta) int {
	last := len(a.deltas)
	a.deltas = append(a.deltas, delta)

	if a.cache == nil {
		a.cache = make(map[basics.Address]int)
	}
	a.cache[delta.address] = last
	return last
}

func (a *compactAccountDeltas) insertMissing(delta accountDelta) {
	idx := a.insert(delta)
	a.misses = append(a.misses, idx)
}

// updateOld updates existing or inserts a new partial entry with only old field filled
func (a *compactAccountDeltas) updateOld(idx int, old store.PersistedAccountData) {
	a.deltas[idx].oldAcct = old
}

func (c *onlineAccountDelta) append(acctDelta ledgercore.AccountData, deltaRound basics.Round) {
	var baseEntry store.BaseOnlineAccountData
	baseEntry.SetCoreAccountData(&acctDelta)
	c.newAcct = append(c.newAcct, baseEntry)
	c.updRound = append(c.updRound, uint64(deltaRound))
	c.newStatus = append(c.newStatus, acctDelta.Status)
}

// makeCompactAccountDeltas takes an array of account AccountDeltas ( one array entry per round ), and compacts the arrays into a single
// data structure that contains all the account deltas changes. While doing that, the function eliminate any intermediate account changes.
// It counts the number of changes each account get modified across the round range by specifying it in the nAcctDeltas field of the accountDeltaCount/modifiedCreatable.
func makeCompactOnlineAccountDeltas(accountDeltas []ledgercore.AccountDeltas, baseRound basics.Round, baseOnlineAccounts lruOnlineAccounts) (outAccountDeltas compactOnlineAccountDeltas) {
	if len(accountDeltas) == 0 {
		return
	}

	// the sizes of the maps here aren't super accurate, but would hopefully be a rough estimate for a reasonable starting point.
	size := accountDeltas[0].Len()*len(accountDeltas) + 1
	outAccountDeltas.cache = make(map[basics.Address]int, size)
	outAccountDeltas.deltas = make([]onlineAccountDelta, 0, size)
	outAccountDeltas.misses = make([]int, 0, size)

	deltaRound := baseRound
	for _, roundDelta := range accountDeltas {
		deltaRound++
		for i := 0; i < roundDelta.Len(); i++ {
			addr, acctDelta := roundDelta.GetByIdx(i)
			if prev, idx := outAccountDeltas.get(addr); idx != -1 {
				updEntry := prev
				updEntry.nOnlineAcctDeltas++
				updEntry.append(acctDelta, deltaRound)
				outAccountDeltas.update(idx, updEntry)
			} else {
				// it's a new entry.
				newEntry := onlineAccountDelta{
					nOnlineAcctDeltas: 1,
					address:           addr,
				}
				newEntry.append(acctDelta, deltaRound)
				// the cache always has the most recent data,
				// including deleted/expired online accounts with empty voting data
				if baseOnlineAccountData, has := baseOnlineAccounts.read(addr); has {
					newEntry.oldAcct = baseOnlineAccountData
					outAccountDeltas.insert(newEntry)
				} else {
					outAccountDeltas.insertMissing(newEntry)
				}
			}
		}
	}
	return
}

// accountsLoadOld updates the entries on the deltas.old map that matches the provided addresses.
// The round number of the persistedAccountData is not updated by this function, and the caller is responsible
// for populating this field.
func (a *compactOnlineAccountDeltas) accountsLoadOld(tx *sql.Tx) (err error) {
	if len(a.misses) == 0 {
		return nil
	}
	// fetch the latest entry
	selectStmt, err := tx.Prepare("SELECT rowid, data FROM onlineaccounts WHERE address=? ORDER BY updround DESC LIMIT 1")
	if err != nil {
		return
	}
	defer selectStmt.Close()
	defer func() {
		a.misses = nil
	}()
	var rowid sql.NullInt64
	var acctDataBuf []byte
	for _, idx := range a.misses {
		addr := a.deltas[idx].address
		err = selectStmt.QueryRow(addr[:]).Scan(&rowid, &acctDataBuf)
		switch err {
		case nil:
			if len(acctDataBuf) > 0 {
				persistedAcctData := &store.PersistedOnlineAccountData{Addr: addr, Rowid: rowid.Int64}
				err = protocol.Decode(acctDataBuf, &persistedAcctData.AccountData)
				if err != nil {
					return err
				}
				a.updateOld(idx, *persistedAcctData)
			} else {
				// empty data means offline account
				a.updateOld(idx, store.PersistedOnlineAccountData{Addr: addr, Rowid: rowid.Int64})
			}
		case sql.ErrNoRows:
			// we don't have that account, just return an empty record.
			a.updateOld(idx, store.PersistedOnlineAccountData{Addr: addr})
			err = nil
		default:
			// unexpected error - let the caller know that we couldn't complete the operation.
			return err
		}
	}
	return
}

// get returns accountDelta by address and its position.
// if no such entry -1 returned
func (a *compactOnlineAccountDeltas) get(addr basics.Address) (onlineAccountDelta, int) {
	idx, ok := a.cache[addr]
	if !ok {
		return onlineAccountDelta{}, -1
	}
	return a.deltas[idx], idx
}

func (a *compactOnlineAccountDeltas) len() int {
	return len(a.deltas)
}

func (a *compactOnlineAccountDeltas) getByIdx(i int) onlineAccountDelta {
	return a.deltas[i]
}

// update replaces specific entry by idx
func (a *compactOnlineAccountDeltas) update(idx int, delta onlineAccountDelta) {
	a.deltas[idx] = delta
}

func (a *compactOnlineAccountDeltas) insert(delta onlineAccountDelta) int {
	last := len(a.deltas)
	a.deltas = append(a.deltas, delta)

	if a.cache == nil {
		a.cache = make(map[basics.Address]int)
	}
	a.cache[delta.address] = last
	return last
}

func (a *compactOnlineAccountDeltas) insertMissing(delta onlineAccountDelta) {
	idx := a.insert(delta)
	a.misses = append(a.misses, idx)
}

// updateOld updates existing or inserts a new partial entry with only old field filled
func (a *compactOnlineAccountDeltas) updateOld(idx int, old store.PersistedOnlineAccountData) {
	a.deltas[idx].oldAcct = old
}

// accountDataToOnline returns the part of the AccountData that matters
// for online accounts (to answer top-N queries).  We store a subset of
// the full AccountData because we need to store a large number of these
// in memory (say, 1M), and storing that many AccountData could easily
// cause us to run out of memory.
func accountDataToOnline(address basics.Address, ad *ledgercore.AccountData, proto config.ConsensusParams) *ledgercore.OnlineAccount {
	return &ledgercore.OnlineAccount{
		Address:                 address,
		MicroAlgos:              ad.MicroAlgos,
		RewardsBase:             ad.RewardsBase,
		NormalizedOnlineBalance: ad.NormalizedOnlineBalance(proto),
		VoteFirstValid:          ad.VoteFirstValid,
		VoteLastValid:           ad.VoteLastValid,
		StateProofID:            ad.StateProofID,
	}
}

// accountsNewRound is a convenience wrapper for accountsNewRoundImpl
func accountsNewRound(
	tx *sql.Tx,
	updates compactAccountDeltas, resources compactResourcesDeltas, kvPairs map[string]modifiedKvValue, creatables map[basics.CreatableIndex]ledgercore.ModifiedCreatable,
	proto config.ConsensusParams, lastUpdateRound basics.Round,
) (updatedAccounts []store.PersistedAccountData, updatedResources map[basics.Address][]store.PersistedResourcesData, updatedKVs map[string]store.PersistedKVData, err error) {
	hasAccounts := updates.len() > 0
	hasResources := resources.len() > 0
	hasKvPairs := len(kvPairs) > 0
	hasCreatables := len(creatables) > 0

	writer, err := store.MakeAccountsSQLWriter(tx, hasAccounts, hasResources, hasKvPairs, hasCreatables)
	if err != nil {
		return
	}
	defer writer.Close()

	return accountsNewRoundImpl(writer, updates, resources, kvPairs, creatables, proto, lastUpdateRound)
}

func onlineAccountsNewRound(
	tx *sql.Tx,
	updates compactOnlineAccountDeltas,
	proto config.ConsensusParams, lastUpdateRound basics.Round,
) (updatedAccounts []store.PersistedOnlineAccountData, err error) {
	hasAccounts := updates.len() > 0

	writer, err := store.MakeOnlineAccountsSQLWriter(tx, hasAccounts)
	if err != nil {
		return
	}
	defer writer.Close()

	updatedAccounts, err = onlineAccountsNewRoundImpl(writer, updates, proto, lastUpdateRound)
	return
}

// accountsNewRoundImpl updates the accountbase and assetcreators tables by applying the provided deltas to the accounts / creatables.
// The function returns a persistedAccountData for the modified accounts which can be stored in the base cache.
func accountsNewRoundImpl(
	writer store.AccountsWriter,
	updates compactAccountDeltas, resources compactResourcesDeltas, kvPairs map[string]modifiedKvValue, creatables map[basics.CreatableIndex]ledgercore.ModifiedCreatable,
	proto config.ConsensusParams, lastUpdateRound basics.Round,
) (updatedAccounts []store.PersistedAccountData, updatedResources map[basics.Address][]store.PersistedResourcesData, updatedKVs map[string]store.PersistedKVData, err error) {
	updatedAccounts = make([]store.PersistedAccountData, updates.len())
	updatedAccountIdx := 0
	newAddressesRowIDs := make(map[basics.Address]int64)
	for i := 0; i < updates.len(); i++ {
		data := updates.getByIdx(i)
		if data.oldAcct.Rowid == 0 {
			// zero rowid means we don't have a previous value.
			if data.newAcct.IsEmpty() {
				// IsEmpty means we don't have a previous value. Note, can't use newAcct.MsgIsZero
				// because of non-zero UpdateRound field in a new delta
				// if we didn't had it before, and we don't have anything now, just skip it.
			} else {
				// create a new entry.
				var rowid int64
				normBalance := data.newAcct.NormalizedOnlineBalance(proto)
				rowid, err = writer.InsertAccount(data.address, normBalance, data.newAcct)
				if err == nil {
					updatedAccounts[updatedAccountIdx].Rowid = rowid
					updatedAccounts[updatedAccountIdx].AccountData = data.newAcct
					newAddressesRowIDs[data.address] = rowid
				}
			}
		} else {
			// non-zero rowid means we had a previous value.
			if data.newAcct.IsEmpty() {
				// new value is zero, which means we need to delete the current value.
				var rowsAffected int64
				rowsAffected, err = writer.DeleteAccount(data.oldAcct.Rowid)
				if err == nil {
					// we deleted the entry successfully.
					updatedAccounts[updatedAccountIdx].Rowid = 0
					updatedAccounts[updatedAccountIdx].AccountData = store.BaseAccountData{}
					if rowsAffected != 1 {
						err = fmt.Errorf("failed to delete accountbase row for account %v, rowid %d", data.address, data.oldAcct.Rowid)
					}
				}
			} else {
				var rowsAffected int64
				normBalance := data.newAcct.NormalizedOnlineBalance(proto)
				rowsAffected, err = writer.UpdateAccount(data.oldAcct.Rowid, normBalance, data.newAcct)
				if err == nil {
					// rowid doesn't change on update.
					updatedAccounts[updatedAccountIdx].Rowid = data.oldAcct.Rowid
					updatedAccounts[updatedAccountIdx].AccountData = data.newAcct
					if rowsAffected != 1 {
						err = fmt.Errorf("failed to update accountbase row for account %v, rowid %d", data.address, data.oldAcct.Rowid)
					}
				}
			}
		}

		if err != nil {
			return
		}

		// set the returned persisted account states so that we could store that as the baseAccounts in commitRound
		updatedAccounts[updatedAccountIdx].Round = lastUpdateRound
		updatedAccounts[updatedAccountIdx].Addr = data.address
		updatedAccountIdx++
	}

	updatedResources = make(map[basics.Address][]store.PersistedResourcesData)

	// the resources update is going to be made in three parts:
	// on the first loop, we will find out all the entries that need to be deleted, and parepare a pendingResourcesDeletion map.
	// on the second loop, we will perform update/insertion. when considering inserting, we would test the pendingResourcesDeletion to see
	// if the said entry was scheduled to be deleted. If so, we would "upgrade" the insert operation into an update operation.
	// on the last loop, we would delete the remainder of the resource entries that were detected in loop #1 and were not upgraded in loop #2.
	// the rationale behind this is that addrid might get reused, and we need to ensure
	// that at all times there are no two representations of the same entry in the resources table.
	// ( which would trigger a constrain violation )
	type resourceKey struct {
		addrid int64
		aidx   basics.CreatableIndex
	}
	var pendingResourcesDeletion map[resourceKey]struct{} // map to indicate which resources need to be deleted
	for i := 0; i < resources.len(); i++ {
		data := resources.getByIdx(i)
		if data.oldResource.Addrid == 0 || data.oldResource.Data.IsEmpty() || !data.newResource.IsEmpty() {
			continue
		}
		if pendingResourcesDeletion == nil {
			pendingResourcesDeletion = make(map[resourceKey]struct{})
		}
		pendingResourcesDeletion[resourceKey{addrid: data.oldResource.Addrid, aidx: data.oldResource.Aidx}] = struct{}{}

		entry := store.PersistedResourcesData{Addrid: 0, Aidx: data.oldResource.Aidx, Data: store.MakeResourcesData(0), Round: lastUpdateRound}
		deltas := updatedResources[data.address]
		deltas = append(deltas, entry)
		updatedResources[data.address] = deltas
	}

	for i := 0; i < resources.len(); i++ {
		data := resources.getByIdx(i)
		addr := data.address
		aidx := data.oldResource.Aidx
		addrid := data.oldResource.Addrid
		if addrid == 0 {
			// new entry, data.oldResource does not have addrid
			// check if this delta is part of in-memory only account
			// that is created, funded, transferred, and closed within a commit range
			inMemEntry := data.oldResource.Data.IsEmpty() && data.newResource.IsEmpty()
			addrid = newAddressesRowIDs[addr]
			if addrid == 0 && !inMemEntry {
				err = fmt.Errorf("cannot resolve address %s (%d), aidx %d, data %v", addr.String(), addrid, aidx, data.newResource)
				return
			}
		}
		var entry store.PersistedResourcesData
		if data.oldResource.Data.IsEmpty() {
			// IsEmpty means we don't have a previous value. Note, can't use oldResource.data.MsgIsZero
			// because of possibility of empty asset holdings or app local state after opting in,
			// as well as non-zero UpdateRound field in a new delta
			if data.newResource.IsEmpty() {
				// if we didn't had it before, and we don't have anything now, just skip it.
				// set zero addrid to mark this entry invalid for subsequent addr to addrid resolution
				// because the base account might gone.
				entry = store.PersistedResourcesData{Addrid: 0, Aidx: aidx, Data: store.MakeResourcesData(0), Round: lastUpdateRound}
			} else {
				// create a new entry.
				if !data.newResource.IsApp() && !data.newResource.IsAsset() {
					err = fmt.Errorf("unknown creatable for addr %v (%d), aidx %d, data %v", addr, addrid, aidx, data.newResource)
					return
				}
				// check if we need to "upgrade" this insert operation into an update operation due to a scheduled
				// delete operation of the same resource.
				if _, pendingDeletion := pendingResourcesDeletion[resourceKey{addrid: addrid, aidx: aidx}]; pendingDeletion {
					// yes - we've had this entry being deleted and re-created in the same commit range. This means that we can safely
					// update the database entry instead of deleting + inserting.
					delete(pendingResourcesDeletion, resourceKey{addrid: addrid, aidx: aidx})
					var rowsAffected int64
					rowsAffected, err = writer.UpdateResource(addrid, aidx, data.newResource)
					if err == nil {
						// rowid doesn't change on update.
						entry = store.PersistedResourcesData{Addrid: addrid, Aidx: aidx, Data: data.newResource, Round: lastUpdateRound}
						if rowsAffected != 1 {
							err = fmt.Errorf("failed to update resources row for addr %s (%d), aidx %d", addr, addrid, aidx)
						}
					}
				} else {
					_, err = writer.InsertResource(addrid, aidx, data.newResource)
					if err == nil {
						// set the returned persisted account states so that we could store that as the baseResources in commitRound
						entry = store.PersistedResourcesData{Addrid: addrid, Aidx: aidx, Data: data.newResource, Round: lastUpdateRound}
					}
				}
			}
		} else {
			// non-zero rowid means we had a previous value.
			if data.newResource.IsEmpty() {
				// new value is zero, which means we need to delete the current value.
				// this case was already handled in the first loop.
				continue
			} else {
				if !data.newResource.IsApp() && !data.newResource.IsAsset() {
					err = fmt.Errorf("unknown creatable for addr %v (%d), aidx %d, data %v", addr, addrid, aidx, data.newResource)
					return
				}
				var rowsAffected int64
				rowsAffected, err = writer.UpdateResource(addrid, aidx, data.newResource)
				if err == nil {
					// rowid doesn't change on update.
					entry = store.PersistedResourcesData{Addrid: addrid, Aidx: aidx, Data: data.newResource, Round: lastUpdateRound}
					if rowsAffected != 1 {
						err = fmt.Errorf("failed to update resources row for addr %s (%d), aidx %d", addr, addrid, aidx)
					}
				}
			}
		}

		if err != nil {
			return
		}

		deltas := updatedResources[addr]
		deltas = append(deltas, entry)
		updatedResources[addr] = deltas
	}

	// last, we want to delete the resource table entries that are no longer needed.
	for delRes := range pendingResourcesDeletion {
		// new value is zero, which means we need to delete the current value.
		var rowsAffected int64
		rowsAffected, err = writer.DeleteResource(delRes.addrid, delRes.aidx)
		if err == nil {
			// we deleted the entry successfully.
			// set zero addrid to mark this entry invalid for subsequent addr to addrid resolution
			// because the base account might gone.
			if rowsAffected != 1 {
				err = fmt.Errorf("failed to delete resources row (%d), aidx %d", delRes.addrid, delRes.aidx)
			}
		}
		if err != nil {
			return
		}
	}

	updatedKVs = make(map[string]store.PersistedKVData, len(kvPairs))
	for key, mv := range kvPairs {
		if mv.data != nil {
			// reminder: check oldData for nil here, b/c bytes.Equal conflates nil and "".
			if mv.oldData != nil && bytes.Equal(mv.oldData, mv.data) {
				continue // changed back within the delta span
			}
			err = writer.UpsertKvPair(key, mv.data)
			updatedKVs[key] = store.PersistedKVData{Value: mv.data, Round: lastUpdateRound}
		} else {
			if mv.oldData == nil { // Came and went within the delta span
				continue
			}
			err = writer.DeleteKvPair(key)
			updatedKVs[key] = store.PersistedKVData{Value: nil, Round: lastUpdateRound}
		}
		if err != nil {
			return
		}
	}

	for cidx, cdelta := range creatables {
		if cdelta.Created {
			_, err = writer.InsertCreatable(cidx, cdelta.Ctype, cdelta.Creator[:])
		} else {
			_, err = writer.DeleteCreatable(cidx, cdelta.Ctype)
		}
		if err != nil {
			return
		}
	}

	return
}

func onlineAccountsNewRoundImpl(
	writer store.OnlineAccountsWriter, updates compactOnlineAccountDeltas,
	proto config.ConsensusParams, lastUpdateRound basics.Round,
) (updatedAccounts []store.PersistedOnlineAccountData, err error) {

	for i := 0; i < updates.len(); i++ {
		data := updates.getByIdx(i)
		prevAcct := data.oldAcct
		for j := 0; j < len(data.newAcct); j++ {
			newAcct := data.newAcct[j]
			updRound := data.updRound[j]
			newStatus := data.newStatus[j]
			if prevAcct.Rowid == 0 {
				// zero rowid means we don't have a previous value.
				if newAcct.IsEmpty() {
					// IsEmpty means we don't have a previous value.
					// if we didn't had it before, and we don't have anything now, just skip it.
				} else {
					if newStatus == basics.Online {
						if newAcct.IsVotingEmpty() {
							err = fmt.Errorf("empty voting data for online account %s: %v", data.address.String(), newAcct)
						} else {
							// create a new entry.
							var rowid int64
							normBalance := newAcct.NormalizedOnlineBalance(proto)
							rowid, err = writer.InsertOnlineAccount(data.address, normBalance, newAcct, updRound, uint64(newAcct.VoteLastValid))
							if err == nil {
								updated := store.PersistedOnlineAccountData{
									Addr:        data.address,
									AccountData: newAcct,
									Round:       lastUpdateRound,
									Rowid:       rowid,
									UpdRound:    basics.Round(updRound),
								}
								updatedAccounts = append(updatedAccounts, updated)
								prevAcct = updated
							}
						}
					} else if !newAcct.IsVotingEmpty() {
						err = fmt.Errorf("non-empty voting data for non-online account %s: %v", data.address.String(), newAcct)
					}
				}
			} else {
				// non-zero rowid means we had a previous value.
				if newAcct.IsVotingEmpty() {
					// new value is zero then go offline
					if newStatus == basics.Online {
						err = fmt.Errorf("empty voting data but online account %s: %v", data.address.String(), newAcct)
					} else {
						var rowid int64
						rowid, err = writer.InsertOnlineAccount(data.address, 0, store.BaseOnlineAccountData{}, updRound, 0)
						if err == nil {
							updated := store.PersistedOnlineAccountData{
								Addr:        data.address,
								AccountData: store.BaseOnlineAccountData{},
								Round:       lastUpdateRound,
								Rowid:       rowid,
								UpdRound:    basics.Round(updRound),
							}

							updatedAccounts = append(updatedAccounts, updated)
							prevAcct = updated
						}
					}
				} else {
					if prevAcct.AccountData != newAcct {
						var rowid int64
						normBalance := newAcct.NormalizedOnlineBalance(proto)
						rowid, err = writer.InsertOnlineAccount(data.address, normBalance, newAcct, updRound, uint64(newAcct.VoteLastValid))
						if err == nil {
							updated := store.PersistedOnlineAccountData{
								Addr:        data.address,
								AccountData: newAcct,
								Round:       lastUpdateRound,
								Rowid:       rowid,
								UpdRound:    basics.Round(updRound),
							}

							updatedAccounts = append(updatedAccounts, updated)
							prevAcct = updated
						}
					}
				}
			}

			if err != nil {
				return
			}
		}
	}

	return
}

// catchpointAccountResourceCounter keeps track of the resources processed for the current account
type catchpointAccountResourceCounter struct {
	totalAppParams      uint64
	totalAppLocalStates uint64
	totalAssetParams    uint64
	totalAssets         uint64
}

// encodedAccountsBatchIter allows us to iterate over the accounts data stored in the accountbase table.
type encodedAccountsBatchIter struct {
	accountsRows    *sql.Rows
	resourcesRows   *sql.Rows
	nextBaseRow     pendingBaseRow
	nextResourceRow pendingResourceRow
	acctResCnt      catchpointAccountResourceCounter
}

// Next returns an array containing the account data, in the same way it appear in the database
// returning accountCount accounts data at a time.
func (iterator *encodedAccountsBatchIter) Next(ctx context.Context, tx *sql.Tx, accountCount int, resourceCount int) (bals []encodedBalanceRecordV6, numAccountsProcessed uint64, err error) {
	if iterator.accountsRows == nil {
		iterator.accountsRows, err = tx.QueryContext(ctx, "SELECT rowid, address, data FROM accountbase ORDER BY rowid")
		if err != nil {
			return
		}
	}
	if iterator.resourcesRows == nil {
		iterator.resourcesRows, err = tx.QueryContext(ctx, "SELECT addrid, aidx, data FROM resources ORDER BY addrid, aidx")
		if err != nil {
			return
		}
	}

	// gather up to accountCount encoded accounts.
	bals = make([]encodedBalanceRecordV6, 0, accountCount)
	var encodedRecord encodedBalanceRecordV6
	var baseAcct store.BaseAccountData
	var numAcct int
	baseCb := func(addr basics.Address, rowid int64, accountData *store.BaseAccountData, encodedAccountData []byte) (err error) {
		encodedRecord = encodedBalanceRecordV6{Address: addr, AccountData: encodedAccountData}
		baseAcct = *accountData
		numAcct++
		return nil
	}

	var totalResources int

	// emptyCount := 0
	resCb := func(addr basics.Address, cidx basics.CreatableIndex, resData *store.ResourcesData, encodedResourceData []byte, lastResource bool) error {

		emptyBaseAcct := baseAcct.TotalAppParams == 0 && baseAcct.TotalAppLocalStates == 0 && baseAcct.TotalAssetParams == 0 && baseAcct.TotalAssets == 0
		if !emptyBaseAcct && resData != nil {
			if encodedRecord.Resources == nil {
				encodedRecord.Resources = make(map[uint64]msgp.Raw)
			}
			encodedRecord.Resources[uint64(cidx)] = encodedResourceData
			if resData.IsApp() && resData.IsOwning() {
				iterator.acctResCnt.totalAppParams++
			}
			if resData.IsApp() && resData.IsHolding() {
				iterator.acctResCnt.totalAppLocalStates++
			}

			if resData.IsAsset() && resData.IsOwning() {
				iterator.acctResCnt.totalAssetParams++
			}
			if resData.IsAsset() && resData.IsHolding() {
				iterator.acctResCnt.totalAssets++
			}
			totalResources++
		}

		if baseAcct.TotalAppParams == iterator.acctResCnt.totalAppParams &&
			baseAcct.TotalAppLocalStates == iterator.acctResCnt.totalAppLocalStates &&
			baseAcct.TotalAssetParams == iterator.acctResCnt.totalAssetParams &&
			baseAcct.TotalAssets == iterator.acctResCnt.totalAssets {

			encodedRecord.ExpectingMoreEntries = false
			bals = append(bals, encodedRecord)
			numAccountsProcessed++

			iterator.acctResCnt = catchpointAccountResourceCounter{}

			return nil
		}

		// max resources per chunk reached, stop iterating.
		if lastResource {
			encodedRecord.ExpectingMoreEntries = true
			bals = append(bals, encodedRecord)
			encodedRecord.Resources = nil
		}

		return nil
	}

	_, iterator.nextBaseRow, iterator.nextResourceRow, err = processAllBaseAccountRecords(
		iterator.accountsRows, iterator.resourcesRows,
		baseCb, resCb,
		iterator.nextBaseRow, iterator.nextResourceRow, accountCount, resourceCount,
	)
	if err != nil {
		iterator.Close()
		return
	}

	if len(bals) == accountCount || totalResources == resourceCount {
		// we're done with this iteration.
		return
	}

	err = iterator.accountsRows.Err()
	if err != nil {
		iterator.Close()
		return
	}
	// Do not Close() the iterator here.  It is the caller's responsibility to
	// do so, signalled by the return of an empty chunk. If we Close() here, the
	// next call to Next() will start all over!
	return
}

// Close shuts down the encodedAccountsBatchIter, releasing database resources.
func (iterator *encodedAccountsBatchIter) Close() {
	if iterator.accountsRows != nil {
		iterator.accountsRows.Close()
		iterator.accountsRows = nil
	}
	if iterator.resourcesRows != nil {
		iterator.resourcesRows.Close()
		iterator.resourcesRows = nil
	}
}

// orderedAccountsIterStep is used by orderedAccountsIter to define the current step
//
//msgp:ignore orderedAccountsIterStep
type orderedAccountsIterStep int

const (
	// startup step
	oaiStepStartup = orderedAccountsIterStep(0)
	// delete old ordering table if we have any leftover from previous invocation
	oaiStepDeleteOldOrderingTable = orderedAccountsIterStep(0)
	// create new ordering table
	oaiStepCreateOrderingTable = orderedAccountsIterStep(1)
	// query the existing accounts
	oaiStepQueryAccounts = orderedAccountsIterStep(2)
	// iterate over the existing accounts and insert their hash & address into the staging ordering table
	oaiStepInsertAccountData = orderedAccountsIterStep(3)
	// create an index on the ordering table so that we can efficiently scan it.
	oaiStepCreateOrderingAccountIndex = orderedAccountsIterStep(4)
	// query the ordering table
	oaiStepSelectFromOrderedTable = orderedAccountsIterStep(5)
	// iterate over the ordering table
	oaiStepIterateOverOrderedTable = orderedAccountsIterStep(6)
	// cleanup and delete ordering table
	oaiStepShutdown = orderedAccountsIterStep(7)
	// do nothing as we're done.
	oaiStepDone = orderedAccountsIterStep(8)
)

// orderedAccountsIter allows us to iterate over the accounts addresses in the order of the account hashes.
type orderedAccountsIter struct {
	step               orderedAccountsIterStep
	accountBaseRows    *sql.Rows
	hashesRows         *sql.Rows
	resourcesRows      *sql.Rows
	tx                 *sql.Tx
	pendingBaseRow     pendingBaseRow
	pendingResourceRow pendingResourceRow
	accountCount       int
	insertStmt         *sql.Stmt
}

// makeOrderedAccountsIter creates an ordered account iterator. Note that due to implementation reasons,
// only a single iterator can be active at a time.
func makeOrderedAccountsIter(tx *sql.Tx, accountCount int) *orderedAccountsIter {
	return &orderedAccountsIter{
		tx:           tx,
		accountCount: accountCount,
		step:         oaiStepStartup,
	}
}

type pendingBaseRow struct {
	addr               basics.Address
	rowid              int64
	accountData        *store.BaseAccountData
	encodedAccountData []byte
}

type pendingResourceRow struct {
	addrid int64
	aidx   basics.CreatableIndex
	buf    []byte
}

func processAllResources(
	resRows *sql.Rows,
	addr basics.Address, accountData *store.BaseAccountData, acctRowid int64, pr pendingResourceRow, resourceCount int,
	callback func(addr basics.Address, creatableIdx basics.CreatableIndex, resData *store.ResourcesData, encodedResourceData []byte, lastResource bool) error,
) (pendingResourceRow, int, error) {
	var err error
	count := 0

	// Declare variabled outside of the loop to prevent allocations per iteration.
	// At least resData is resolved as "escaped" because of passing it by a pointer to protocol.Decode()
	var buf []byte
	var addrid int64
	var aidx basics.CreatableIndex
	var resData store.ResourcesData
	for {
		if pr.addrid != 0 {
			// some accounts may not have resources, consider the following case:
			// acct 1 and 3 has resources, account 2 does not
			// in this case addrid = 3 after processing resources from 1, but acctRowid = 2
			// and we need to skip accounts without resources
			if pr.addrid > acctRowid {
				err = callback(addr, 0, nil, nil, false)
				return pr, count, err
			}
			if pr.addrid < acctRowid {
				err = fmt.Errorf("resource table entries mismatches accountbase table entries : reached addrid %d while expecting resource for %d", pr.addrid, acctRowid)
				return pendingResourceRow{}, count, err
			}
			addrid = pr.addrid
			buf = pr.buf
			aidx = pr.aidx
			pr = pendingResourceRow{}
		} else {
			if !resRows.Next() {
				err = callback(addr, 0, nil, nil, false)
				if err != nil {
					return pendingResourceRow{}, count, err
				}
				break
			}
			err = resRows.Scan(&addrid, &aidx, &buf)
			if err != nil {
				return pendingResourceRow{}, count, err
			}
			if addrid < acctRowid {
				err = fmt.Errorf("resource table entries mismatches accountbase table entries : reached addrid %d while expecting resource for %d", addrid, acctRowid)
				return pendingResourceRow{}, count, err
			} else if addrid > acctRowid {
				err = callback(addr, 0, nil, nil, false)
				return pendingResourceRow{addrid, aidx, buf}, count, err
			}
		}
		resData = store.ResourcesData{}
		err = protocol.Decode(buf, &resData)
		if err != nil {
			return pendingResourceRow{}, count, err
		}
		count++
		if resourceCount > 0 && count == resourceCount {
			// last resource to be included in chunk
			err := callback(addr, aidx, &resData, buf, true)
			return pendingResourceRow{}, count, err
		}
		err = callback(addr, aidx, &resData, buf, false)
		if err != nil {
			return pendingResourceRow{}, count, err
		}
	}
	return pendingResourceRow{}, count, nil
}

func processAllBaseAccountRecords(
	baseRows *sql.Rows,
	resRows *sql.Rows,
	baseCb func(addr basics.Address, rowid int64, accountData *store.BaseAccountData, encodedAccountData []byte) error,
	resCb func(addr basics.Address, creatableIdx basics.CreatableIndex, resData *store.ResourcesData, encodedResourceData []byte, lastResource bool) error,
	pendingBase pendingBaseRow, pendingResource pendingResourceRow, accountCount int, resourceCount int,
) (int, pendingBaseRow, pendingResourceRow, error) {
	var addr basics.Address
	var prevAddr basics.Address
	var err error
	count := 0

	var accountData store.BaseAccountData
	var addrbuf []byte
	var buf []byte
	var rowid int64
	for {
		if pendingBase.rowid != 0 {
			addr = pendingBase.addr
			rowid = pendingBase.rowid
			accountData = *pendingBase.accountData
			buf = pendingBase.encodedAccountData
			pendingBase = pendingBaseRow{}
		} else {
			if !baseRows.Next() {
				break
			}

			err = baseRows.Scan(&rowid, &addrbuf, &buf)
			if err != nil {
				return 0, pendingBaseRow{}, pendingResourceRow{}, err
			}

			if len(addrbuf) != len(addr) {
				err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
				return 0, pendingBaseRow{}, pendingResourceRow{}, err
			}

			copy(addr[:], addrbuf)

			accountData = store.BaseAccountData{}
			err = protocol.Decode(buf, &accountData)
			if err != nil {
				return 0, pendingBaseRow{}, pendingResourceRow{}, err
			}
		}

		err = baseCb(addr, rowid, &accountData, buf)
		if err != nil {
			return 0, pendingBaseRow{}, pendingResourceRow{}, err
		}

		var resourcesProcessed int
		pendingResource, resourcesProcessed, err = processAllResources(resRows, addr, &accountData, rowid, pendingResource, resourceCount, resCb)
		if err != nil {
			err = fmt.Errorf("failed to gather resources for account %v, addrid %d, prev address %v : %w", addr, rowid, prevAddr, err)
			return 0, pendingBaseRow{}, pendingResourceRow{}, err
		}

		if resourcesProcessed == resourceCount {
			// we're done with this iteration.
			pendingBase := pendingBaseRow{
				addr:               addr,
				rowid:              rowid,
				accountData:        &accountData,
				encodedAccountData: buf,
			}
			return count, pendingBase, pendingResource, nil
		}
		resourceCount -= resourcesProcessed

		count++
		if accountCount > 0 && count == accountCount {
			// we're done with this iteration.
			return count, pendingBaseRow{}, pendingResource, nil
		}
		prevAddr = addr
	}

	return count, pendingBaseRow{}, pendingResource, nil
}

// accountAddressHash is used by Next to return a single account address and the associated hash.
type accountAddressHash struct {
	addrid int64
	digest []byte
}

// Next returns an array containing the account address and hash
// the Next function works in multiple processing stages, where it first processes the current accounts and order them
// followed by returning the ordered accounts. In the first phase, it would return empty accountAddressHash array
// and sets the processedRecords to the number of accounts that were processed. On the second phase, the acct
// would contain valid data ( and optionally the account data as well, if was asked in makeOrderedAccountsIter) and
// the processedRecords would be zero. If err is sql.ErrNoRows it means that the iterator have completed it's work and no further
// accounts exists. Otherwise, the caller is expected to keep calling "Next" to retrieve the next set of accounts
// ( or let the Next function make some progress toward that goal )
func (iterator *orderedAccountsIter) Next(ctx context.Context) (acct []accountAddressHash, processedRecords int, err error) {
	if iterator.step == oaiStepDeleteOldOrderingTable {
		// although we're going to delete this table anyway when completing the iterator execution, we'll try to
		// clean up any intermediate table.
		_, err = iterator.tx.ExecContext(ctx, "DROP TABLE IF EXISTS accountsiteratorhashes")
		if err != nil {
			return
		}
		iterator.step = oaiStepCreateOrderingTable
		return
	}
	if iterator.step == oaiStepCreateOrderingTable {
		// create the temporary table
		_, err = iterator.tx.ExecContext(ctx, "CREATE TABLE accountsiteratorhashes(addrid INTEGER, hash blob)")
		if err != nil {
			return
		}
		iterator.step = oaiStepQueryAccounts
		return
	}
	if iterator.step == oaiStepQueryAccounts {
		// iterate over the existing accounts
		iterator.accountBaseRows, err = iterator.tx.QueryContext(ctx, "SELECT rowid, address, data FROM accountbase ORDER BY rowid")
		if err != nil {
			return
		}
		// iterate over the existing resources
		iterator.resourcesRows, err = iterator.tx.QueryContext(ctx, "SELECT addrid, aidx, data FROM resources ORDER BY addrid, aidx")
		if err != nil {
			return
		}
		// prepare the insert statement into the temporary table
		iterator.insertStmt, err = iterator.tx.PrepareContext(ctx, "INSERT INTO accountsiteratorhashes(addrid, hash) VALUES(?, ?)")
		if err != nil {
			return
		}
		iterator.step = oaiStepInsertAccountData
		return
	}
	if iterator.step == oaiStepInsertAccountData {
		var lastAddrID int64
		baseCb := func(addr basics.Address, rowid int64, accountData *store.BaseAccountData, encodedAccountData []byte) (err error) {
			hash := store.AccountHashBuilderV6(addr, accountData, encodedAccountData)
			_, err = iterator.insertStmt.ExecContext(ctx, rowid, hash)
			if err != nil {
				return
			}
			lastAddrID = rowid
			return nil
		}

		resCb := func(addr basics.Address, cidx basics.CreatableIndex, resData *store.ResourcesData, encodedResourceData []byte, lastResource bool) error {
			if resData != nil {
				hash, err := store.ResourcesHashBuilderV6(resData, addr, cidx, resData.UpdateRound, encodedResourceData)
				if err != nil {
					return err
				}
				_, err = iterator.insertStmt.ExecContext(ctx, lastAddrID, hash)
				return err
			}
			return nil
		}

		count := 0
		count, iterator.pendingBaseRow, iterator.pendingResourceRow, err = processAllBaseAccountRecords(
			iterator.accountBaseRows, iterator.resourcesRows,
			baseCb, resCb,
			iterator.pendingBaseRow, iterator.pendingResourceRow, iterator.accountCount, math.MaxInt,
		)
		if err != nil {
			iterator.Close(ctx)
			return
		}

		if count == iterator.accountCount {
			// we're done with this iteration.
			processedRecords = count
			return
		}

		// make sure the resource iterator has no more entries.
		if iterator.resourcesRows.Next() {
			iterator.Close(ctx)
			err = errors.New("resource table entries exceed the ones specified in the accountbase table")
			return
		}

		processedRecords = count
		iterator.accountBaseRows.Close()
		iterator.accountBaseRows = nil
		iterator.resourcesRows.Close()
		iterator.resourcesRows = nil
		iterator.insertStmt.Close()
		iterator.insertStmt = nil
		iterator.step = oaiStepCreateOrderingAccountIndex
		return
	}
	if iterator.step == oaiStepCreateOrderingAccountIndex {
		// create an index. It shown that even when we're making a single select statement in step 5, it would be better to have this index vs. not having it at all.
		// note that this index is using the rowid of the accountsiteratorhashes table.
		_, err = iterator.tx.ExecContext(ctx, "CREATE INDEX accountsiteratorhashesidx ON accountsiteratorhashes(hash)")
		if err != nil {
			iterator.Close(ctx)
			return
		}
		iterator.step = oaiStepSelectFromOrderedTable
		return
	}
	if iterator.step == oaiStepSelectFromOrderedTable {
		// select the data from the ordered table
		iterator.hashesRows, err = iterator.tx.QueryContext(ctx, "SELECT addrid, hash FROM accountsiteratorhashes ORDER BY hash")

		if err != nil {
			iterator.Close(ctx)
			return
		}
		iterator.step = oaiStepIterateOverOrderedTable
		return
	}

	if iterator.step == oaiStepIterateOverOrderedTable {
		acct = make([]accountAddressHash, iterator.accountCount)
		acctIdx := 0
		for iterator.hashesRows.Next() {
			err = iterator.hashesRows.Scan(&(acct[acctIdx].addrid), &(acct[acctIdx].digest))
			if err != nil {
				iterator.Close(ctx)
				return
			}
			acctIdx++
			if acctIdx == iterator.accountCount {
				// we're done with this iteration.
				return
			}
		}
		acct = acct[:acctIdx]
		iterator.step = oaiStepShutdown
		iterator.hashesRows.Close()
		iterator.hashesRows = nil
		return
	}
	if iterator.step == oaiStepShutdown {
		err = iterator.Close(ctx)
		if err != nil {
			return
		}
		iterator.step = oaiStepDone
		// fallthrough
	}
	return nil, 0, sql.ErrNoRows
}

// Close shuts down the orderedAccountsBuilderIter, releasing database resources.
func (iterator *orderedAccountsIter) Close(ctx context.Context) (err error) {
	if iterator.accountBaseRows != nil {
		iterator.accountBaseRows.Close()
		iterator.accountBaseRows = nil
	}
	if iterator.resourcesRows != nil {
		iterator.resourcesRows.Close()
		iterator.resourcesRows = nil
	}
	if iterator.hashesRows != nil {
		iterator.hashesRows.Close()
		iterator.hashesRows = nil
	}
	if iterator.insertStmt != nil {
		iterator.insertStmt.Close()
		iterator.insertStmt = nil
	}
	_, err = iterator.tx.ExecContext(ctx, "DROP TABLE IF EXISTS accountsiteratorhashes")
	return
}

// catchpointPendingHashesIterator allows us to iterate over the hashes in the catchpointpendinghashes table in their order.
type catchpointPendingHashesIterator struct {
	hashCount int
	tx        *sql.Tx
	rows      *sql.Rows
}

// makeCatchpointPendingHashesIterator create a pending hashes iterator that retrieves the hashes in the catchpointpendinghashes table.
func makeCatchpointPendingHashesIterator(hashCount int, tx *sql.Tx) *catchpointPendingHashesIterator {
	return &catchpointPendingHashesIterator{
		hashCount: hashCount,
		tx:        tx,
	}
}

// Next returns an array containing the hashes, returning HashCount hashes at a time.
func (iterator *catchpointPendingHashesIterator) Next(ctx context.Context) (hashes [][]byte, err error) {
	if iterator.rows == nil {
		iterator.rows, err = iterator.tx.QueryContext(ctx, "SELECT data FROM catchpointpendinghashes ORDER BY data")
		if err != nil {
			return
		}
	}

	// gather up to accountCount encoded accounts.
	hashes = make([][]byte, iterator.hashCount)
	hashIdx := 0
	for iterator.rows.Next() {
		err = iterator.rows.Scan(&hashes[hashIdx])
		if err != nil {
			iterator.Close()
			return
		}

		hashIdx++
		if hashIdx == iterator.hashCount {
			// we're done with this iteration.
			return
		}
	}
	hashes = hashes[:hashIdx]
	err = iterator.rows.Err()
	if err != nil {
		iterator.Close()
		return
	}
	// we just finished reading the table.
	iterator.Close()
	return
}

// Close shuts down the catchpointPendingHashesIterator, releasing database resources.
func (iterator *catchpointPendingHashesIterator) Close() {
	if iterator.rows != nil {
		iterator.rows.Close()
		iterator.rows = nil
	}
}
