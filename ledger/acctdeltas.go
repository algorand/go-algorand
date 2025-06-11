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
	"bytes"
	"context"
	"database/sql"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/encoded"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
)

// resourceDelta is used as part of the compactResourcesDeltas to describe a change to a single resource.
type resourceDelta struct {
	oldResource trackerdb.PersistedResourcesData
	newResource trackerdb.ResourcesData
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
	oldAcct     trackerdb.PersistedAccountData
	newAcct     trackerdb.BaseAccountData
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
	oldAcct           trackerdb.PersistedOnlineAccountData
	newAcct           []trackerdb.BaseOnlineAccountData
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
func prepareNormalizedBalancesV5(bals []encoded.BalanceRecordV5, rewardUnit uint64) (normalizedAccountBalances []trackerdb.NormalizedAccountBalance, err error) {
	normalizedAccountBalances = make([]trackerdb.NormalizedAccountBalance, len(bals))
	for i, balance := range bals {
		normalizedAccountBalances[i].Address = balance.Address
		var accountDataV5 basics.AccountData
		err = protocol.Decode(balance.AccountData, &accountDataV5)
		if err != nil {
			return nil, err
		}
		normalizedAccountBalances[i].AccountData.SetAccountData(&accountDataV5)
		normalizedAccountBalances[i].NormalizedBalance = accountDataV5.NormalizedOnlineBalance(rewardUnit)
		type resourcesRow struct {
			aidx basics.CreatableIndex
			trackerdb.ResourcesData
		}
		var resources []resourcesRow
		addResourceRow := func(_ context.Context, _ int64, aidx basics.CreatableIndex, rd *trackerdb.ResourcesData) error {
			resources = append(resources, resourcesRow{aidx: aidx, ResourcesData: *rd})
			return nil
		}
		if err = trackerdb.AccountDataResources(context.Background(), &accountDataV5, 0, addResourceRow); err != nil {
			return nil, err
		}
		normalizedAccountBalances[i].AccountHashes = make([][]byte, 1)
		normalizedAccountBalances[i].AccountHashes[0] = trackerdb.AccountHashBuilder(balance.Address, accountDataV5, balance.AccountData)
		if len(resources) > 0 {
			normalizedAccountBalances[i].Resources = make(map[basics.CreatableIndex]trackerdb.ResourcesData, len(resources))
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

// prepareNormalizedBalancesV6 converts an array of encoded.BalanceRecordV6 into an equal size array of normalizedAccountBalances.
func prepareNormalizedBalancesV6(bals []encoded.BalanceRecordV6, proto config.ConsensusParams) (normalizedAccountBalances []trackerdb.NormalizedAccountBalance, err error) {
	normalizedAccountBalances = make([]trackerdb.NormalizedAccountBalance, len(bals))
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
			proto.RewardUnit)
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
			normalizedAccountBalances[i].AccountHashes[0] = trackerdb.AccountHashBuilderV6(balance.Address, &normalizedAccountBalances[i].AccountData, balance.AccountData)
			curHashIdx++
		}
		if len(balance.Resources) > 0 {
			normalizedAccountBalances[i].Resources = make(map[basics.CreatableIndex]trackerdb.ResourcesData, len(balance.Resources))
			normalizedAccountBalances[i].EncodedResources = make(map[basics.CreatableIndex][]byte, len(balance.Resources))
			for cidx, res := range balance.Resources {
				var resData trackerdb.ResourcesData
				err = protocol.Decode(res, &resData)
				if err != nil {
					return nil, err
				}
				normalizedAccountBalances[i].AccountHashes[curHashIdx], err = trackerdb.ResourcesHashBuilderV6(&resData, balance.Address, basics.CreatableIndex(cidx), resData.UpdateRound, res)
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
					newResource: trackerdb.MakeResourcesData(deltaRound * updateRoundMultiplier),
				}
				newEntry.newResource.SetAssetData(res.Params, res.Holding)
				// baseResources caches deleted entries, and they have addrid = 0
				// need to handle this and prevent such entries to be treated as fully resolved
				baseResourceData, has := baseResources.read(res.Addr, basics.CreatableIndex(res.Aidx))
				existingAcctCacheEntry := has && baseResourceData.AcctRef != nil
				if existingAcctCacheEntry {
					newEntry.oldResource = baseResourceData
					outResourcesDeltas.insert(newEntry)
				} else {
					if pad, has := baseAccounts.read(res.Addr); has {
						newEntry.oldResource = trackerdb.PersistedResourcesData{AcctRef: pad.Ref}
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
					newResource: trackerdb.MakeResourcesData(deltaRound * updateRoundMultiplier),
				}
				newEntry.newResource.SetAppData(res.Params, res.State)
				baseResourceData, has := baseResources.read(res.Addr, basics.CreatableIndex(res.Aidx))
				existingAcctCacheEntry := has && baseResourceData.AcctRef != nil
				if existingAcctCacheEntry {
					newEntry.oldResource = baseResourceData
					outResourcesDeltas.insert(newEntry)
				} else {
					if pad, has := baseAccounts.read(res.Addr); has {
						newEntry.oldResource = trackerdb.PersistedResourcesData{AcctRef: pad.Ref}
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
func (a *compactResourcesDeltas) resourcesLoadOld(tx trackerdb.TransactionScope, knownAddresses map[basics.Address]trackerdb.AccountRef) (err error) {
	if len(a.misses) == 0 {
		return nil
	}
	ar, err := tx.MakeAccountsReader()
	if err != nil {
		return err
	}

	defer func() {
		a.misses = nil
	}()
	var acctRef trackerdb.AccountRef
	var aidx basics.CreatableIndex
	var resDataBuf []byte
	var ok bool
	for _, missIdx := range a.misses {
		delta := a.deltas[missIdx]
		addr := delta.address
		aidx = delta.oldResource.Aidx
		if delta.oldResource.AcctRef != nil {
			acctRef = delta.oldResource.AcctRef
		} else if acctRef, ok = knownAddresses[addr]; !ok {
			acctRef, err = ar.LookupAccountRowID(addr)
			if err != nil {
				if err != sql.ErrNoRows && err != trackerdb.ErrNotFound {
					err = fmt.Errorf("base account cannot be read while processing resource for addr=%s, aidx=%d: %w", addr.String(), aidx, err)
					return err

				}
				// not having an account could be legit : the account might not have been created yet, which is why it won't
				// have a rowid. We will be able to re-test that after all the baseAccountData would be written to disk.
				err = nil
				continue
			}
		}
		resDataBuf, err = ar.LookupResourceDataByAddrID(acctRef, aidx)
		switch err {
		case nil:
			if len(resDataBuf) > 0 {
				persistedResData := trackerdb.PersistedResourcesData{AcctRef: acctRef, Aidx: aidx}
				err = protocol.Decode(resDataBuf, &persistedResData.Data)
				if err != nil {
					return err
				}
				a.updateOld(missIdx, persistedResData)
			} else {
				err = fmt.Errorf("empty resource record: addrid=%d, aidx=%d", acctRef, aidx)
				return err
			}
		case trackerdb.ErrNotFound:
			// we don't have that account, just return an empty record.
			a.updateOld(missIdx, trackerdb.PersistedResourcesData{AcctRef: acctRef, Aidx: aidx})
			err = nil
		case sql.ErrNoRows:
			// we don't have that account, just return an empty record.
			a.updateOld(missIdx, trackerdb.PersistedResourcesData{AcctRef: acctRef, Aidx: aidx})
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
func (a *compactResourcesDeltas) updateOld(idx int, old trackerdb.PersistedResourcesData) {
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
					newAcct: trackerdb.BaseAccountData{
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
func (a *compactAccountDeltas) accountsLoadOld(tx trackerdb.TransactionScope) (err error) {
	// TODO: this function only needs a reader's scope to the datastore
	if len(a.misses) == 0 {
		return nil
	}
	arw, err := tx.MakeAccountsOptimizedReader()
	if err != nil {
		return err
	}

	defer func() {
		a.misses = nil
	}()
	for _, idx := range a.misses {
		addr := a.deltas[idx].address
		data, err := arw.LookupAccount(addr)
		if err != nil {
			// unexpected error - let the caller know that we couldn't complete the operation.
			return err
		}
		// update the account
		a.updateOld(idx, data)
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
func (a *compactAccountDeltas) updateOld(idx int, old trackerdb.PersistedAccountData) {
	a.deltas[idx].oldAcct = old
}

func (c *onlineAccountDelta) append(acctDelta ledgercore.AccountData, deltaRound basics.Round) {
	var baseEntry trackerdb.BaseOnlineAccountData
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
func (a *compactOnlineAccountDeltas) accountsLoadOld(tx trackerdb.TransactionScope) (err error) {
	if len(a.misses) == 0 {
		return nil
	}
	ar, err := tx.MakeAccountsReader()
	if err != nil {
		return err
	}
	defer func() {
		a.misses = nil
	}()
	for _, idx := range a.misses {
		addr := a.deltas[idx].address
		ref, acctDataBuf, err := ar.LookupOnlineAccountDataByAddress(addr)
		switch err {
		case nil:
			if len(acctDataBuf) > 0 {
				persistedAcctData := &trackerdb.PersistedOnlineAccountData{Addr: addr, Ref: ref}
				err = protocol.Decode(acctDataBuf, &persistedAcctData.AccountData)
				if err != nil {
					return err
				}
				a.updateOld(idx, *persistedAcctData)
			} else {
				// empty data means offline account
				a.updateOld(idx, trackerdb.PersistedOnlineAccountData{Addr: addr, Ref: ref})
			}
		case trackerdb.ErrNotFound:
			// we don't have that account, just return an empty record.
			a.updateOld(idx, trackerdb.PersistedOnlineAccountData{Addr: addr})
		// TODO: phase out sql.ErrNoRows
		case sql.ErrNoRows:
			// we don't have that account, just return an empty record.
			a.updateOld(idx, trackerdb.PersistedOnlineAccountData{Addr: addr})
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
func (a *compactOnlineAccountDeltas) updateOld(idx int, old trackerdb.PersistedOnlineAccountData) {
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
		NormalizedOnlineBalance: ad.NormalizedOnlineBalance(proto.RewardUnit),
		VoteFirstValid:          ad.VoteFirstValid,
		VoteLastValid:           ad.VoteLastValid,
		StateProofID:            ad.StateProofID,
	}
}

// accountsNewRound is a convenience wrapper for accountsNewRoundImpl
func accountsNewRound(
	tx trackerdb.TransactionScope,
	updates compactAccountDeltas, resources compactResourcesDeltas, kvPairs map[string]modifiedKvValue, creatables map[basics.CreatableIndex]ledgercore.ModifiedCreatable,
	proto config.ConsensusParams, lastUpdateRound basics.Round,
) (updatedAccounts []trackerdb.PersistedAccountData, updatedResources map[basics.Address][]trackerdb.PersistedResourcesData, updatedKVs map[string]trackerdb.PersistedKVData, err error) {
	hasAccounts := updates.len() > 0
	hasResources := resources.len() > 0
	hasKvPairs := len(kvPairs) > 0
	hasCreatables := len(creatables) > 0

	writer, err := tx.MakeAccountsOptimizedWriter(hasAccounts, hasResources, hasKvPairs, hasCreatables)
	if err != nil {
		return
	}
	defer writer.Close()

	return accountsNewRoundImpl(writer, updates, resources, kvPairs, creatables, proto, lastUpdateRound)
}

func onlineAccountsNewRound(
	tx trackerdb.TransactionScope,
	updates compactOnlineAccountDeltas,
	proto config.ConsensusParams, lastUpdateRound basics.Round,
) (updatedAccounts []trackerdb.PersistedOnlineAccountData, err error) {
	hasAccounts := updates.len() > 0

	writer, err := tx.MakeOnlineAccountsOptimizedWriter(hasAccounts)
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
	writer trackerdb.AccountsWriter,
	updates compactAccountDeltas, resources compactResourcesDeltas, kvPairs map[string]modifiedKvValue, creatables map[basics.CreatableIndex]ledgercore.ModifiedCreatable,
	proto config.ConsensusParams, lastUpdateRound basics.Round,
) (updatedAccounts []trackerdb.PersistedAccountData, updatedResources map[basics.Address][]trackerdb.PersistedResourcesData, updatedKVs map[string]trackerdb.PersistedKVData, err error) {
	updatedAccounts = make([]trackerdb.PersistedAccountData, updates.len())
	updatedAccountIdx := 0
	newAddressesRowIDs := make(map[basics.Address]trackerdb.AccountRef)
	for i := 0; i < updates.len(); i++ {
		data := updates.getByIdx(i)
		if data.oldAcct.Ref == nil {
			// zero rowid means we don't have a previous value.
			if data.newAcct.IsEmpty() {
				// IsEmpty means we don't have a previous value. Note, can't use newAcct.MsgIsZero
				// because of non-zero UpdateRound field in a new delta
				// if we didn't had it before, and we don't have anything now, just skip it.
			} else {
				// create a new entry.
				var ref trackerdb.AccountRef
				normBalance := data.newAcct.NormalizedOnlineBalance(proto.RewardUnit)
				ref, err = writer.InsertAccount(data.address, normBalance, data.newAcct)
				if err != nil {
					return nil, nil, nil, err
				}
				updatedAccounts[updatedAccountIdx].Ref = ref
				updatedAccounts[updatedAccountIdx].AccountData = data.newAcct
				newAddressesRowIDs[data.address] = ref
			}
		} else {
			// non-zero rowid means we had a previous value.
			if data.newAcct.IsEmpty() {
				// new value is zero, which means we need to delete the current value.
				var rowsAffected int64
				rowsAffected, err = writer.DeleteAccount(data.oldAcct.Ref)
				if err != nil {
					return nil, nil, nil, err
				}
				// we deleted the entry successfully.
				updatedAccounts[updatedAccountIdx].Ref = nil
				updatedAccounts[updatedAccountIdx].AccountData = trackerdb.BaseAccountData{}
				if rowsAffected != 1 {
					err = fmt.Errorf("failed to delete accountbase row for account %v, rowid %d", data.address, data.oldAcct.Ref)
					return nil, nil, nil, err
				}
			} else {
				var rowsAffected int64
				normBalance := data.newAcct.NormalizedOnlineBalance(proto.RewardUnit)
				rowsAffected, err = writer.UpdateAccount(data.oldAcct.Ref, normBalance, data.newAcct)
				if err != nil {
					return nil, nil, nil, err
				}
				// rowid doesn't change on update.
				updatedAccounts[updatedAccountIdx].Ref = data.oldAcct.Ref
				updatedAccounts[updatedAccountIdx].AccountData = data.newAcct
				if rowsAffected != 1 {
					err = fmt.Errorf("failed to update accountbase row for account %v, rowid %d", data.address, data.oldAcct.Ref)
					return nil, nil, nil, err
				}
			}
		}

		// set the returned persisted account states so that we could store that as the baseAccounts in commitRound
		updatedAccounts[updatedAccountIdx].Round = lastUpdateRound
		updatedAccounts[updatedAccountIdx].Addr = data.address
		updatedAccountIdx++
	}

	updatedResources = make(map[basics.Address][]trackerdb.PersistedResourcesData)

	// the resources update is going to be made in three parts:
	// on the first loop, we will find out all the entries that need to be deleted, and parepare a pendingResourcesDeletion map.
	// on the second loop, we will perform update/insertion. when considering inserting, we would test the pendingResourcesDeletion to see
	// if the said entry was scheduled to be deleted. If so, we would "upgrade" the insert operation into an update operation.
	// on the last loop, we would delete the remainder of the resource entries that were detected in loop #1 and were not upgraded in loop #2.
	// the rationale behind this is that addrid might get reused, and we need to ensure
	// that at all times there are no two representations of the same entry in the resources table.
	// ( which would trigger a constrain violation )
	type resourceKey struct {
		acctRef trackerdb.AccountRef
		aidx    basics.CreatableIndex
	}
	var pendingResourcesDeletion map[resourceKey]struct{} // map to indicate which resources need to be deleted
	for i := 0; i < resources.len(); i++ {
		data := resources.getByIdx(i)
		if data.oldResource.AcctRef == nil || data.oldResource.Data.IsEmpty() || !data.newResource.IsEmpty() {
			continue
		}
		if pendingResourcesDeletion == nil {
			pendingResourcesDeletion = make(map[resourceKey]struct{})
		}
		pendingResourcesDeletion[resourceKey{acctRef: data.oldResource.AcctRef, aidx: data.oldResource.Aidx}] = struct{}{}

		entry := trackerdb.PersistedResourcesData{AcctRef: nil, Aidx: data.oldResource.Aidx, Data: trackerdb.MakeResourcesData(0), Round: lastUpdateRound}
		deltas := updatedResources[data.address]
		deltas = append(deltas, entry)
		updatedResources[data.address] = deltas
	}

	for i := 0; i < resources.len(); i++ {
		data := resources.getByIdx(i)
		addr := data.address
		aidx := data.oldResource.Aidx
		acctRef := data.oldResource.AcctRef
		if acctRef == nil {
			// new entry, data.oldResource does not have addrid
			// check if this delta is part of in-memory only account
			// that is created, funded, transferred, and closed within a commit range
			inMemEntry := data.oldResource.Data.IsEmpty() && data.newResource.IsEmpty()
			acctRef = newAddressesRowIDs[addr]
			if acctRef == nil && !inMemEntry {
				err = fmt.Errorf("cannot resolve address %s (%d), aidx %d, data %v", addr.String(), acctRef, aidx, data.newResource)
				return nil, nil, nil, err
			}
		}
		var entry trackerdb.PersistedResourcesData
		if data.oldResource.Data.IsEmpty() {
			// IsEmpty means we don't have a previous value. Note, can't use oldResource.data.MsgIsZero
			// because of possibility of empty asset holdings or app local state after opting in,
			// as well as non-zero UpdateRound field in a new delta
			if data.newResource.IsEmpty() {
				// if we didn't had it before, and we don't have anything now, just skip it.
				// set zero addrid to mark this entry invalid for subsequent addr to addrid resolution
				// because the base account might gone.
				entry = trackerdb.PersistedResourcesData{AcctRef: nil, Aidx: aidx, Data: trackerdb.MakeResourcesData(0), Round: lastUpdateRound}
			} else {
				// create a new entry.
				if !data.newResource.IsApp() && !data.newResource.IsAsset() {
					err = fmt.Errorf("unknown creatable for addr %v (%d), aidx %d, data %v", addr, acctRef, aidx, data.newResource)
					return nil, nil, nil, err
				}
				// check if we need to "upgrade" this insert operation into an update operation due to a scheduled
				// delete operation of the same resource.
				if _, pendingDeletion := pendingResourcesDeletion[resourceKey{acctRef: acctRef, aidx: aidx}]; pendingDeletion {
					// yes - we've had this entry being deleted and re-created in the same commit range. This means that we can safely
					// update the database entry instead of deleting + inserting.
					delete(pendingResourcesDeletion, resourceKey{acctRef: acctRef, aidx: aidx})
					var rowsAffected int64
					rowsAffected, err = writer.UpdateResource(acctRef, aidx, data.newResource)
					if err != nil {
						return nil, nil, nil, err
					}
					// rowid doesn't change on update.
					entry = trackerdb.PersistedResourcesData{AcctRef: acctRef, Aidx: aidx, Data: data.newResource, Round: lastUpdateRound}
					if rowsAffected != 1 {
						err = fmt.Errorf("failed to update resources row for addr %s (%d), aidx %d", addr, acctRef, aidx)
						return nil, nil, nil, err
					}
				} else {
					_, err = writer.InsertResource(acctRef, aidx, data.newResource)
					if err != nil {
						return nil, nil, nil, err
					}
					// set the returned persisted account states so that we could store that as the baseResources in commitRound
					entry = trackerdb.PersistedResourcesData{AcctRef: acctRef, Aidx: aidx, Data: data.newResource, Round: lastUpdateRound}
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
					err = fmt.Errorf("unknown creatable for addr %v (%d), aidx %d, data %v", addr, acctRef, aidx, data.newResource)
					return nil, nil, nil, err
				}
				var rowsAffected int64
				rowsAffected, err = writer.UpdateResource(acctRef, aidx, data.newResource)
				if err != nil {
					return nil, nil, nil, err
				}
				// rowid doesn't change on update.
				entry = trackerdb.PersistedResourcesData{AcctRef: acctRef, Aidx: aidx, Data: data.newResource, Round: lastUpdateRound}
				if rowsAffected != 1 {
					err = fmt.Errorf("failed to update resources row for addr %s (%d), aidx %d", addr, acctRef, aidx)
					return nil, nil, nil, err
				}
			}
		}

		deltas := updatedResources[addr]
		deltas = append(deltas, entry)
		updatedResources[addr] = deltas
	}

	// last, we want to delete the resource table entries that are no longer needed.
	for delRes := range pendingResourcesDeletion {
		// new value is zero, which means we need to delete the current value.
		var rowsAffected int64
		rowsAffected, err = writer.DeleteResource(delRes.acctRef, delRes.aidx)
		if err != nil {
			return nil, nil, nil, err
		}
		// we deleted the entry successfully.
		// set zero addrid to mark this entry invalid for subsequent addr to addrid resolution
		// because the base account might gone.
		if rowsAffected != 1 {
			err = fmt.Errorf("failed to delete resources row (%d), aidx %d", delRes.acctRef, delRes.aidx)
			return nil, nil, nil, err
		}
	}

	updatedKVs = make(map[string]trackerdb.PersistedKVData, len(kvPairs))
	for key, mv := range kvPairs {
		if mv.data != nil {
			// reminder: check oldData for nil here, b/c bytes.Equal conflates nil and "".
			if mv.oldData != nil && bytes.Equal(mv.oldData, mv.data) {
				continue // changed back within the delta span
			}
			err = writer.UpsertKvPair(key, mv.data)
			if err != nil {
				return nil, nil, nil, err
			}
			updatedKVs[key] = trackerdb.PersistedKVData{Value: mv.data, Round: lastUpdateRound}
		} else {
			if mv.oldData == nil { // Came and went within the delta span
				continue
			}
			err = writer.DeleteKvPair(key)
			if err != nil {
				return nil, nil, nil, err
			}
			updatedKVs[key] = trackerdb.PersistedKVData{Value: nil, Round: lastUpdateRound}
		}
	}

	for cidx, cdelta := range creatables {
		if cdelta.Created {
			_, err = writer.InsertCreatable(cidx, cdelta.Ctype, cdelta.Creator[:])
		} else {
			_, err = writer.DeleteCreatable(cidx, cdelta.Ctype)
		}
		if err != nil {
			return nil, nil, nil, err
		}
	}

	return
}

func onlineAccountsNewRoundImpl(
	writer trackerdb.OnlineAccountsWriter, updates compactOnlineAccountDeltas,
	proto config.ConsensusParams, lastUpdateRound basics.Round,
) (updatedAccounts []trackerdb.PersistedOnlineAccountData, err error) {

	for i := 0; i < updates.len(); i++ {
		data := updates.getByIdx(i)
		prevAcct := data.oldAcct
		for j := 0; j < len(data.newAcct); j++ {
			newAcct := data.newAcct[j]
			updRound := data.updRound[j]
			newStatus := data.newStatus[j]
			if newStatus == basics.Online && newAcct.IsVotingEmpty() {
				return nil, fmt.Errorf("empty voting data for online account %s: %v", data.address, newAcct)
			}
			if prevAcct.Ref == nil { // zero rowid (nil Ref) means we don't have a previous value.
				if newStatus != basics.Online {
					continue // didn't exist, and not going online, we don't care.
				}

				// create a new entry.
				var ref trackerdb.OnlineAccountRef
				normBalance := newAcct.NormalizedOnlineBalance(proto.RewardUnit)
				ref, err = writer.InsertOnlineAccount(data.address, normBalance, newAcct, updRound, uint64(newAcct.VoteLastValid))
				if err != nil {
					return nil, err
				}
				updated := trackerdb.PersistedOnlineAccountData{
					Addr:        data.address,
					AccountData: newAcct,
					Round:       lastUpdateRound,
					Ref:         ref,
					UpdRound:    basics.Round(updRound),
				}
				updatedAccounts = append(updatedAccounts, updated)
				prevAcct = updated
			} else { // non-zero rowid (non-nil Ref) means we had a previous value.
				if newStatus == basics.Online {
					// was already online, so create an update only if something changed
					if prevAcct.AccountData != newAcct {
						var ref trackerdb.OnlineAccountRef
						normBalance := newAcct.NormalizedOnlineBalance(proto.RewardUnit)
						ref, err = writer.InsertOnlineAccount(data.address, normBalance, newAcct, updRound, uint64(newAcct.VoteLastValid))
						if err != nil {
							return nil, err
						}
						updated := trackerdb.PersistedOnlineAccountData{
							Addr:        data.address,
							AccountData: newAcct,
							Round:       lastUpdateRound,
							Ref:         ref,
							UpdRound:    basics.Round(updRound),
						}

						updatedAccounts = append(updatedAccounts, updated)
						prevAcct = updated
					}
				} else {
					if prevAcct.AccountData.IsVotingEmpty() && newStatus != basics.Online {
						// we are not using newAcct.IsVotingEmpty because new account comes from deltas,
						// and deltas are base (full) accounts, so that it can have status=offline and non-empty voting data
						// for suspended accounts.
						// it is not the same for online accounts where empty all offline accounts are stored with empty voting data.

						// if both old and new are offline, ignore
						// otherwise the following could happen:
						// 1. there are multiple offline account deltas so all of them could be inserted
						// 2. delta.oldAcct is often pulled from a cache that is only updated on new rows insert so
						// it could pull a very old already deleted offline value resulting one more insert
						continue
					}
					// "delete" by inserting a zero entry
					var ref trackerdb.OnlineAccountRef
					ref, err = writer.InsertOnlineAccount(data.address, 0, trackerdb.BaseOnlineAccountData{}, updRound, 0)
					if err != nil {
						return nil, err
					}
					updated := trackerdb.PersistedOnlineAccountData{
						Addr:        data.address,
						AccountData: trackerdb.BaseOnlineAccountData{},
						Round:       lastUpdateRound,
						Ref:         ref,
						UpdRound:    basics.Round(updRound),
					}

					updatedAccounts = append(updatedAccounts, updated)
					prevAcct = updated
				}
			}
		}
	}

	return
}
