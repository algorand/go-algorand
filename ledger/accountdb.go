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
	"time"

	"github.com/mattn/go-sqlite3"

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// accountsDbQueries is used to cache a prepared SQL statement to look up
// the state of a single account.
type accountsDbQueries struct {
	listCreatablesStmt          *sql.Stmt
	lookupStmt                  *sql.Stmt
	lookupResourcesStmt         *sql.Stmt
	lookupAllResourcesStmt      *sql.Stmt
	lookupKvPairStmt            *sql.Stmt
	lookupCreatorStmt           *sql.Stmt
	deleteStoredCatchpoint      *sql.Stmt
	insertStoredCatchpoint      *sql.Stmt
	selectOldestCatchpointFiles *sql.Stmt
	selectCatchpointStateUint64 *sql.Stmt
	deleteCatchpointState       *sql.Stmt
	insertCatchpointStateUint64 *sql.Stmt
	selectCatchpointStateString *sql.Stmt
	insertCatchpointStateString *sql.Stmt
}

var accountsSchema = []string{
	`CREATE TABLE IF NOT EXISTS acctrounds (
		id string primary key,
		rnd integer)`,
	`CREATE TABLE IF NOT EXISTS accounttotals (
		id string primary key,
		online integer,
		onlinerewardunits integer,
		offline integer,
		offlinerewardunits integer,
		notparticipating integer,
		notparticipatingrewardunits integer,
		rewardslevel integer)`,
	`CREATE TABLE IF NOT EXISTS accountbase (
		address blob primary key,
		data blob)`,
	`CREATE TABLE IF NOT EXISTS kvstore (
		key blob primary key,
		value blob)`,
	`CREATE TABLE IF NOT EXISTS assetcreators (
		asset integer primary key,
		creator blob)`,
	`CREATE TABLE IF NOT EXISTS storedcatchpoints (
		round integer primary key,
		filename text NOT NULL,
		catchpoint text NOT NULL,
		filesize size NOT NULL,
		pinned integer NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS accounthashes (
		id integer primary key,
		data blob)`,
	`CREATE TABLE IF NOT EXISTS catchpointstate (
		id string primary key,
		intval integer,
		strval text)`,
}

// TODO: Post applications, rename assetcreators -> creatables and rename
// 'asset' column -> 'creatable'
var creatablesMigration = []string{
	`ALTER TABLE assetcreators ADD COLUMN ctype INTEGER DEFAULT 0`,
}

// createNormalizedOnlineBalanceIndex handles accountbase/catchpointbalances tables
func createNormalizedOnlineBalanceIndex(idxname string, tablename string) string {
	return fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s
		ON %s ( normalizedonlinebalance, address, data )
		WHERE normalizedonlinebalance>0`, idxname, tablename)
}

func createUniqueAddressBalanceIndex(idxname string, tablename string) string {
	return fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (address)`, idxname, tablename)
}

var createOnlineAccountIndex = []string{
	`ALTER TABLE accountbase
		ADD COLUMN normalizedonlinebalance INTEGER`,
	createNormalizedOnlineBalanceIndex("onlineaccountbals", "accountbase"),
}

var createResourcesTable = []string{
	`CREATE TABLE IF NOT EXISTS resources (
		addrid INTEGER NOT NULL,
		aidx INTEGER NOT NULL,
		data BLOB NOT NULL,
		PRIMARY KEY (addrid, aidx) ) WITHOUT ROWID`,
}

var accountsResetExprs = []string{
	`DROP TABLE IF EXISTS acctrounds`,
	`DROP TABLE IF EXISTS accounttotals`,
	`DROP TABLE IF EXISTS accountbase`,
	`DROP TABLE IF EXISTS assetcreators`,
	`DROP TABLE IF EXISTS storedcatchpoints`,
	`DROP TABLE IF EXISTS catchpointstate`,
	`DROP TABLE IF EXISTS accounthashes`,
	`DROP TABLE IF EXISTS resources`,
}

// accountDBVersion is the database version that this binary would know how to support and how to upgrade to.
// details about the content of each of the versions can be found in the upgrade functions upgradeDatabaseSchemaXXXX
// and their descriptions.
var accountDBVersion = int32(6)

// persistedAccountData is used for representing a single account stored on the disk. In addition to the
// basics.AccountData, it also stores complete referencing information used to maintain the base accounts
// list.
type persistedAccountData struct {
	// The address of the account. In contrasts to maps, having this value explicitly here allows us to use this
	// data structure in queues directly, without "attaching" the address as the address as the map key.
	addr basics.Address
	// The underlaying account data
	accountData baseAccountData
	// The rowid, when available. If the entry was loaded from the disk, then we have the rowid for it. Entries
	// that doesn't have rowid ( hence, rowid == 0 ) represent either deleted accounts or non-existing accounts.
	rowid int64
	// the round number that is associated with the accountData. This field is needed so that we can maintain a correct
	// lruAccounts cache. We use it to ensure that the entries on the lruAccounts.accountsList are the latest ones.
	// this becomes an issue since while we attempt to write an update to disk, we might be reading an entry and placing
	// it on the lruAccounts.pendingAccounts; The commitRound doesn't attempt to flush the pending accounts, but rather
	// just write the latest ( which is correct ) to the lruAccounts.accountsList. later on, during on newBlockImpl, we
	// want to ensure that the "real" written value isn't being overridden by the value from the pending accounts.
	round basics.Round
}

//msgp:ignore persistedResourcesData
type persistedResourcesData struct {
	// addrid is the rowid of the account address that holds this resource.
	// it is used in update/delete operations so must be filled for existing records.
	// resolution is a multi stage process:
	// - baseResources cache might have valid entries
	// - baseAccount cache might have an entry for the address with rowid set
	// - when loading non-cached resources in resourcesLoadOld
	// - when creating new accounts in accountsNewRound
	addrid int64
	// creatable index
	aidx basics.CreatableIndex
	// actual resource data
	data resourcesData
	// the round number that is associated with the resourcesData. This field is the corresponding one to the round field
	// in persistedAccountData, and serves the same purpose.
	round basics.Round
}

func (prd *persistedResourcesData) AccountResource() ledgercore.AccountResource {
	var ret ledgercore.AccountResource
	if prd.data.IsAsset() {
		if prd.data.IsHolding() {
			holding := prd.data.GetAssetHolding()
			ret.AssetHolding = &holding
		}
		if prd.data.IsOwning() {
			assetParams := prd.data.GetAssetParams()
			ret.AssetParams = &assetParams
		}
	}
	if prd.data.IsApp() {
		if prd.data.IsHolding() {
			localState := prd.data.GetAppLocalState()
			ret.AppLocalState = &localState
		}
		if prd.data.IsOwning() {
			appParams := prd.data.GetAppParams()
			ret.AppParams = &appParams
		}
	}
	return ret
}

// resourceDelta is used as part of the compactResourcesDeltas to describe a change to a single resource.
type resourceDelta struct {
	oldResource persistedResourcesData
	newResource resourcesData
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
	oldAcct     persistedAccountData
	newAcct     baseAccountData
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

// catchpointState is used to store catchpoint related variables into the catchpointstate table.
type catchpointState string

const (
	// catchpointStateLastCatchpoint is written by a node once a catchpoint label is created for a round
	catchpointStateLastCatchpoint = catchpointState("lastCatchpoint")
	// catchpointStateWritingCatchpoint is written by a node while a catchpoint file is being created. It gets deleted once the file
	// creation is complete, and used as a way to record the fact that we've started generating the catchpoint file for that particular
	// round.
	catchpointStateWritingCatchpoint = catchpointState("writingCatchpoint")
	// catchpointCatchupState is the state of the catchup process. The variable is stored only during the catchpoint catchup process, and removed afterward.
	catchpointStateCatchupState = catchpointState("catchpointCatchupState")
	// catchpointStateCatchupLabel is the label to which the currently catchpoint catchup process is trying to catchup to.
	catchpointStateCatchupLabel = catchpointState("catchpointCatchupLabel")
	// catchpointCatchupBlockRound is the block round that is associated with the current running catchpoint catchup.
	catchpointStateCatchupBlockRound = catchpointState("catchpointCatchupBlockRound")
	// catchpointStateCatchupBalancesRound is the balance round that is associated with the current running catchpoint catchup. Typically it would be
	// equal to catchpointStateCatchupBlockRound - 320.
	catchpointStateCatchupBalancesRound = catchpointState("catchpointCatchupBalancesRound")
	// catchpointStateCatchupHashRound is the round that is associated with the hash of the merkle trie. Normally, it's identical to catchpointStateCatchupBalancesRound,
	// however, it could differ when we catchup from a catchpoint that was created using a different version : in this case,
	// we set it to zero in order to reset the merkle trie. This would force the merkle trie to be re-build on startup ( if needed ).
	catchpointStateCatchupHashRound = catchpointState("catchpointCatchupHashRound")
)

// normalizedAccountBalance is a staging area for a catchpoint file account information before it's being added to the catchpoint staging tables.
type normalizedAccountBalance struct {
	// The public key address to which the account belongs.
	address basics.Address
	// accountData contains the baseAccountData for that account.
	accountData baseAccountData
	// resources is a map, where the key is the creatable index, and the value is the resource data.
	resources map[basics.CreatableIndex]resourcesData
	// encodedAccountData contains the baseAccountData encoded bytes that are going to be written to the accountbase table.
	encodedAccountData []byte
	// accountHashes contains a list of all the hashes that would need to be added to the merkle trie for that account.
	// on V6, we could have multiple hashes, since we have separate account/resource hashes.
	accountHashes [][]byte
	// normalizedBalance contains the normalized balance for the account.
	normalizedBalance uint64
	// encodedResources provides the encoded form of the resources
	encodedResources map[basics.CreatableIndex][]byte
}

// prepareNormalizedBalancesV5 converts an array of encodedBalanceRecordV5 into an equal size array of normalizedAccountBalances.
func prepareNormalizedBalancesV5(bals []encodedBalanceRecordV5, proto config.ConsensusParams) (normalizedAccountBalances []normalizedAccountBalance, err error) {
	normalizedAccountBalances = make([]normalizedAccountBalance, len(bals))
	for i, balance := range bals {
		normalizedAccountBalances[i].address = balance.Address
		var accountDataV5 basics.AccountData
		err = protocol.Decode(balance.AccountData, &accountDataV5)
		if err != nil {
			return nil, err
		}
		normalizedAccountBalances[i].accountData.SetAccountData(&accountDataV5)
		normalizedAccountBalances[i].normalizedBalance = accountDataV5.NormalizedOnlineBalance(proto)
		type resourcesRow struct {
			aidx basics.CreatableIndex
			resourcesData
		}
		var resources []resourcesRow
		addResourceRow := func(_ context.Context, _ int64, aidx basics.CreatableIndex, rd *resourcesData) error {
			resources = append(resources, resourcesRow{aidx: aidx, resourcesData: *rd})
			return nil
		}
		if err = accountDataResources(context.Background(), &accountDataV5, 0, addResourceRow); err != nil {
			return nil, err
		}
		normalizedAccountBalances[i].accountHashes = make([][]byte, 1)
		normalizedAccountBalances[i].accountHashes[0] = accountHashBuilder(balance.Address, accountDataV5, balance.AccountData)
		if len(resources) > 0 {
			normalizedAccountBalances[i].resources = make(map[basics.CreatableIndex]resourcesData, len(resources))
			normalizedAccountBalances[i].encodedResources = make(map[basics.CreatableIndex][]byte, len(resources))
		}
		for _, resource := range resources {
			normalizedAccountBalances[i].resources[resource.aidx] = resource.resourcesData
			normalizedAccountBalances[i].encodedResources[resource.aidx] = protocol.Encode(&resource.resourcesData)
		}
		normalizedAccountBalances[i].encodedAccountData = protocol.Encode(&normalizedAccountBalances[i].accountData)
	}
	return
}

// prepareNormalizedBalancesV6 converts an array of encodedBalanceRecordV6 into an equal size array of normalizedAccountBalances.
func prepareNormalizedBalancesV6(bals []encodedBalanceRecordV6, proto config.ConsensusParams) (normalizedAccountBalances []normalizedAccountBalance, err error) {
	normalizedAccountBalances = make([]normalizedAccountBalance, len(bals))
	for i, balance := range bals {
		normalizedAccountBalances[i].address = balance.Address
		err = protocol.Decode(balance.AccountData, &(normalizedAccountBalances[i].accountData))
		if err != nil {
			return nil, err
		}
		normalizedAccountBalances[i].normalizedBalance = basics.NormalizedOnlineAccountBalance(
			normalizedAccountBalances[i].accountData.Status,
			normalizedAccountBalances[i].accountData.RewardsBase,
			normalizedAccountBalances[i].accountData.MicroAlgos,
			proto)
		normalizedAccountBalances[i].encodedAccountData = balance.AccountData
		normalizedAccountBalances[i].accountHashes = make([][]byte, 1+len(balance.Resources))
		normalizedAccountBalances[i].accountHashes[0] = accountHashBuilderV6(balance.Address, &normalizedAccountBalances[i].accountData, balance.AccountData)
		if len(balance.Resources) > 0 {
			normalizedAccountBalances[i].resources = make(map[basics.CreatableIndex]resourcesData, len(balance.Resources))
			normalizedAccountBalances[i].encodedResources = make(map[basics.CreatableIndex][]byte, len(balance.Resources))
			resIdx := 0
			for cidx, res := range balance.Resources {
				var resData resourcesData
				err = protocol.Decode(res, &resData)
				if err != nil {
					return nil, err
				}
				var ctype basics.CreatableType
				if resData.IsAsset() {
					ctype = basics.AssetCreatable
				} else if resData.IsApp() {
					ctype = basics.AppCreatable
				} else {
					err = fmt.Errorf("unknown creatable for addr %s, aidx %d, data %v", balance.Address.String(), cidx, resData)
				}
				normalizedAccountBalances[i].accountHashes[resIdx+1] = resourcesHashBuilderV6(balance.Address, basics.CreatableIndex(cidx), ctype, resData.UpdateRound, res)
				normalizedAccountBalances[i].resources[basics.CreatableIndex(cidx)] = resData
				normalizedAccountBalances[i].encodedResources[basics.CreatableIndex(cidx)] = res
				resIdx++
			}
		}
	}
	return
}

// makeCompactResourceDeltas takes an array of AccountDeltas ( one array entry per round ), and compacts the resource portions of the arrays into a single
// data structure that contains all the resources deltas changes. While doing that, the function eliminate any intermediate resources changes.
// It counts the number of changes each account get modified across the round range by specifying it in the nAcctDeltas field of the resourcesDeltas.
func makeCompactResourceDeltas(accountDeltas []ledgercore.AccountDeltas, baseRound basics.Round, setUpdateRound bool, baseAccounts lruAccounts, baseResources lruResources) (outResourcesDeltas compactResourcesDeltas) {
	if len(accountDeltas) == 0 {
		return
	}

	// the sizes of the maps here aren't super accurate, but would hopefully be a rough estimate for a reasonable starting point.
	size := accountDeltas[0].Len()*len(accountDeltas) + 1
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
	for _, roundDelta := range accountDeltas {
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
					newResource: makeResourcesData(deltaRound * updateRoundMultiplier),
				}
				newEntry.newResource.SetAssetData(res.Params, res.Holding)
				// baseResources caches deleted entries, and they have addrid = 0
				// need to handle this and prevent such entries to be treated as fully resolved
				baseResourceData, has := baseResources.read(res.Addr, basics.CreatableIndex(res.Aidx))
				existingAcctCacheEntry := has && baseResourceData.addrid != 0
				if existingAcctCacheEntry {
					newEntry.oldResource = baseResourceData
					outResourcesDeltas.insert(newEntry)
				} else {
					if pad, has := baseAccounts.read(res.Addr); has {
						newEntry.oldResource = persistedResourcesData{addrid: pad.rowid}
					}
					newEntry.oldResource.aidx = basics.CreatableIndex(res.Aidx)
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
					newResource: makeResourcesData(deltaRound * updateRoundMultiplier),
				}
				newEntry.newResource.SetAppData(res.Params, res.State)
				baseResourceData, has := baseResources.read(res.Addr, basics.CreatableIndex(res.Aidx))
				existingAcctCacheEntry := has && baseResourceData.addrid != 0
				if existingAcctCacheEntry {
					newEntry.oldResource = baseResourceData
					outResourcesDeltas.insert(newEntry)
				} else {
					if pad, has := baseAccounts.read(res.Addr); has {
						newEntry.oldResource = persistedResourcesData{addrid: pad.rowid}
					}
					newEntry.oldResource.aidx = basics.CreatableIndex(res.Aidx)
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
		aidx = delta.oldResource.aidx
		if delta.oldResource.addrid != 0 {
			addrid = delta.oldResource.addrid
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
				persistedResData := persistedResourcesData{addrid: addrid, aidx: aidx}
				err = protocol.Decode(resDataBuf, &persistedResData.data)
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
			a.updateOld(missIdx, persistedResourcesData{addrid: addrid, aidx: aidx})
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
	a.cache[accountCreatable{address: delta.address, index: delta.oldResource.aidx}] = last
	return last
}

func (a *compactResourcesDeltas) insertMissing(delta resourceDelta) {
	a.misses = append(a.misses, a.insert(delta))
}

// updateOld updates existing or inserts a new partial entry with only old field filled
func (a *compactResourcesDeltas) updateOld(idx int, old persistedResourcesData) {
	a.deltas[idx].oldResource = old
}

// makeCompactAccountDeltas takes an array of account AccountDeltas ( one array entry per round ), and compacts the arrays into a single
// data structure that contains all the account deltas changes. While doing that, the function eliminate any intermediate account changes.
// It counts the number of changes each account get modified across the round range by specifying it in the nAcctDeltas field of the accountDeltaCount/modifiedCreatable.
func makeCompactAccountDeltas(accountDeltas []ledgercore.AccountDeltas, baseRound basics.Round, setUpdateRound bool, baseAccounts lruAccounts) (outAccountDeltas compactAccountDeltas) {
	if len(accountDeltas) == 0 {
		return
	}

	// the sizes of the maps here aren't super accurate, but would hopefully be a rough estimate for a reasonable starting point.
	size := accountDeltas[0].Len()*len(accountDeltas) + 1
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
	for _, roundDelta := range accountDeltas {
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
					newAcct: baseAccountData{
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
				persistedAcctData := &persistedAccountData{addr: addr, rowid: rowid.Int64}
				err = protocol.Decode(acctDataBuf, &persistedAcctData.accountData)
				if err != nil {
					return err
				}
				a.updateOld(idx, *persistedAcctData)
			} else {
				// to retain backward compatibility, we will treat this condition as if we don't have the account.
				a.updateOld(idx, persistedAccountData{addr: addr, rowid: rowid.Int64})
			}
		case sql.ErrNoRows:
			// we don't have that account, just return an empty record.
			a.updateOld(idx, persistedAccountData{addr: addr})
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
func (a *compactAccountDeltas) updateOld(idx int, old persistedAccountData) {
	a.deltas[idx].oldAcct = old
}

// writeCatchpointStagingBalances inserts all the account balances in the provided array into the catchpoint balance staging table catchpointbalances.
func writeCatchpointStagingBalances(ctx context.Context, tx *sql.Tx, bals []normalizedAccountBalance) error {
	insertAcctStmt, err := tx.PrepareContext(ctx, "INSERT INTO catchpointbalances(address, normalizedonlinebalance, data) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}

	var insertRscStmt *sql.Stmt
	insertRscStmt, err = tx.PrepareContext(ctx, "INSERT INTO catchpointresources(addrid, aidx, data) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}

	var result sql.Result
	var rowID int64
	for _, balance := range bals {
		result, err = insertAcctStmt.ExecContext(ctx, balance.address[:], balance.normalizedBalance, balance.encodedAccountData)
		if err != nil {
			return err
		}
		aff, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if aff != 1 {
			return fmt.Errorf("number of affected record in insert was expected to be one, but was %d", aff)
		}
		rowID, err = result.LastInsertId()
		if err != nil {
			return err
		}
		// write resources
		for aidx := range balance.resources {
			result, err := insertRscStmt.ExecContext(ctx, rowID, aidx, balance.encodedResources[aidx])
			if err != nil {
				return err
			}
			aff, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if aff != 1 {
				return fmt.Errorf("number of affected record in insert was expected to be one, but was %d", aff)
			}
		}
	}
	return nil
}

// writeCatchpointStagingHashes inserts all the account hashes in the provided array into the catchpoint pending hashes table catchpointpendinghashes.
func writeCatchpointStagingHashes(ctx context.Context, tx *sql.Tx, bals []normalizedAccountBalance) error {
	insertStmt, err := tx.PrepareContext(ctx, "INSERT INTO catchpointpendinghashes(data) VALUES(?)")
	if err != nil {
		return err
	}

	for _, balance := range bals {
		for _, hash := range balance.accountHashes {
			result, err := insertStmt.ExecContext(ctx, hash[:])
			if err != nil {
				return err
			}

			aff, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if aff != 1 {
				return fmt.Errorf("number of affected record in insert was expected to be one, but was %d", aff)
			}
		}
	}
	return nil
}

// createCatchpointStagingHashesIndex creates an index on catchpointpendinghashes to allow faster scanning according to the hash order
func createCatchpointStagingHashesIndex(ctx context.Context, tx *sql.Tx) (err error) {
	_, err = tx.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS catchpointpendinghashesidx ON catchpointpendinghashes(data)")
	if err != nil {
		return
	}
	return
}

// writeCatchpointStagingCreatable inserts all the creatables in the provided array into the catchpoint asset creator staging table catchpointassetcreators.
// note that we cannot insert the resources here : in order to insert the resources, we need the rowid of the accountbase entry. This is being inserted by
// writeCatchpointStagingBalances via a separate go-routine.
func writeCatchpointStagingCreatable(ctx context.Context, tx *sql.Tx, bals []normalizedAccountBalance) error {
	var insertCreatorsStmt *sql.Stmt
	var err error
	insertCreatorsStmt, err = tx.PrepareContext(ctx, "INSERT INTO catchpointassetcreators(asset, creator, ctype) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}
	defer insertCreatorsStmt.Close()

	for _, balance := range bals {
		for aidx, resData := range balance.resources {
			if resData.IsOwning() {
				// determine if it's an asset
				if resData.IsAsset() {
					_, err := insertCreatorsStmt.ExecContext(ctx, basics.CreatableIndex(aidx), balance.address[:], basics.AssetCreatable)
					if err != nil {
						return err
					}
				}
				// determine if it's an application
				if resData.IsApp() {
					_, err := insertCreatorsStmt.ExecContext(ctx, basics.CreatableIndex(aidx), balance.address[:], basics.AppCreatable)
					if err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func resetCatchpointStagingBalances(ctx context.Context, tx *sql.Tx, newCatchup bool) (err error) {
	s := []string{
		"DROP TABLE IF EXISTS catchpointbalances",
		"DROP TABLE IF EXISTS catchpointassetcreators",
		"DROP TABLE IF EXISTS catchpointaccounthashes",
		"DROP TABLE IF EXISTS catchpointpendinghashes",
		"DROP TABLE IF EXISTS catchpointresources",
		"DELETE FROM accounttotals where id='catchpointStaging'",
	}

	if newCatchup {
		// SQLite has no way to rename an existing index.  So, we need
		// to cook up a fresh name for the index, which will be kept
		// around after we rename the table from "catchpointbalances"
		// to "accountbase".  To construct a unique index name, we
		// use the current time.
		// Apply the same logic to
		now := time.Now().UnixNano()
		idxnameBalances := fmt.Sprintf("onlineaccountbals_idx_%d", now)
		idxnameAddress := fmt.Sprintf("accountbase_address_idx_%d", now)

		s = append(s,
			"CREATE TABLE IF NOT EXISTS catchpointassetcreators (asset integer primary key, creator blob, ctype integer)",
			"CREATE TABLE IF NOT EXISTS catchpointbalances (addrid INTEGER PRIMARY KEY NOT NULL, address blob NOT NULL, data blob, normalizedonlinebalance INTEGER)",
			"CREATE TABLE IF NOT EXISTS catchpointpendinghashes (data blob)",
			"CREATE TABLE IF NOT EXISTS catchpointaccounthashes (id integer primary key, data blob)",
			"CREATE TABLE IF NOT EXISTS catchpointresources (addrid INTEGER NOT NULL, aidx INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (addrid, aidx) ) WITHOUT ROWID",
			createNormalizedOnlineBalanceIndex(idxnameBalances, "catchpointbalances"),
			createUniqueAddressBalanceIndex(idxnameAddress, "catchpointbalances"),
		)
	}

	for _, stmt := range s {
		_, err = tx.Exec(stmt)
		if err != nil {
			return err
		}
	}

	return nil
}

// applyCatchpointStagingBalances switches the staged catchpoint catchup tables onto the actual
// tables and update the correct balance round. This is the final step in switching onto the new catchpoint round.
func applyCatchpointStagingBalances(ctx context.Context, tx *sql.Tx, balancesRound basics.Round, merkleRootRound basics.Round) (err error) {
	stmts := []string{
		"ALTER TABLE accountbase RENAME TO accountbase_old",
		"ALTER TABLE assetcreators RENAME TO assetcreators_old",
		"ALTER TABLE accounthashes RENAME TO accounthashes_old",
		"ALTER TABLE resources RENAME TO resources_old",

		"ALTER TABLE catchpointbalances RENAME TO accountbase",
		"ALTER TABLE catchpointassetcreators RENAME TO assetcreators",
		"ALTER TABLE catchpointaccounthashes RENAME TO accounthashes",
		"ALTER TABLE catchpointresources RENAME TO resources",

		"DROP TABLE IF EXISTS accountbase_old",
		"DROP TABLE IF EXISTS assetcreators_old",
		"DROP TABLE IF EXISTS accounthashes_old",
		"DROP TABLE IF EXISTS resources_old",
	}

	for _, stmt := range stmts {
		_, err = tx.Exec(stmt)
		if err != nil {
			return err
		}
	}

	_, err = tx.Exec("INSERT OR REPLACE INTO acctrounds(id, rnd) VALUES('acctbase', ?)", balancesRound)
	if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT OR REPLACE INTO acctrounds(id, rnd) VALUES('hashbase', ?)", merkleRootRound)
	if err != nil {
		return err
	}

	return
}

func getCatchpoint(tx *sql.Tx, round basics.Round) (fileName string, catchpoint string, fileSize int64, err error) {
	err = tx.QueryRow("SELECT filename, catchpoint, filesize FROM storedcatchpoints WHERE round=?", int64(round)).Scan(&fileName, &catchpoint, &fileSize)
	return
}

// accountsInit fills the database using tx with initAccounts if the
// database has not been initialized yet.
//
// accountsInit returns nil if either it has initialized the database
// correctly, or if the database has already been initialized.
func accountsInit(tx *sql.Tx, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error) {
	for _, tableCreate := range accountsSchema {
		_, err = tx.Exec(tableCreate)
		if err != nil {
			return
		}
	}

	// Run creatables migration if it hasn't run yet
	var creatableMigrated bool
	err = tx.QueryRow("SELECT 1 FROM pragma_table_info('assetcreators') WHERE name='ctype'").Scan(&creatableMigrated)
	if err == sql.ErrNoRows {
		// Run migration
		for _, migrateCmd := range creatablesMigration {
			_, err = tx.Exec(migrateCmd)
			if err != nil {
				return
			}
		}
	} else if err != nil {
		return
	}

	_, err = tx.Exec("INSERT INTO acctrounds (id, rnd) VALUES ('acctbase', 0)")
	if err == nil {
		var ot basics.OverflowTracker
		var totals ledgercore.AccountTotals

		for addr, data := range initAccounts {
			_, err = tx.Exec("INSERT INTO accountbase (address, data) VALUES (?, ?)",
				addr[:], protocol.Encode(&data))
			if err != nil {
				return true, err
			}

			ad := ledgercore.ToAccountData(data)
			totals.AddAccount(proto, ad, &ot)
		}

		if ot.Overflowed {
			return true, fmt.Errorf("overflow computing totals")
		}

		err = accountsPutTotals(tx, totals, false)
		if err != nil {
			return true, err
		}
		newDatabase = true
	} else {
		serr, ok := err.(sqlite3.Error)
		// serr.Code is sqlite.ErrConstraint if the database has already been initialized;
		// in that case, ignore the error and return nil.
		if !ok || serr.Code != sqlite3.ErrConstraint {
			return
		}

	}

	return newDatabase, nil
}

// accountsAddNormalizedBalance adds the normalizedonlinebalance column
// to the accountbase table.
func accountsAddNormalizedBalance(tx *sql.Tx, proto config.ConsensusParams) error {
	var exists bool
	err := tx.QueryRow("SELECT 1 FROM pragma_table_info('accountbase') WHERE name='normalizedonlinebalance'").Scan(&exists)
	if err == nil {
		// Already exists.
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}

	for _, stmt := range createOnlineAccountIndex {
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}

	rows, err := tx.Query("SELECT address, data FROM accountbase")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		err = rows.Scan(&addrbuf, &buf)
		if err != nil {
			return err
		}

		var data basics.AccountData
		err = protocol.Decode(buf, &data)
		if err != nil {
			return err
		}

		normBalance := data.NormalizedOnlineBalance(proto)
		if normBalance > 0 {
			_, err = tx.Exec("UPDATE accountbase SET normalizedonlinebalance=? WHERE address=?", normBalance, addrbuf)
			if err != nil {
				return err
			}
		}
	}

	return rows.Err()
}

// accountsCreateResourceTable creates the resource table in the database.
func accountsCreateResourceTable(ctx context.Context, tx *sql.Tx) error {
	var exists bool
	err := tx.QueryRowContext(ctx, "SELECT 1 FROM pragma_table_info('resources') WHERE name='addrid'").Scan(&exists)
	if err == nil {
		// Already exists.
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	for _, stmt := range createResourcesTable {
		_, err = tx.ExecContext(ctx, stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

type baseOnlineAccountData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	VoteID          crypto.OneTimeSignatureVerifier `codec:"A"`
	SelectionID     crypto.VRFVerifier              `codec:"B"`
	VoteFirstValid  basics.Round                    `codec:"C"`
	VoteLastValid   basics.Round                    `codec:"D"`
	VoteKeyDilution uint64                          `codec:"E"`
	StateProofID    merklesignature.Verifier        `codec:"F"`
}

type baseAccountData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Status                     basics.Status     `codec:"a"`
	MicroAlgos                 basics.MicroAlgos `codec:"b"`
	RewardsBase                uint64            `codec:"c"`
	RewardedMicroAlgos         basics.MicroAlgos `codec:"d"`
	AuthAddr                   basics.Address    `codec:"e"`
	TotalAppSchemaNumUint      uint64            `codec:"f"`
	TotalAppSchemaNumByteSlice uint64            `codec:"g"`
	TotalExtraAppPages         uint32            `codec:"h"`
	TotalAssetParams           uint64            `codec:"i"`
	TotalAssets                uint64            `codec:"j"`
	TotalAppParams             uint64            `codec:"k"`
	TotalAppLocalStates        uint64            `codec:"l"`

	baseOnlineAccountData

	// UpdateRound is the round that modified this account data last. Since we want all the nodes to have the exact same
	// value for this field, we'll be setting the value of this field to zero *before* the EnableAccountDataResourceSeparation
	// consensus parameter is being set. Once the above consensus takes place, this field would be populated with the
	// correct round number.
	UpdateRound uint64 `codec:"z"`
}

// IsEmpty return true if any of the fields other then the UpdateRound are non-zero.
func (ba *baseAccountData) IsEmpty() bool {
	return ba.Status == 0 &&
		ba.MicroAlgos.Raw == 0 &&
		ba.RewardsBase == 0 &&
		ba.RewardedMicroAlgos.Raw == 0 &&
		ba.AuthAddr.IsZero() &&
		ba.TotalAppSchemaNumUint == 0 &&
		ba.TotalAppSchemaNumByteSlice == 0 &&
		ba.TotalExtraAppPages == 0 &&
		ba.TotalAssetParams == 0 &&
		ba.TotalAssets == 0 &&
		ba.TotalAppParams == 0 &&
		ba.TotalAppLocalStates == 0 &&
		ba.VoteID.MsgIsZero() &&
		ba.SelectionID.MsgIsZero() &&
		ba.StateProofID.MsgIsZero() &&
		ba.VoteFirstValid == 0 &&
		ba.VoteLastValid == 0 &&
		ba.VoteKeyDilution == 0
}

func (ba *baseAccountData) NormalizedOnlineBalance(proto config.ConsensusParams) uint64 {
	return basics.NormalizedOnlineAccountBalance(ba.Status, ba.RewardsBase, ba.MicroAlgos, proto)
}

func (ba *baseAccountData) SetCoreAccountData(ad *ledgercore.AccountData) {
	ba.Status = ad.Status
	ba.MicroAlgos = ad.MicroAlgos
	ba.RewardsBase = ad.RewardsBase
	ba.RewardedMicroAlgos = ad.RewardedMicroAlgos
	ba.VoteID = ad.VoteID
	ba.SelectionID = ad.SelectionID
	ba.StateProofID = ad.StateProofID
	ba.VoteFirstValid = ad.VoteFirstValid
	ba.VoteLastValid = ad.VoteLastValid
	ba.VoteKeyDilution = ad.VoteKeyDilution
	ba.AuthAddr = ad.AuthAddr
	ba.TotalAppSchemaNumUint = ad.TotalAppSchema.NumUint
	ba.TotalAppSchemaNumByteSlice = ad.TotalAppSchema.NumByteSlice
	ba.TotalExtraAppPages = ad.TotalExtraAppPages
	ba.TotalAssetParams = ad.TotalAssetParams
	ba.TotalAssets = ad.TotalAssets
	ba.TotalAppParams = ad.TotalAppParams
	ba.TotalAppLocalStates = ad.TotalAppLocalStates
}

func (ba *baseAccountData) SetAccountData(ad *basics.AccountData) {
	ba.Status = ad.Status
	ba.MicroAlgos = ad.MicroAlgos
	ba.RewardsBase = ad.RewardsBase
	ba.RewardedMicroAlgos = ad.RewardedMicroAlgos
	ba.VoteID = ad.VoteID
	ba.SelectionID = ad.SelectionID
	ba.StateProofID = ad.StateProofID
	ba.VoteFirstValid = ad.VoteFirstValid
	ba.VoteLastValid = ad.VoteLastValid
	ba.VoteKeyDilution = ad.VoteKeyDilution
	ba.AuthAddr = ad.AuthAddr
	ba.TotalAppSchemaNumUint = ad.TotalAppSchema.NumUint
	ba.TotalAppSchemaNumByteSlice = ad.TotalAppSchema.NumByteSlice
	ba.TotalExtraAppPages = ad.TotalExtraAppPages
	ba.TotalAssetParams = uint64(len(ad.AssetParams))
	ba.TotalAssets = uint64(len(ad.Assets))
	ba.TotalAppParams = uint64(len(ad.AppParams))
	ba.TotalAppLocalStates = uint64(len(ad.AppLocalStates))
}

func (ba *baseAccountData) GetLedgerCoreAccountData() ledgercore.AccountData {
	return ledgercore.AccountData{
		AccountBaseData: ledgercore.AccountBaseData{
			Status:             ba.Status,
			MicroAlgos:         ba.MicroAlgos,
			RewardsBase:        ba.RewardsBase,
			RewardedMicroAlgos: ba.RewardedMicroAlgos,
			AuthAddr:           ba.AuthAddr,
			TotalAppSchema: basics.StateSchema{
				NumUint:      ba.TotalAppSchemaNumUint,
				NumByteSlice: ba.TotalAppSchemaNumByteSlice,
			},
			TotalExtraAppPages:  ba.TotalExtraAppPages,
			TotalAppParams:      ba.TotalAppParams,
			TotalAppLocalStates: ba.TotalAppLocalStates,
			TotalAssetParams:    ba.TotalAssetParams,
			TotalAssets:         ba.TotalAssets,
		},
		VotingData: ledgercore.VotingData{
			VoteID:          ba.VoteID,
			SelectionID:     ba.SelectionID,
			StateProofID:    ba.StateProofID,
			VoteFirstValid:  ba.VoteFirstValid,
			VoteLastValid:   ba.VoteLastValid,
			VoteKeyDilution: ba.VoteKeyDilution,
		},
	}
}

func (ba *baseAccountData) GetAccountData() basics.AccountData {
	return basics.AccountData{
		Status:             ba.Status,
		MicroAlgos:         ba.MicroAlgos,
		RewardsBase:        ba.RewardsBase,
		RewardedMicroAlgos: ba.RewardedMicroAlgos,
		VoteID:             ba.VoteID,
		SelectionID:        ba.SelectionID,
		StateProofID:       ba.StateProofID,
		VoteFirstValid:     ba.VoteFirstValid,
		VoteLastValid:      ba.VoteLastValid,
		VoteKeyDilution:    ba.VoteKeyDilution,
		AuthAddr:           ba.AuthAddr,
		TotalAppSchema: basics.StateSchema{
			NumUint:      ba.TotalAppSchemaNumUint,
			NumByteSlice: ba.TotalAppSchemaNumByteSlice,
		},
		TotalExtraAppPages: ba.TotalExtraAppPages,
	}
}

type resourceFlags uint8

const (
	resourceFlagsHolding    resourceFlags = 0 //nolint:deadcode,varcheck
	resourceFlagsNotHolding resourceFlags = 1
	resourceFlagsOwnership  resourceFlags = 2
	resourceFlagsEmptyAsset resourceFlags = 4
	resourceFlagsEmptyApp   resourceFlags = 8
)

//
// Resource flags interpretation:
//
// resourceFlagsHolding - the resource contains the holding of asset/app.
// resourceFlagsNotHolding - the resource is completely empty. This state should not be persisted.
// resourceFlagsOwnership - the resource contains the asset parameter or application parameters.
// resourceFlagsEmptyAsset - this is an asset resource, and it is empty.
// resourceFlagsEmptyApp - this is an app resource, and it is empty.

type resourcesData struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	// asset parameters ( basics.AssetParams )
	Total         uint64         `codec:"a"`
	Decimals      uint32         `codec:"b"`
	DefaultFrozen bool           `codec:"c"`
	UnitName      string         `codec:"d"`
	AssetName     string         `codec:"e"`
	URL           string         `codec:"f"`
	MetadataHash  [32]byte       `codec:"g"`
	Manager       basics.Address `codec:"h"`
	Reserve       basics.Address `codec:"i"`
	Freeze        basics.Address `codec:"j"`
	Clawback      basics.Address `codec:"k"`

	// asset holding ( basics.AssetHolding )
	Amount uint64 `codec:"l"`
	Frozen bool   `codec:"m"`

	// application local state ( basics.AppLocalState )
	SchemaNumUint      uint64              `codec:"n"`
	SchemaNumByteSlice uint64              `codec:"o"`
	KeyValue           basics.TealKeyValue `codec:"p"`

	// application global params ( basics.AppParams )
	ApprovalProgram               []byte              `codec:"q,allocbound=config.MaxAvailableAppProgramLen"`
	ClearStateProgram             []byte              `codec:"r,allocbound=config.MaxAvailableAppProgramLen"`
	GlobalState                   basics.TealKeyValue `codec:"s"`
	LocalStateSchemaNumUint       uint64              `codec:"t"`
	LocalStateSchemaNumByteSlice  uint64              `codec:"u"`
	GlobalStateSchemaNumUint      uint64              `codec:"v"`
	GlobalStateSchemaNumByteSlice uint64              `codec:"w"`
	ExtraProgramPages             uint32              `codec:"x"`

	// ResourceFlags helps to identify which portions of this structure should be used; in particular, it
	// helps to provide a marker - i.e. whether the account was, for instance, opted-in for the asset compared
	// to just being the owner of the asset. A comparison against the empty structure doesn't work here -
	// since both the holdings and the parameters are allowed to be all at their default values.
	ResourceFlags resourceFlags `codec:"y"`

	// UpdateRound is the round that modified this resource last. Since we want all the nodes to have the exact same
	// value for this field, we'll be setting the value of this field to zero *before* the EnableAccountDataResourceSeparation
	// consensus parameter is being set. Once the above consensus takes place, this field would be populated with the
	// correct round number.
	UpdateRound uint64 `codec:"z"`
}

// makeResourcesData returns a new empty instance of resourcesData.
// Using this constructor method is necessary because of the ResourceFlags field.
// An optional rnd args sets UpdateRound
func makeResourcesData(rnd uint64) resourcesData {
	return resourcesData{ResourceFlags: resourceFlagsNotHolding, UpdateRound: rnd}
}

func (rd *resourcesData) IsHolding() bool {
	return (rd.ResourceFlags & resourceFlagsNotHolding) == resourceFlagsHolding
}

func (rd *resourcesData) IsOwning() bool {
	return (rd.ResourceFlags & resourceFlagsOwnership) == resourceFlagsOwnership
}

func (rd *resourcesData) IsEmpty() bool {
	return !rd.IsApp() && !rd.IsAsset()
}

func (rd *resourcesData) IsEmptyAppFields() bool {
	return rd.SchemaNumUint == 0 &&
		rd.SchemaNumByteSlice == 0 &&
		len(rd.KeyValue) == 0 &&
		len(rd.ApprovalProgram) == 0 &&
		len(rd.ClearStateProgram) == 0 &&
		len(rd.GlobalState) == 0 &&
		rd.LocalStateSchemaNumUint == 0 &&
		rd.LocalStateSchemaNumByteSlice == 0 &&
		rd.GlobalStateSchemaNumUint == 0 &&
		rd.GlobalStateSchemaNumByteSlice == 0 &&
		rd.ExtraProgramPages == 0
}

func (rd *resourcesData) IsApp() bool {
	if (rd.ResourceFlags & resourceFlagsEmptyApp) == resourceFlagsEmptyApp {
		return true
	}
	return !rd.IsEmptyAppFields()
}

func (rd *resourcesData) IsEmptyAssetFields() bool {
	return rd.Amount == 0 &&
		!rd.Frozen &&
		rd.Total == 0 &&
		rd.Decimals == 0 &&
		!rd.DefaultFrozen &&
		rd.UnitName == "" &&
		rd.AssetName == "" &&
		rd.URL == "" &&
		rd.MetadataHash == [32]byte{} &&
		rd.Manager.IsZero() &&
		rd.Reserve.IsZero() &&
		rd.Freeze.IsZero() &&
		rd.Clawback.IsZero()
}

func (rd *resourcesData) IsAsset() bool {
	if (rd.ResourceFlags & resourceFlagsEmptyAsset) == resourceFlagsEmptyAsset {
		return true
	}
	return !rd.IsEmptyAssetFields()
}

func (rd *resourcesData) ClearAssetParams() {
	rd.Total = 0
	rd.Decimals = 0
	rd.DefaultFrozen = false
	rd.UnitName = ""
	rd.AssetName = ""
	rd.URL = ""
	rd.MetadataHash = basics.Address{}
	rd.Manager = basics.Address{}
	rd.Reserve = basics.Address{}
	rd.Freeze = basics.Address{}
	rd.Clawback = basics.Address{}
	hadHolding := (rd.ResourceFlags & resourceFlagsNotHolding) == resourceFlagsHolding
	rd.ResourceFlags -= rd.ResourceFlags & resourceFlagsOwnership
	rd.ResourceFlags &= ^resourceFlagsEmptyAsset
	if rd.IsEmptyAssetFields() && hadHolding {
		rd.ResourceFlags |= resourceFlagsEmptyAsset
	}
}

func (rd *resourcesData) SetAssetParams(ap basics.AssetParams, haveHoldings bool) {
	rd.Total = ap.Total
	rd.Decimals = ap.Decimals
	rd.DefaultFrozen = ap.DefaultFrozen
	rd.UnitName = ap.UnitName
	rd.AssetName = ap.AssetName
	rd.URL = ap.URL
	rd.MetadataHash = ap.MetadataHash
	rd.Manager = ap.Manager
	rd.Reserve = ap.Reserve
	rd.Freeze = ap.Freeze
	rd.Clawback = ap.Clawback
	rd.ResourceFlags |= resourceFlagsOwnership
	if !haveHoldings {
		rd.ResourceFlags |= resourceFlagsNotHolding
	}
	rd.ResourceFlags &= ^resourceFlagsEmptyAsset
	if rd.IsEmptyAssetFields() {
		rd.ResourceFlags |= resourceFlagsEmptyAsset
	}
}

func (rd *resourcesData) GetAssetParams() basics.AssetParams {
	ap := basics.AssetParams{
		Total:         rd.Total,
		Decimals:      rd.Decimals,
		DefaultFrozen: rd.DefaultFrozen,
		UnitName:      rd.UnitName,
		AssetName:     rd.AssetName,
		URL:           rd.URL,
		MetadataHash:  rd.MetadataHash,
		Manager:       rd.Manager,
		Reserve:       rd.Reserve,
		Freeze:        rd.Freeze,
		Clawback:      rd.Clawback,
	}
	return ap
}

func (rd *resourcesData) ClearAssetHolding() {
	rd.Amount = 0
	rd.Frozen = false

	rd.ResourceFlags |= resourceFlagsNotHolding
	hadParams := (rd.ResourceFlags & resourceFlagsOwnership) == resourceFlagsOwnership
	if hadParams && rd.IsEmptyAssetFields() {
		rd.ResourceFlags |= resourceFlagsEmptyAsset
	} else {
		rd.ResourceFlags &= ^resourceFlagsEmptyAsset
	}
}

func (rd *resourcesData) SetAssetHolding(ah basics.AssetHolding) {
	rd.Amount = ah.Amount
	rd.Frozen = ah.Frozen
	rd.ResourceFlags &= ^(resourceFlagsNotHolding + resourceFlagsEmptyAsset)
	// resourceFlagsHolding is set implicitly since it is zero
	if rd.IsEmptyAssetFields() {
		rd.ResourceFlags |= resourceFlagsEmptyAsset
	}
}

func (rd *resourcesData) GetAssetHolding() basics.AssetHolding {
	return basics.AssetHolding{
		Amount: rd.Amount,
		Frozen: rd.Frozen,
	}
}

func (rd *resourcesData) ClearAppLocalState() {
	rd.SchemaNumUint = 0
	rd.SchemaNumByteSlice = 0
	rd.KeyValue = nil

	rd.ResourceFlags |= resourceFlagsNotHolding
	hadParams := (rd.ResourceFlags & resourceFlagsOwnership) == resourceFlagsOwnership
	if hadParams && rd.IsEmptyAppFields() {
		rd.ResourceFlags |= resourceFlagsEmptyApp
	} else {
		rd.ResourceFlags &= ^resourceFlagsEmptyApp
	}
}

func (rd *resourcesData) SetAppLocalState(als basics.AppLocalState) {
	rd.SchemaNumUint = als.Schema.NumUint
	rd.SchemaNumByteSlice = als.Schema.NumByteSlice
	rd.KeyValue = als.KeyValue
	rd.ResourceFlags &= ^(resourceFlagsEmptyApp + resourceFlagsNotHolding)
	if rd.IsEmptyAppFields() {
		rd.ResourceFlags |= resourceFlagsEmptyApp
	}
}

func (rd *resourcesData) GetAppLocalState() basics.AppLocalState {
	return basics.AppLocalState{
		Schema: basics.StateSchema{
			NumUint:      rd.SchemaNumUint,
			NumByteSlice: rd.SchemaNumByteSlice,
		},
		KeyValue: rd.KeyValue,
	}
}

func (rd *resourcesData) ClearAppParams() {
	rd.ApprovalProgram = nil
	rd.ClearStateProgram = nil
	rd.GlobalState = nil
	rd.LocalStateSchemaNumUint = 0
	rd.LocalStateSchemaNumByteSlice = 0
	rd.GlobalStateSchemaNumUint = 0
	rd.GlobalStateSchemaNumByteSlice = 0
	rd.ExtraProgramPages = 0
	hadHolding := (rd.ResourceFlags & resourceFlagsNotHolding) == resourceFlagsHolding
	rd.ResourceFlags -= rd.ResourceFlags & resourceFlagsOwnership
	rd.ResourceFlags &= ^resourceFlagsEmptyApp
	if rd.IsEmptyAppFields() && hadHolding {
		rd.ResourceFlags |= resourceFlagsEmptyApp
	}
}

func (rd *resourcesData) SetAppParams(ap basics.AppParams, haveHoldings bool) {
	rd.ApprovalProgram = ap.ApprovalProgram
	rd.ClearStateProgram = ap.ClearStateProgram
	rd.GlobalState = ap.GlobalState
	rd.LocalStateSchemaNumUint = ap.LocalStateSchema.NumUint
	rd.LocalStateSchemaNumByteSlice = ap.LocalStateSchema.NumByteSlice
	rd.GlobalStateSchemaNumUint = ap.GlobalStateSchema.NumUint
	rd.GlobalStateSchemaNumByteSlice = ap.GlobalStateSchema.NumByteSlice
	rd.ExtraProgramPages = ap.ExtraProgramPages
	rd.ResourceFlags |= resourceFlagsOwnership
	if !haveHoldings {
		rd.ResourceFlags |= resourceFlagsNotHolding
	}
	rd.ResourceFlags &= ^resourceFlagsEmptyApp
	if rd.IsEmptyAppFields() {
		rd.ResourceFlags |= resourceFlagsEmptyApp
	}
}

func (rd *resourcesData) GetAppParams() basics.AppParams {
	return basics.AppParams{
		ApprovalProgram:   rd.ApprovalProgram,
		ClearStateProgram: rd.ClearStateProgram,
		GlobalState:       rd.GlobalState,
		StateSchemas: basics.StateSchemas{
			LocalStateSchema: basics.StateSchema{
				NumUint:      rd.LocalStateSchemaNumUint,
				NumByteSlice: rd.LocalStateSchemaNumByteSlice,
			},
			GlobalStateSchema: basics.StateSchema{
				NumUint:      rd.GlobalStateSchemaNumUint,
				NumByteSlice: rd.GlobalStateSchemaNumByteSlice,
			},
		},
		ExtraProgramPages: rd.ExtraProgramPages,
	}
}

func (rd *resourcesData) SetAssetData(ap ledgercore.AssetParamsDelta, ah ledgercore.AssetHoldingDelta) {
	if ah.Holding != nil {
		rd.SetAssetHolding(*ah.Holding)
	} else if ah.Deleted {
		rd.ClearAssetHolding()
	}
	if ap.Params != nil {
		rd.SetAssetParams(*ap.Params, rd.IsHolding())
	} else if ap.Deleted {
		rd.ClearAssetParams()
	}
}

func (rd *resourcesData) SetAppData(ap ledgercore.AppParamsDelta, al ledgercore.AppLocalStateDelta) {
	if al.LocalState != nil {
		rd.SetAppLocalState(*al.LocalState)
	} else if al.Deleted {
		rd.ClearAppLocalState()
	}
	if ap.Params != nil {
		rd.SetAppParams(*ap.Params, rd.IsHolding())
	} else if ap.Deleted {
		rd.ClearAppParams()
	}
}

func accountDataResources(
	ctx context.Context,
	accountData *basics.AccountData, rowid int64,
	outputResourceCb func(ctx context.Context, rowid int64, cidx basics.CreatableIndex, rd *resourcesData) error,
) error {
	// handle all the assets we can find:
	for aidx, holding := range accountData.Assets {
		var rd resourcesData
		rd.SetAssetHolding(holding)
		if ap, has := accountData.AssetParams[aidx]; has {
			rd.SetAssetParams(ap, true)
			delete(accountData.AssetParams, aidx)
		}
		err := outputResourceCb(ctx, rowid, basics.CreatableIndex(aidx), &rd)
		if err != nil {
			return err
		}
	}
	for aidx, aparams := range accountData.AssetParams {
		var rd resourcesData
		rd.SetAssetParams(aparams, false)
		err := outputResourceCb(ctx, rowid, basics.CreatableIndex(aidx), &rd)
		if err != nil {
			return err
		}
	}

	// handle all the applications we can find:
	for aidx, localState := range accountData.AppLocalStates {
		var rd resourcesData
		rd.SetAppLocalState(localState)
		if ap, has := accountData.AppParams[aidx]; has {
			rd.SetAppParams(ap, true)
			delete(accountData.AppParams, aidx)
		}
		err := outputResourceCb(ctx, rowid, basics.CreatableIndex(aidx), &rd)
		if err != nil {
			return err
		}
	}
	for aidx, aparams := range accountData.AppParams {
		var rd resourcesData
		rd.SetAppParams(aparams, false)
		err := outputResourceCb(ctx, rowid, basics.CreatableIndex(aidx), &rd)
		if err != nil {
			return err
		}
	}

	return nil
}

// performResourceTableMigration migrate the database to use the resources table.
func performResourceTableMigration(ctx context.Context, tx *sql.Tx, log func(processed, total uint64)) (err error) {
	now := time.Now().UnixNano()
	idxnameBalances := fmt.Sprintf("onlineaccountbals_idx_%d", now)
	idxnameAddress := fmt.Sprintf("accountbase_address_idx_%d", now)

	createNewAcctBase := []string{
		`CREATE TABLE IF NOT EXISTS accountbase_resources_migration (
		addrid INTEGER PRIMARY KEY NOT NULL,
		address blob NOT NULL,
		data blob,
		normalizedonlinebalance INTEGER )`,
		createNormalizedOnlineBalanceIndex(idxnameBalances, "accountbase_resources_migration"),
		createUniqueAddressBalanceIndex(idxnameAddress, "accountbase_resources_migration"),
	}

	applyNewAcctBase := []string{
		`ALTER TABLE accountbase RENAME TO accountbase_old`,
		`ALTER TABLE accountbase_resources_migration RENAME TO accountbase`,
		`DROP TABLE IF EXISTS accountbase_old`,
	}

	for _, stmt := range createNewAcctBase {
		_, err = tx.ExecContext(ctx, stmt)
		if err != nil {
			return err
		}
	}
	var insertNewAcctBase *sql.Stmt
	var insertResources *sql.Stmt
	var insertNewAcctBaseNormBal *sql.Stmt
	insertNewAcctBase, err = tx.PrepareContext(ctx, "INSERT INTO accountbase_resources_migration(address, data) VALUES(?, ?)")
	if err != nil {
		return err
	}
	defer insertNewAcctBase.Close()

	insertNewAcctBaseNormBal, err = tx.PrepareContext(ctx, "INSERT INTO accountbase_resources_migration(address, data, normalizedonlinebalance) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}
	defer insertNewAcctBaseNormBal.Close()

	insertResources, err = tx.PrepareContext(ctx, "INSERT INTO resources(addrid, aidx, data) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}
	defer insertResources.Close()

	var rows *sql.Rows
	rows, err = tx.QueryContext(ctx, "SELECT address, data, normalizedonlinebalance FROM accountbase ORDER BY address")
	if err != nil {
		return err
	}
	defer rows.Close()

	var insertRes sql.Result
	var rowID int64
	var rowsAffected int64
	var processedAccounts uint64
	var totalBaseAccounts uint64

	totalBaseAccounts, err = totalAccounts(ctx, tx)
	if err != nil {
		return err
	}
	for rows.Next() {
		var addrbuf []byte
		var encodedAcctData []byte
		var normBal sql.NullInt64
		err = rows.Scan(&addrbuf, &encodedAcctData, &normBal)
		if err != nil {
			return err
		}

		var accountData basics.AccountData
		err = protocol.Decode(encodedAcctData, &accountData)
		if err != nil {
			return err
		}
		var newAccountData baseAccountData
		newAccountData.SetAccountData(&accountData)
		encodedAcctData = protocol.Encode(&newAccountData)

		if normBal.Valid {
			insertRes, err = insertNewAcctBaseNormBal.ExecContext(ctx, addrbuf, encodedAcctData, normBal.Int64)
		} else {
			insertRes, err = insertNewAcctBase.ExecContext(ctx, addrbuf, encodedAcctData)
		}

		if err != nil {
			return err
		}
		rowsAffected, err = insertRes.RowsAffected()
		if err != nil {
			return err
		}
		if rowsAffected != 1 {
			return fmt.Errorf("number of affected rows is not 1 - %d", rowsAffected)
		}
		rowID, err = insertRes.LastInsertId()
		if err != nil {
			return err
		}
		insertResourceCallback := func(ctx context.Context, rowID int64, cidx basics.CreatableIndex, rd *resourcesData) error {
			var err error
			if rd != nil {
				encodedData := protocol.Encode(rd)
				_, err = insertResources.ExecContext(ctx, rowID, cidx, encodedData)
			}
			return err
		}
		err = accountDataResources(ctx, &accountData, rowID, insertResourceCallback)
		if err != nil {
			return err
		}
		processedAccounts++
		if log != nil {
			log(processedAccounts, totalBaseAccounts)
		}
	}

	// if the above loop was abrupt by an error, test it now.
	if err = rows.Err(); err != nil {
		return err
	}

	for _, stmt := range applyNewAcctBase {
		_, err = tx.Exec(stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

// removeEmptyAccountData removes empty AccountData msgp-encoded entries from accountbase table
// and optionally returns list of addresses that were eliminated
func removeEmptyAccountData(tx *sql.Tx, queryAddresses bool) (num int64, addresses []basics.Address, err error) {
	if queryAddresses {
		rows, err := tx.Query("SELECT address FROM accountbase where length(data) = 1 and data = x'80'") // empty AccountData is 0x80
		if err != nil {
			return 0, nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var addrbuf []byte
			err = rows.Scan(&addrbuf)
			if err != nil {
				return 0, nil, err
			}
			var addr basics.Address
			if len(addrbuf) != len(addr) {
				err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
				return 0, nil, err
			}
			copy(addr[:], addrbuf)
			addresses = append(addresses, addr)
		}

		// if the above loop was abrupted by an error, test it now.
		if err = rows.Err(); err != nil {
			return 0, nil, err
		}
	}

	result, err := tx.Exec("DELETE from accountbase where length(data) = 1 and data = x'80'")
	if err != nil {
		return 0, nil, err
	}
	num, err = result.RowsAffected()
	if err != nil {
		// something wrong on getting rows count but data deleted, ignore the error
		num = int64(len(addresses))
		err = nil
	}
	return num, addresses, err
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

func resetAccountHashes(tx *sql.Tx) (err error) {
	_, err = tx.Exec(`DELETE FROM accounthashes`)
	return
}

func accountsReset(tx *sql.Tx) error {
	for _, stmt := range accountsResetExprs {
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}
	_, err := db.SetUserVersion(context.Background(), tx, 0)
	return err
}

// accountsRound returns the tracker balances round number
func accountsRound(tx *sql.Tx) (rnd basics.Round, err error) {
	err = tx.QueryRow("SELECT rnd FROM acctrounds WHERE id='acctbase'").Scan(&rnd)
	if err != nil {
		return
	}
	return
}

// accountsHashRound returns the round of the hash tree
// if the hash of the tree doesn't exists, it returns zero.
func accountsHashRound(tx *sql.Tx) (hashrnd basics.Round, err error) {
	err = tx.QueryRow("SELECT rnd FROM acctrounds WHERE id='hashbase'").Scan(&hashrnd)
	if err == sql.ErrNoRows {
		hashrnd = basics.Round(0)
		err = nil
	}
	return
}

func accountsInitDbQueries(r db.Queryable, w db.Queryable) (*accountsDbQueries, error) {
	var err error
	qs := &accountsDbQueries{}

	qs.listCreatablesStmt, err = r.Prepare("SELECT rnd, asset, creator FROM acctrounds LEFT JOIN assetcreators ON assetcreators.asset <= ? AND assetcreators.ctype = ? WHERE acctrounds.id='acctbase' ORDER BY assetcreators.asset desc LIMIT ?")
	if err != nil {
		return nil, err
	}

	qs.lookupStmt, err = r.Prepare("SELECT accountbase.rowid, rnd, data FROM acctrounds LEFT JOIN accountbase ON address=? WHERE id='acctbase'")
	if err != nil {
		return nil, err
	}

	qs.lookupResourcesStmt, err = r.Prepare("SELECT accountbase.rowid, rnd, resources.data FROM acctrounds LEFT JOIN accountbase ON accountbase.address = ? LEFT JOIN resources ON accountbase.rowid = resources.addrid AND resources.aidx = ? WHERE id='acctbase'")
	if err != nil {
		return nil, err
	}

	qs.lookupAllResourcesStmt, err = r.Prepare("SELECT accountbase.rowid, rnd, resources.aidx, resources.data FROM acctrounds LEFT JOIN accountbase ON accountbase.address = ? LEFT JOIN resources ON accountbase.rowid = resources.addrid WHERE id='acctbase'")
	if err != nil {
		return nil, err
	}

	qs.lookupKvPairStmt, err = r.Prepare("SELECT value FROM kvstore WHERE key = ?")
	if err != nil {
		return nil, err
	}

	qs.lookupCreatorStmt, err = r.Prepare("SELECT rnd, creator FROM acctrounds LEFT JOIN assetcreators ON asset = ? AND ctype = ? WHERE id='acctbase'")
	if err != nil {
		return nil, err
	}

	qs.deleteStoredCatchpoint, err = w.Prepare("DELETE FROM storedcatchpoints WHERE round=?")
	if err != nil {
		return nil, err
	}

	qs.insertStoredCatchpoint, err = w.Prepare("INSERT INTO storedcatchpoints(round, filename, catchpoint, filesize, pinned) VALUES(?, ?, ?, ?, 0)")
	if err != nil {
		return nil, err
	}

	qs.selectOldestCatchpointFiles, err = r.Prepare("SELECT round, filename FROM storedcatchpoints WHERE pinned = 0 and round <= COALESCE((SELECT round FROM storedcatchpoints WHERE pinned = 0 ORDER BY round DESC LIMIT ?, 1),0) ORDER BY round ASC LIMIT ?")
	if err != nil {
		return nil, err
	}

	qs.selectCatchpointStateUint64, err = r.Prepare("SELECT intval FROM catchpointstate WHERE id=?")
	if err != nil {
		return nil, err
	}

	qs.deleteCatchpointState, err = w.Prepare("DELETE FROM catchpointstate WHERE id=?")
	if err != nil {
		return nil, err
	}

	qs.insertCatchpointStateUint64, err = w.Prepare("INSERT OR REPLACE INTO catchpointstate(id, intval) VALUES(?, ?)")
	if err != nil {
		return nil, err
	}

	qs.insertCatchpointStateString, err = w.Prepare("INSERT OR REPLACE INTO catchpointstate(id, strval) VALUES(?, ?)")
	if err != nil {
		return nil, err
	}

	qs.selectCatchpointStateString, err = r.Prepare("SELECT strval FROM catchpointstate WHERE id=?")
	if err != nil {
		return nil, err
	}
	return qs, nil
}

// listCreatables returns an array of CreatableLocator which have CreatableIndex smaller or equal to maxIdx and are of the provided CreatableType.
func (qs *accountsDbQueries) listCreatables(maxIdx basics.CreatableIndex, maxResults uint64, ctype basics.CreatableType) (results []basics.CreatableLocator, dbRound basics.Round, err error) {
	err = db.Retry(func() error {
		// Query for assets in range
		rows, err := qs.listCreatablesStmt.Query(maxIdx, ctype, maxResults)
		if err != nil {
			return err
		}
		defer rows.Close()

		// For each row, copy into a new CreatableLocator and append to results
		var buf []byte
		var cl basics.CreatableLocator
		var creatableIndex sql.NullInt64
		for rows.Next() {
			err = rows.Scan(&dbRound, &creatableIndex, &buf)
			if err != nil {
				return err
			}
			if !creatableIndex.Valid {
				// we received an entry without any index. This would happen only on the first entry when there are no creatables of the requested type.
				break
			}
			cl.Index = basics.CreatableIndex(creatableIndex.Int64)
			copy(cl.Creator[:], buf)
			cl.Type = ctype
			results = append(results, cl)
		}
		return nil
	})
	return
}

func (qs *accountsDbQueries) lookupKvPair(key string) (value string, ok bool, err error) {
	err = db.Retry(func() error {
		err := qs.lookupKvPairStmt.QueryRow(key).Scan(&value)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil // value and ok remain zero values
			}
			return err
		}
		// value has been set by Scan
		ok = true
		return nil
	})
	return
}

func (qs *accountsDbQueries) lookupCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (addr basics.Address, ok bool, dbRound basics.Round, err error) {
	err = db.Retry(func() error {
		var buf []byte
		err := qs.lookupCreatorStmt.QueryRow(cidx, ctype).Scan(&dbRound, &buf)

		// this shouldn't happen unless we can't figure the round number.
		if err == sql.ErrNoRows {
			return fmt.Errorf("lookupCreator was unable to retrieve round number")
		}

		// Some other database error
		if err != nil {
			return err
		}

		if len(buf) > 0 {
			ok = true
			copy(addr[:], buf)
		}
		return nil
	})
	return
}

func (qs *accountsDbQueries) lookupResources(addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (data persistedResourcesData, err error) {
	err = db.Retry(func() error {
		var buf []byte
		var rowid sql.NullInt64
		err := qs.lookupResourcesStmt.QueryRow(addr[:], aidx).Scan(&rowid, &data.round, &buf)
		if err == nil {
			data.aidx = aidx
			if len(buf) > 0 && rowid.Valid {
				data.addrid = rowid.Int64
				err = protocol.Decode(buf, &data.data)
				if err != nil {
					return err
				}
				if ctype == basics.AssetCreatable && !data.data.IsAsset() {
					return fmt.Errorf("lookupResources asked for an asset but got %v", data.data)
				}
				if ctype == basics.AppCreatable && !data.data.IsApp() {
					return fmt.Errorf("lookupResources asked for an app but got %v", data.data)
				}
				return nil
			}
			data.data = makeResourcesData(0)
			// we don't have that account, just return the database round.
			return nil
		}

		// this should never happen; it indicates that we don't have a current round in the acctrounds table.
		if err == sql.ErrNoRows {
			// Return the zero value of data
			return fmt.Errorf("unable to query resource data for address %v aidx %v ctype %v : %w", addr, aidx, ctype, err)
		}
		return err
	})
	return
}

func (qs *accountsDbQueries) lookupAllResources(addr basics.Address) (data []persistedResourcesData, rnd basics.Round, err error) {
	err = db.Retry(func() error {
		// Query for all resources
		rows, err := qs.lookupAllResourcesStmt.Query(addr[:])
		if err != nil {
			return err
		}
		defer rows.Close()

		var addrid, aidx sql.NullInt64
		var dbRound basics.Round
		data = nil
		var buf []byte
		for rows.Next() {
			err := rows.Scan(&addrid, &dbRound, &aidx, &buf)
			if err != nil {
				return err
			}
			if !addrid.Valid || !aidx.Valid {
				// we received an entry without any index. This would happen only on the first entry when there are no resources for this address.
				// ensure this is the first entry, set the round and return
				if len(data) != 0 {
					return fmt.Errorf("lookupAllResources: unexpected invalid result on non-first resource record: (%v, %v)", addrid.Valid, aidx.Valid)
				}
				rnd = dbRound
				break
			}
			var resData resourcesData
			err = protocol.Decode(buf, &resData)
			if err != nil {
				return err
			}
			data = append(data, persistedResourcesData{
				addrid: addrid.Int64,
				aidx:   basics.CreatableIndex(aidx.Int64),
				data:   resData,
				round:  dbRound,
			})
			rnd = dbRound
		}
		return nil
	})
	return
}

// lookup looks up for a the account data given it's address. It returns the persistedAccountData, which includes the current database round and the matching
// account data, if such was found. If no matching account data could be found for the given address, an empty account data would
// be retrieved.
func (qs *accountsDbQueries) lookup(addr basics.Address) (data persistedAccountData, err error) {
	err = db.Retry(func() error {
		var buf []byte
		var rowid sql.NullInt64
		err := qs.lookupStmt.QueryRow(addr[:]).Scan(&rowid, &data.round, &buf)
		if err == nil {
			data.addr = addr
			if len(buf) > 0 && rowid.Valid {
				data.rowid = rowid.Int64
				err = protocol.Decode(buf, &data.accountData)
				return err
			}
			// we don't have that account, just return the database round.
			return nil
		}

		// this should never happen; it indicates that we don't have a current round in the acctrounds table.
		if err == sql.ErrNoRows {
			// Return the zero value of data
			return fmt.Errorf("unable to query account data for address %v : %w", addr, err)
		}

		return err
	})

	return
}

func (qs *accountsDbQueries) storeCatchpoint(ctx context.Context, round basics.Round, fileName string, catchpoint string, fileSize int64) (err error) {
	err = db.Retry(func() (err error) {
		_, err = qs.deleteStoredCatchpoint.ExecContext(ctx, round)

		if err != nil || (fileName == "" && catchpoint == "" && fileSize == 0) {
			return
		}

		_, err = qs.insertStoredCatchpoint.ExecContext(ctx, round, fileName, catchpoint, fileSize)
		return
	})
	return
}

func (qs *accountsDbQueries) getOldestCatchpointFiles(ctx context.Context, fileCount int, filesToKeep int) (fileNames map[basics.Round]string, err error) {
	err = db.Retry(func() (err error) {
		var rows *sql.Rows
		rows, err = qs.selectOldestCatchpointFiles.QueryContext(ctx, filesToKeep, fileCount)
		if err != nil {
			return
		}
		defer rows.Close()

		fileNames = make(map[basics.Round]string)
		for rows.Next() {
			var fileName string
			var round basics.Round
			err = rows.Scan(&round, &fileName)
			if err != nil {
				return
			}
			fileNames[round] = fileName
		}

		err = rows.Err()
		return
	})
	return
}

func (qs *accountsDbQueries) readCatchpointStateUint64(ctx context.Context, stateName catchpointState) (rnd uint64, def bool, err error) {
	var val sql.NullInt64
	err = db.Retry(func() (err error) {
		err = qs.selectCatchpointStateUint64.QueryRowContext(ctx, stateName).Scan(&val)
		if err == sql.ErrNoRows || (err == nil && !val.Valid) {
			val.Int64 = 0 // default to zero.
			err = nil
			def = true
			return
		}
		return err
	})
	return uint64(val.Int64), def, err
}

func (qs *accountsDbQueries) writeCatchpointStateUint64(ctx context.Context, stateName catchpointState, setValue uint64) (cleared bool, err error) {
	err = db.Retry(func() (err error) {
		if setValue == 0 {
			_, err = qs.deleteCatchpointState.ExecContext(ctx, stateName)
			cleared = true
			return err
		}

		// we don't know if there is an entry in the table for this state, so we'll insert/replace it just in case.
		_, err = qs.insertCatchpointStateUint64.ExecContext(ctx, stateName, setValue)
		cleared = false
		return err
	})
	return cleared, err

}

func (qs *accountsDbQueries) readCatchpointStateString(ctx context.Context, stateName catchpointState) (str string, def bool, err error) {
	var val sql.NullString
	err = db.Retry(func() (err error) {
		err = qs.selectCatchpointStateString.QueryRowContext(ctx, stateName).Scan(&val)
		if err == sql.ErrNoRows || (err == nil && !val.Valid) {
			val.String = "" // default to empty string
			err = nil
			def = true
			return
		}
		return err
	})
	return val.String, def, err
}

func (qs *accountsDbQueries) writeCatchpointStateString(ctx context.Context, stateName catchpointState, setValue string) (cleared bool, err error) {
	err = db.Retry(func() (err error) {
		if setValue == "" {
			_, err = qs.deleteCatchpointState.ExecContext(ctx, stateName)
			cleared = true
			return err
		}

		// we don't know if there is an entry in the table for this state, so we'll insert/replace it just in case.
		_, err = qs.insertCatchpointStateString.ExecContext(ctx, stateName, setValue)
		cleared = false
		return err
	})
	return cleared, err
}

func (qs *accountsDbQueries) close() {
	preparedQueries := []**sql.Stmt{
		&qs.listCreatablesStmt,
		&qs.lookupStmt,
		&qs.lookupResourcesStmt,
		&qs.lookupAllResourcesStmt,
		&qs.lookupKvPairStmt,
		&qs.lookupCreatorStmt,
		&qs.deleteStoredCatchpoint,
		&qs.insertStoredCatchpoint,
		&qs.selectOldestCatchpointFiles,
		&qs.selectCatchpointStateUint64,
		&qs.deleteCatchpointState,
		&qs.insertCatchpointStateUint64,
		&qs.selectCatchpointStateString,
		&qs.insertCatchpointStateString,
	}
	for _, preparedQuery := range preparedQueries {
		if (*preparedQuery) != nil {
			(*preparedQuery).Close()
			*preparedQuery = nil
		}
	}
}

// accountsOnlineTop returns the top n online accounts starting at position offset
// (that is, the top offset'th account through the top offset+n-1'th account).
//
// The accounts are sorted by their normalized balance and address.  The normalized
// balance has to do with the reward parts of online account balances.  See the
// normalization procedure in AccountData.NormalizedOnlineBalance().
//
// Note that this does not check if the accounts have a vote key valid for any
// particular round (past, present, or future).
func accountsOnlineTop(tx *sql.Tx, offset, n uint64, proto config.ConsensusParams) (map[basics.Address]*ledgercore.OnlineAccount, error) {
	rows, err := tx.Query("SELECT address, data FROM accountbase WHERE normalizedonlinebalance>0 ORDER BY normalizedonlinebalance DESC, address DESC LIMIT ? OFFSET ?", n, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[basics.Address]*ledgercore.OnlineAccount, n)
	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		err = rows.Scan(&addrbuf, &buf)
		if err != nil {
			return nil, err
		}

		var data baseAccountData
		err = protocol.Decode(buf, &data)
		if err != nil {
			return nil, err
		}

		var addr basics.Address
		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return nil, err
		}

		copy(addr[:], addrbuf)
		ad := data.GetLedgerCoreAccountData()
		res[addr] = accountDataToOnline(addr, &ad, proto)
	}

	return res, rows.Err()
}

func accountsTotals(tx *sql.Tx, catchpointStaging bool) (totals ledgercore.AccountTotals, err error) {
	id := ""
	if catchpointStaging {
		id = "catchpointStaging"
	}
	row := tx.QueryRow("SELECT online, onlinerewardunits, offline, offlinerewardunits, notparticipating, notparticipatingrewardunits, rewardslevel FROM accounttotals WHERE id=?", id)
	err = row.Scan(&totals.Online.Money.Raw, &totals.Online.RewardUnits,
		&totals.Offline.Money.Raw, &totals.Offline.RewardUnits,
		&totals.NotParticipating.Money.Raw, &totals.NotParticipating.RewardUnits,
		&totals.RewardsLevel)

	return
}

func accountsPutTotals(tx *sql.Tx, totals ledgercore.AccountTotals, catchpointStaging bool) error {
	id := ""
	if catchpointStaging {
		id = "catchpointStaging"
	}
	_, err := tx.Exec("REPLACE INTO accounttotals (id, online, onlinerewardunits, offline, offlinerewardunits, notparticipating, notparticipatingrewardunits, rewardslevel) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		id,
		totals.Online.Money.Raw, totals.Online.RewardUnits,
		totals.Offline.Money.Raw, totals.Offline.RewardUnits,
		totals.NotParticipating.Money.Raw, totals.NotParticipating.RewardUnits,
		totals.RewardsLevel)
	return err
}

type accountsWriter interface {
	insertAccount(addr basics.Address, normBalance uint64, data baseAccountData) (rowid int64, err error)
	deleteAccount(rowid int64) (rowsAffected int64, err error)
	updateAccount(rowid int64, normBalance uint64, data baseAccountData) (rowsAffected int64, err error)

	insertResource(addrid int64, aidx basics.CreatableIndex, data resourcesData) (rowid int64, err error)
	deleteResource(addrid int64, aidx basics.CreatableIndex) (rowsAffected int64, err error)
	updateResource(addrid int64, aidx basics.CreatableIndex, data resourcesData) (rowsAffected int64, err error)

	upsertKvPair(key string, value string) error
	deleteKvPair(key string) error

	insertCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType, creator []byte) (rowid int64, err error)
	deleteCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType) (rowsAffected int64, err error)

	close()
}

type accountsSQLWriter struct {
	insertCreatableIdxStmt, deleteCreatableIdxStmt             *sql.Stmt
	deleteByRowIDStmt, insertStmt, updateStmt                  *sql.Stmt
	deleteResourceStmt, insertResourceStmt, updateResourceStmt *sql.Stmt
	deleteKvPairStmt, upsertKvPairStmt                         *sql.Stmt
}

func (w *accountsSQLWriter) close() {
	if w.deleteByRowIDStmt != nil {
		w.deleteByRowIDStmt.Close()
		w.deleteByRowIDStmt = nil
	}
	if w.insertStmt != nil {
		w.insertStmt.Close()
		w.insertStmt = nil
	}
	if w.updateStmt != nil {
		w.updateStmt.Close()
		w.updateStmt = nil
	}
	if w.deleteResourceStmt != nil {
		w.deleteResourceStmt.Close()
		w.deleteResourceStmt = nil
	}
	if w.insertResourceStmt != nil {
		w.insertResourceStmt.Close()
		w.insertResourceStmt = nil
	}
	if w.updateResourceStmt != nil {
		w.updateResourceStmt.Close()
		w.updateResourceStmt = nil
	}
	if w.deleteKvPairStmt != nil {
		w.deleteKvPairStmt.Close()
		w.deleteKvPairStmt = nil
	}
	if w.upsertKvPairStmt != nil {
		w.upsertKvPairStmt.Close()
		w.upsertKvPairStmt = nil
	}
	if w.insertCreatableIdxStmt != nil {
		w.insertCreatableIdxStmt.Close()
		w.insertCreatableIdxStmt = nil
	}
	if w.deleteCreatableIdxStmt != nil {
		w.deleteCreatableIdxStmt.Close()
		w.deleteCreatableIdxStmt = nil
	}
}

func makeAccountsSQLWriter(tx *sql.Tx, hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (w *accountsSQLWriter, err error) {
	w = new(accountsSQLWriter)

	if hasAccounts {
		w.deleteByRowIDStmt, err = tx.Prepare("DELETE FROM accountbase WHERE rowid=?")
		if err != nil {
			return
		}

		w.insertStmt, err = tx.Prepare("INSERT INTO accountbase (address, normalizedonlinebalance, data) VALUES (?, ?, ?)")
		if err != nil {
			return
		}

		w.updateStmt, err = tx.Prepare("UPDATE accountbase SET normalizedonlinebalance = ?, data = ? WHERE rowid = ?")
		if err != nil {
			return
		}
	}

	if hasResources {
		w.deleteResourceStmt, err = tx.Prepare("DELETE FROM resources WHERE addrid = ? AND aidx = ?")
		if err != nil {
			return
		}

		w.insertResourceStmt, err = tx.Prepare("INSERT INTO resources(addrid, aidx, data) VALUES(?, ?, ?)")
		if err != nil {
			return
		}

		w.updateResourceStmt, err = tx.Prepare("UPDATE resources SET data = ? WHERE addrid = ? AND aidx = ?")
		if err != nil {
			return
		}
	}

	if hasKvPairs {
		w.upsertKvPairStmt, err = tx.Prepare("INSERT INTO kvstore (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
		if err != nil {
			return
		}

		w.deleteKvPairStmt, err = tx.Prepare("DELETE FROM kvstore WHERE key=?")
		if err != nil {
			return
		}
	}

	if hasCreatables {
		w.insertCreatableIdxStmt, err = tx.Prepare("INSERT INTO assetcreators (asset, creator, ctype) VALUES (?, ?, ?)")
		if err != nil {
			return
		}

		w.deleteCreatableIdxStmt, err = tx.Prepare("DELETE FROM assetcreators WHERE asset=? AND ctype=?")
		if err != nil {
			return
		}
	}
	return
}

func (w accountsSQLWriter) insertAccount(addr basics.Address, normBalance uint64, data baseAccountData) (rowid int64, err error) {
	result, err := w.insertStmt.Exec(addr[:], normBalance, protocol.Encode(&data))
	if err != nil {
		return
	}
	rowid, err = result.LastInsertId()
	return
}

func (w accountsSQLWriter) deleteAccount(rowid int64) (rowsAffected int64, err error) {
	result, err := w.deleteByRowIDStmt.Exec(rowid)
	if err != nil {
		return
	}
	rowsAffected, err = result.RowsAffected()
	return
}

func (w accountsSQLWriter) updateAccount(rowid int64, normBalance uint64, data baseAccountData) (rowsAffected int64, err error) {
	result, err := w.updateStmt.Exec(normBalance, protocol.Encode(&data), rowid)
	if err != nil {
		return
	}
	rowsAffected, err = result.RowsAffected()
	return
}

func (w accountsSQLWriter) insertResource(addrid int64, aidx basics.CreatableIndex, data resourcesData) (rowid int64, err error) {
	result, err := w.insertResourceStmt.Exec(addrid, aidx, protocol.Encode(&data))
	if err != nil {
		return
	}
	rowid, err = result.LastInsertId()
	return
}

func (w accountsSQLWriter) deleteResource(addrid int64, aidx basics.CreatableIndex) (rowsAffected int64, err error) {
	result, err := w.deleteResourceStmt.Exec(addrid, aidx)
	if err != nil {
		return
	}
	rowsAffected, err = result.RowsAffected()
	return
}

func (w accountsSQLWriter) updateResource(addrid int64, aidx basics.CreatableIndex, data resourcesData) (rowsAffected int64, err error) {
	result, err := w.updateResourceStmt.Exec(protocol.Encode(&data), addrid, aidx)
	if err != nil {
		return
	}
	rowsAffected, err = result.RowsAffected()
	return
}

func (w accountsSQLWriter) upsertKvPair(key string, value string) error {
	result, err := w.upsertKvPairStmt.Exec(key, value)
	if err != nil {
		return err
	}
	_, err = result.LastInsertId()
	return err
}

func (w accountsSQLWriter) deleteKvPair(key string) error {
	result, err := w.deleteKvPairStmt.Exec(key)
	if err != nil {
		return err
	}
	_, err = result.RowsAffected()
	return err
}

func (w accountsSQLWriter) insertCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType, creator []byte) (rowid int64, err error) {
	result, err := w.insertCreatableIdxStmt.Exec(cidx, creator, ctype)
	if err != nil {
		return
	}
	rowid, err = result.LastInsertId()
	return
}

func (w accountsSQLWriter) deleteCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType) (rowsAffected int64, err error) {
	result, err := w.deleteCreatableIdxStmt.Exec(cidx, ctype)
	if err != nil {
		return
	}
	rowsAffected, err = result.RowsAffected()
	return
}

// accountsNewRound is a convenience wrapper for accountsNewRoundImpl
func accountsNewRound(
	tx *sql.Tx,
	updates compactAccountDeltas, resources compactResourcesDeltas, kvPairs map[string]modifiedValue, creatables map[basics.CreatableIndex]ledgercore.ModifiedCreatable,
	proto config.ConsensusParams, lastUpdateRound basics.Round,
) (updatedAccounts []persistedAccountData, updatedResources map[basics.Address][]persistedResourcesData, err error) {
	hasAccounts := updates.len() > 0
	hasResources := resources.len() > 0
	hasKvPairs := len(kvPairs) > 0
	hasCreatables := len(creatables) > 0
	writer, err := makeAccountsSQLWriter(tx, hasAccounts, hasResources, hasKvPairs, hasCreatables)
	if err != nil {
		return
	}
	defer writer.close()

	return accountsNewRoundImpl(writer, updates, resources, kvPairs, creatables, proto, lastUpdateRound)
}

// accountsNewRoundImpl updates the accountbase and assetcreators tables by applying the provided deltas to the accounts / creatables.
// The function returns a persistedAccountData for the modified accounts which can be stored in the base cache.
func accountsNewRoundImpl(
	writer accountsWriter,
	updates compactAccountDeltas, resources compactResourcesDeltas, kvPairs map[string]modifiedValue, creatables map[basics.CreatableIndex]ledgercore.ModifiedCreatable,
	proto config.ConsensusParams, lastUpdateRound basics.Round,
) (updatedAccounts []persistedAccountData, updatedResources map[basics.Address][]persistedResourcesData, err error) {
	updatedAccounts = make([]persistedAccountData, updates.len())
	updatedAccountIdx := 0
	newAddressesRowIDs := make(map[basics.Address]int64)
	for i := 0; i < updates.len(); i++ {
		data := updates.getByIdx(i)
		if data.oldAcct.rowid == 0 {
			// zero rowid means we don't have a previous value.
			if data.newAcct.IsEmpty() {
				// IsEmpty means we don't have a previous value. Note, can't use newAcct.MsgIsZero
				// because of non-zero UpdateRound field in a new delta
				// if we didn't had it before, and we don't have anything now, just skip it.
			} else {
				// create a new entry.
				var rowid int64
				normBalance := data.newAcct.NormalizedOnlineBalance(proto)
				rowid, err = writer.insertAccount(data.address, normBalance, data.newAcct)
				if err == nil {
					updatedAccounts[updatedAccountIdx].rowid = rowid
					updatedAccounts[updatedAccountIdx].accountData = data.newAcct
					newAddressesRowIDs[data.address] = rowid
				}
			}
		} else {
			// non-zero rowid means we had a previous value.
			if data.newAcct.IsEmpty() {
				// new value is zero, which means we need to delete the current value.
				var rowsAffected int64
				rowsAffected, err = writer.deleteAccount(data.oldAcct.rowid)
				if err == nil {
					// we deleted the entry successfully.
					updatedAccounts[updatedAccountIdx].rowid = 0
					updatedAccounts[updatedAccountIdx].accountData = baseAccountData{}
					if rowsAffected != 1 {
						err = fmt.Errorf("failed to delete accountbase row for account %v, rowid %d", data.address, data.oldAcct.rowid)
					}
				}
			} else {
				var rowsAffected int64
				normBalance := data.newAcct.NormalizedOnlineBalance(proto)
				rowsAffected, err = writer.updateAccount(data.oldAcct.rowid, normBalance, data.newAcct)
				if err == nil {
					// rowid doesn't change on update.
					updatedAccounts[updatedAccountIdx].rowid = data.oldAcct.rowid
					updatedAccounts[updatedAccountIdx].accountData = data.newAcct
					if rowsAffected != 1 {
						err = fmt.Errorf("failed to update accountbase row for account %v, rowid %d", data.address, data.oldAcct.rowid)
					}
				}
			}
		}

		if err != nil {
			return
		}

		// set the returned persisted account states so that we could store that as the baseAccounts in commitRound
		updatedAccounts[updatedAccountIdx].round = lastUpdateRound
		updatedAccounts[updatedAccountIdx].addr = data.address
		updatedAccountIdx++
	}

	updatedResources = make(map[basics.Address][]persistedResourcesData)

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
		if data.oldResource.addrid == 0 || data.oldResource.data.IsEmpty() || !data.newResource.IsEmpty() {
			continue
		}
		if pendingResourcesDeletion == nil {
			pendingResourcesDeletion = make(map[resourceKey]struct{})
		}
		pendingResourcesDeletion[resourceKey{addrid: data.oldResource.addrid, aidx: data.oldResource.aidx}] = struct{}{}

		entry := persistedResourcesData{addrid: 0, aidx: data.oldResource.aidx, data: makeResourcesData(0), round: lastUpdateRound}
		deltas := updatedResources[data.address]
		deltas = append(deltas, entry)
		updatedResources[data.address] = deltas
	}

	for i := 0; i < resources.len(); i++ {
		data := resources.getByIdx(i)
		addr := data.address
		aidx := data.oldResource.aidx
		addrid := data.oldResource.addrid
		if addrid == 0 {
			// new entry, data.oldResource does not have addrid
			// check if this delta is part of in-memory only account
			// that is created, funded, transferred, and closed within a commit range
			inMemEntry := data.oldResource.data.IsEmpty() && data.newResource.IsEmpty()
			addrid = newAddressesRowIDs[addr]
			if addrid == 0 && !inMemEntry {
				err = fmt.Errorf("cannot resolve address %s (%d), aidx %d, data %v", addr.String(), addrid, aidx, data.newResource)
				return
			}
		}
		var entry persistedResourcesData
		if data.oldResource.data.IsEmpty() {
			// IsEmpty means we don't have a previous value. Note, can't use oldResource.data.MsgIsZero
			// because of possibility of empty asset holdings or app local state after opting in,
			// as well as non-zero UpdateRound field in a new delta
			if data.newResource.IsEmpty() {
				// if we didn't had it before, and we don't have anything now, just skip it.
				// set zero addrid to mark this entry invalid for subsequent addr to addrid resolution
				// because the base account might gone.
				entry = persistedResourcesData{addrid: 0, aidx: aidx, data: makeResourcesData(0), round: lastUpdateRound}
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
					rowsAffected, err = writer.updateResource(addrid, aidx, data.newResource)
					if err == nil {
						// rowid doesn't change on update.
						entry = persistedResourcesData{addrid: addrid, aidx: aidx, data: data.newResource, round: lastUpdateRound}
						if rowsAffected != 1 {
							err = fmt.Errorf("failed to update resources row for addr %s (%d), aidx %d", addr, addrid, aidx)
						}
					}
				} else {
					_, err = writer.insertResource(addrid, aidx, data.newResource)
					if err == nil {
						// set the returned persisted account states so that we could store that as the baseResources in commitRound
						entry = persistedResourcesData{addrid: addrid, aidx: aidx, data: data.newResource, round: lastUpdateRound}
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
				rowsAffected, err = writer.updateResource(addrid, aidx, data.newResource)
				if err == nil {
					// rowid doesn't change on update.
					entry = persistedResourcesData{addrid: addrid, aidx: aidx, data: data.newResource, round: lastUpdateRound}
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
		rowsAffected, err = writer.deleteResource(delRes.addrid, delRes.aidx)
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

	for key, value := range kvPairs {
		if value.data != nil {
			err = writer.upsertKvPair(key, *value.data)
		} else {
			err = writer.deleteKvPair(key)
		}
		if err != nil {
			return
		}
	}

	for cidx, cdelta := range creatables {
		if cdelta.Created {
			_, err = writer.insertCreatable(cidx, cdelta.Ctype, cdelta.Creator[:])
		} else {
			_, err = writer.deleteCreatable(cidx, cdelta.Ctype)
		}
		if err != nil {
			return
		}
	}

	return
}

// updates the round number associated with the current account data.
func updateAccountsRound(tx *sql.Tx, rnd basics.Round) (err error) {
	res, err := tx.Exec("UPDATE acctrounds SET rnd=? WHERE id='acctbase' AND rnd<?", rnd, rnd)
	if err != nil {
		return
	}

	aff, err := res.RowsAffected()
	if err != nil {
		return
	}

	if aff != 1 {
		// try to figure out why we couldn't update the round number.
		var base basics.Round
		err = tx.QueryRow("SELECT rnd FROM acctrounds WHERE id='acctbase'").Scan(&base)
		if err != nil {
			return
		}
		if base > rnd {
			err = fmt.Errorf("newRound %d is not after base %d", rnd, base)
			return
		} else if base != rnd {
			err = fmt.Errorf("updateAccountsRound(acctbase, %d): expected to update 1 row but got %d", rnd, aff)
			return
		}
	}
	return
}

// updates the round number associated with the hash of current account data.
func updateAccountsHashRound(tx *sql.Tx, hashRound basics.Round) (err error) {
	res, err := tx.Exec("INSERT OR REPLACE INTO acctrounds(id,rnd) VALUES('hashbase',?)", hashRound)
	if err != nil {
		return
	}

	aff, err := res.RowsAffected()
	if err != nil {
		return
	}

	if aff != 1 {
		err = fmt.Errorf("updateAccountsHashRound(hashbase,%d): expected to update 1 row but got %d", hashRound, aff)
		return
	}
	return
}

// totalAccounts returns the total number of accounts
func totalAccounts(ctx context.Context, tx *sql.Tx) (total uint64, err error) {
	err = tx.QueryRowContext(ctx, "SELECT count(*) FROM accountbase").Scan(&total)
	if err == sql.ErrNoRows {
		total = 0
		err = nil
		return
	}
	return
}

// reencodeAccounts reads all the accounts in the accountbase table, decode and reencode the account data.
// if the account data is found to have a different encoding, it would update the encoded account on disk.
// on return, it returns the number of modified accounts as well as an error ( if we had any )
func reencodeAccounts(ctx context.Context, tx *sql.Tx) (modifiedAccounts uint, err error) {
	modifiedAccounts = 0
	scannedAccounts := 0

	updateStmt, err := tx.PrepareContext(ctx, "UPDATE accountbase SET data = ? WHERE address = ?")
	if err != nil {
		return 0, err
	}

	rows, err := tx.QueryContext(ctx, "SELECT address, data FROM accountbase")
	if err != nil {
		return
	}
	defer rows.Close()

	var addr basics.Address
	for rows.Next() {
		// once every 1000 accounts we scan through, update the warning deadline.
		// as long as the last "chunk" takes less than one second, we should be good to go.
		// note that we should be quite liberal on timing here, since it might perform much slower
		// on low-power devices.
		if scannedAccounts%1000 == 0 {
			// The return value from ResetTransactionWarnDeadline can be safely ignored here since it would only default to writing the warning
			// message, which would let us know that it failed anyway.
			db.ResetTransactionWarnDeadline(ctx, tx, time.Now().Add(time.Second))
		}

		var addrbuf []byte
		var preencodedAccountData []byte
		err = rows.Scan(&addrbuf, &preencodedAccountData)
		if err != nil {
			return
		}

		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return
		}
		copy(addr[:], addrbuf[:])
		scannedAccounts++

		// decode and re-encode:
		var decodedAccountData basics.AccountData
		err = protocol.Decode(preencodedAccountData, &decodedAccountData)
		if err != nil {
			return
		}
		reencodedAccountData := protocol.Encode(&decodedAccountData)
		if bytes.Equal(preencodedAccountData, reencodedAccountData) {
			// these are identical, no need to store re-encoded account data
			continue
		}

		// we need to update the encoded data.
		result, err := updateStmt.ExecContext(ctx, reencodedAccountData, addrbuf)
		if err != nil {
			return 0, err
		}
		rowsUpdated, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		if rowsUpdated != 1 {
			return 0, fmt.Errorf("failed to update account %v, number of rows updated was %d instead of 1", addr, rowsUpdated)
		}
		modifiedAccounts++
	}

	err = rows.Err()
	updateStmt.Close()
	return
}

// MerkleCommitter allows storing and loading merkletrie pages from a sqlite database.
//msgp:ignore MerkleCommitter
type MerkleCommitter struct {
	tx         *sql.Tx
	deleteStmt *sql.Stmt
	insertStmt *sql.Stmt
	selectStmt *sql.Stmt
}

// MakeMerkleCommitter creates a MerkleCommitter object that implements the merkletrie.Committer interface allowing storing and loading
// merkletrie pages from a sqlite database.
func MakeMerkleCommitter(tx *sql.Tx, staging bool) (mc *MerkleCommitter, err error) {
	mc = &MerkleCommitter{tx: tx}
	accountHashesTable := "accounthashes"
	if staging {
		accountHashesTable = "catchpointaccounthashes"
	}
	mc.deleteStmt, err = tx.Prepare("DELETE FROM " + accountHashesTable + " WHERE id=?")
	if err != nil {
		return nil, err
	}
	mc.insertStmt, err = tx.Prepare("INSERT OR REPLACE INTO " + accountHashesTable + "(id, data) VALUES(?, ?)")
	if err != nil {
		return nil, err
	}
	mc.selectStmt, err = tx.Prepare("SELECT data FROM " + accountHashesTable + " WHERE id = ?")
	if err != nil {
		return nil, err
	}
	return mc, nil
}

// StorePage is the merkletrie.Committer interface implementation, stores a single page in a sqlite database table.
func (mc *MerkleCommitter) StorePage(page uint64, content []byte) error {
	if len(content) == 0 {
		_, err := mc.deleteStmt.Exec(page)
		return err
	}
	_, err := mc.insertStmt.Exec(page, content)
	return err
}

// LoadPage is the merkletrie.Committer interface implementation, load a single page from a sqlite database table.
func (mc *MerkleCommitter) LoadPage(page uint64) (content []byte, err error) {
	err = mc.selectStmt.QueryRow(page).Scan(&content)
	if err == sql.ErrNoRows {
		content = nil
		err = nil
		return
	} else if err != nil {
		return nil, err
	}
	return content, nil
}

// encodedAccountsBatchIter allows us to iterate over the accounts data stored in the accountbase table.
type encodedAccountsBatchIter struct {
	accountsRows  *sql.Rows
	resourcesRows *sql.Rows
	nextRow       pendingRow
}

// Next returns an array containing the account data, in the same way it appear in the database
// returning accountCount accounts data at a time.
func (iterator *encodedAccountsBatchIter) Next(ctx context.Context, tx *sql.Tx, accountCount int) (bals []encodedBalanceRecordV6, err error) {
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
	var baseAcct baseAccountData
	var numAcct int
	baseCb := func(addr basics.Address, rowid int64, accountData *baseAccountData, encodedAccountData []byte) (err error) {
		encodedRecord = encodedBalanceRecordV6{Address: addr, AccountData: encodedAccountData}
		baseAcct = *accountData
		numAcct++
		return nil
	}

	var totalAppParams, totalAppLocalStates, totalAssetParams, totalAssets uint64
	// emptyCount := 0
	resCb := func(addr basics.Address, cidx basics.CreatableIndex, resData *resourcesData, encodedResourceData []byte) error {
		emptyBaseAcct := baseAcct.TotalAppParams == 0 && baseAcct.TotalAppLocalStates == 0 && baseAcct.TotalAssetParams == 0 && baseAcct.TotalAssets == 0
		if !emptyBaseAcct && resData != nil {
			if encodedRecord.Resources == nil {
				encodedRecord.Resources = make(map[uint64]msgp.Raw)
			}
			encodedRecord.Resources[uint64(cidx)] = encodedResourceData
			if resData.IsApp() && resData.IsOwning() {
				totalAppParams++
			}
			if resData.IsApp() && resData.IsHolding() {
				totalAppLocalStates++
			}

			if resData.IsAsset() && resData.IsOwning() {
				totalAssetParams++
			}
			if resData.IsAsset() && resData.IsHolding() {
				totalAssets++
			}

		}

		if baseAcct.TotalAppParams == totalAppParams &&
			baseAcct.TotalAppLocalStates == totalAppLocalStates &&
			baseAcct.TotalAssetParams == totalAssetParams &&
			baseAcct.TotalAssets == totalAssets {

			bals = append(bals, encodedRecord)
			totalAppParams = 0
			totalAppLocalStates = 0
			totalAssetParams = 0
			totalAssets = 0
		}

		return nil
	}

	_, iterator.nextRow, err = processAllBaseAccountRecords(
		iterator.accountsRows, iterator.resourcesRows,
		baseCb, resCb,
		iterator.nextRow, accountCount,
	)
	if err != nil {
		iterator.Close()
		return
	}

	if len(bals) == accountCount {
		// we're done with this iteration.
		return
	}

	err = iterator.accountsRows.Err()
	if err != nil {
		iterator.Close()
		return
	}
	// we just finished reading the table.
	iterator.Close()
	return
}

// Close shuts down the encodedAccountsBatchIter, releasing database resources.
func (iterator *encodedAccountsBatchIter) Close() {
	if iterator.accountsRows != nil {
		iterator.accountsRows.Close()
		iterator.accountsRows = nil
	}
}

// orderedAccountsIterStep is used by orderedAccountsIter to define the current step
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
	step            orderedAccountsIterStep
	accountBaseRows *sql.Rows
	hashesRows      *sql.Rows
	resourcesRows   *sql.Rows
	tx              *sql.Tx
	pendingRow      pendingRow
	accountCount    int
	insertStmt      *sql.Stmt
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

type pendingRow struct {
	addrid int64
	aidx   basics.CreatableIndex
	buf    []byte
}

func processAllResources(
	resRows *sql.Rows,
	addr basics.Address, accountData *baseAccountData, acctRowid int64, pr pendingRow,
	callback func(addr basics.Address, creatableIdx basics.CreatableIndex, resData *resourcesData, encodedResourceData []byte) error,
) (pendingRow, error) {
	var err error
	for {
		var buf []byte
		var addrid int64
		var aidx basics.CreatableIndex
		if pr.addrid != 0 {
			// some accounts may not have resources, consider the following case:
			// acct 1 and 3 has resources, account 2 does not
			// in this case addrid = 3 after processing resources from 1, but acctRowid = 2
			// and we need to skip accounts without resources
			if pr.addrid > acctRowid {
				err = callback(addr, 0, nil, nil)
				return pr, err
			}
			if pr.addrid < acctRowid {
				err = fmt.Errorf("resource table entries mismatches accountbase table entries : reached addrid %d while expecting resource for %d", pr.addrid, acctRowid)
				return pendingRow{}, err
			}
			addrid = pr.addrid
			buf = pr.buf
			aidx = pr.aidx
			pr = pendingRow{}
		} else {
			if !resRows.Next() {
				err = callback(addr, 0, nil, nil)
				if err != nil {
					return pendingRow{}, err
				}
				break
			}
			err = resRows.Scan(&addrid, &aidx, &buf)
			if err != nil {
				return pendingRow{}, err
			}
			if addrid < acctRowid {
				err = fmt.Errorf("resource table entries mismatches accountbase table entries : reached addrid %d while expecting resource for %d", addrid, acctRowid)
				return pendingRow{}, err
			} else if addrid > acctRowid {
				err = callback(addr, 0, nil, nil)
				return pendingRow{addrid, aidx, buf}, err
			}
		}
		var resData resourcesData
		err = protocol.Decode(buf, &resData)
		if err != nil {
			return pendingRow{}, err
		}
		err = callback(addr, aidx, &resData, buf)
		if err != nil {
			return pendingRow{}, err
		}
	}
	return pendingRow{}, nil
}

func processAllBaseAccountRecords(
	baseRows *sql.Rows,
	resRows *sql.Rows,
	baseCb func(addr basics.Address, rowid int64, accountData *baseAccountData, encodedAccountData []byte) error,
	resCb func(addr basics.Address, creatableIdx basics.CreatableIndex, resData *resourcesData, encodedResourceData []byte) error,
	pending pendingRow, accountCount int,
) (int, pendingRow, error) {
	var addr basics.Address
	var prevAddr basics.Address
	var err error
	count := 0
	for baseRows.Next() {
		var addrbuf []byte
		var buf []byte
		var rowid int64
		err = baseRows.Scan(&rowid, &addrbuf, &buf)
		if err != nil {
			return 0, pendingRow{}, err
		}

		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return 0, pendingRow{}, err
		}

		copy(addr[:], addrbuf)

		var accountData baseAccountData
		err = protocol.Decode(buf, &accountData)
		if err != nil {
			return 0, pendingRow{}, err
		}
		err = baseCb(addr, rowid, &accountData, buf)
		if err != nil {
			return 0, pendingRow{}, err
		}

		pending, err = processAllResources(resRows, addr, &accountData, rowid, pending, resCb)
		if err != nil {
			err = fmt.Errorf("failed to gather resources for account %v, addrid %d, prev address %v : %w", addr, rowid, prevAddr, err)
			return 0, pendingRow{}, err
		}

		count++
		if accountCount > 0 && count == accountCount {
			// we're done with this iteration.
			return count, pending, nil
		}
		prevAddr = addr
	}

	return count, pending, nil
}

// loadFullAccount converts baseAccountData into basics.AccountData and loads all resources as needed
func loadFullAccount(ctx context.Context, tx *sql.Tx, resourcesTable string, addr basics.Address, addrid int64, data baseAccountData) (ad basics.AccountData, err error) {
	ad = data.GetAccountData()

	hasResources := false
	if data.TotalAppParams > 0 {
		ad.AppParams = make(map[basics.AppIndex]basics.AppParams, data.TotalAppParams)
		hasResources = true
	}
	if data.TotalAppLocalStates > 0 {
		ad.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState, data.TotalAppLocalStates)
		hasResources = true
	}
	if data.TotalAssetParams > 0 {
		ad.AssetParams = make(map[basics.AssetIndex]basics.AssetParams, data.TotalAssetParams)
		hasResources = true
	}
	if data.TotalAssets > 0 {
		ad.Assets = make(map[basics.AssetIndex]basics.AssetHolding, data.TotalAssets)
		hasResources = true
	}

	if !hasResources {
		return
	}

	var resRows *sql.Rows
	query := fmt.Sprintf("SELECT aidx, data FROM %s where addrid = ?", resourcesTable)
	resRows, err = tx.QueryContext(ctx, query, addrid)
	if err != nil {
		return
	}
	defer resRows.Close()

	for resRows.Next() {
		var buf []byte
		var aidx int64
		err = resRows.Scan(&aidx, &buf)
		if err != nil {
			return
		}
		var resData resourcesData
		err = protocol.Decode(buf, &resData)
		if err != nil {
			return
		}
		if resData.ResourceFlags == resourceFlagsNotHolding {
			err = fmt.Errorf("addr %s (%d) aidx = %d resourceFlagsNotHolding should not be persisted", addr.String(), addrid, aidx)
			return
		}
		if resData.IsApp() {
			if resData.IsOwning() {
				ad.AppParams[basics.AppIndex(aidx)] = resData.GetAppParams()
			}
			if resData.IsHolding() {
				ad.AppLocalStates[basics.AppIndex(aidx)] = resData.GetAppLocalState()
			}
		} else if resData.IsAsset() {
			if resData.IsOwning() {
				ad.AssetParams[basics.AssetIndex(aidx)] = resData.GetAssetParams()
			}
			if resData.IsHolding() {
				ad.Assets[basics.AssetIndex(aidx)] = resData.GetAssetHolding()
			}
		} else {
			err = fmt.Errorf("unknown resource data: %v", resData)
			return
		}
	}

	if uint64(len(ad.AssetParams)) != data.TotalAssetParams {
		err = fmt.Errorf("%s assets params mismatch: %d != %d", addr.String(), len(ad.AssetParams), data.TotalAssetParams)
	}
	if err == nil && uint64(len(ad.Assets)) != data.TotalAssets {
		err = fmt.Errorf("%s assets mismatch: %d != %d", addr.String(), len(ad.Assets), data.TotalAssets)
	}
	if err == nil && uint64(len(ad.AppParams)) != data.TotalAppParams {
		err = fmt.Errorf("%s app params mismatch: %d != %d", addr.String(), len(ad.AppParams), data.TotalAppParams)
	}
	if err == nil && uint64(len(ad.AppLocalStates)) != data.TotalAppLocalStates {
		err = fmt.Errorf("%s app local states mismatch: %d != %d", addr.String(), len(ad.AppLocalStates), data.TotalAppLocalStates)
	}
	if err != nil {
		return
	}

	return
}

// LoadAllFullAccounts loads all accounts from balancesTable and resourcesTable.
// On every account full load it invokes acctCb callback to report progress and data.
func LoadAllFullAccounts(
	ctx context.Context, tx *sql.Tx,
	balancesTable string, resourcesTable string,
	acctCb func(basics.Address, basics.AccountData),
) (count int, err error) {
	baseRows, err := tx.QueryContext(ctx, fmt.Sprintf("SELECT rowid, address, data FROM %s ORDER BY address", balancesTable))
	if err != nil {
		return
	}
	defer baseRows.Close()

	for baseRows.Next() {
		var addrbuf []byte
		var buf []byte
		var rowid sql.NullInt64
		err = baseRows.Scan(&rowid, &addrbuf, &buf)
		if err != nil {
			return
		}
		if !rowid.Valid {
			err = fmt.Errorf("invalid rowid in %s", balancesTable)
			return
		}

		var data baseAccountData
		err = protocol.Decode(buf, &data)
		if err != nil {
			return
		}

		var addr basics.Address
		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return
		}
		copy(addr[:], addrbuf)

		var ad basics.AccountData
		ad, err = loadFullAccount(ctx, tx, resourcesTable, addr, rowid.Int64, data)
		if err != nil {
			return
		}

		acctCb(addr, ad)

		count++
	}
	return
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
		baseCb := func(addr basics.Address, rowid int64, accountData *baseAccountData, encodedAccountData []byte) (err error) {
			hash := accountHashBuilderV6(addr, accountData, encodedAccountData)
			_, err = iterator.insertStmt.ExecContext(ctx, rowid, hash)
			if err != nil {
				return
			}
			lastAddrID = rowid
			return nil
		}

		resCb := func(addr basics.Address, cidx basics.CreatableIndex, resData *resourcesData, encodedResourceData []byte) error {
			var err error
			if resData != nil {
				var ctype basics.CreatableType
				if resData.IsAsset() {
					ctype = basics.AssetCreatable
				} else if resData.IsApp() {
					ctype = basics.AppCreatable
				} else {
					err = fmt.Errorf("unknown creatable for addr %s, aidx %d, data %v", addr.String(), cidx, resData)
					return err
				}
				hash := resourcesHashBuilderV6(addr, cidx, ctype, resData.UpdateRound, encodedResourceData)
				_, err = iterator.insertStmt.ExecContext(ctx, lastAddrID, hash)
			}
			return err
		}

		count := 0
		count, iterator.pendingRow, err = processAllBaseAccountRecords(
			iterator.accountBaseRows, iterator.resourcesRows,
			baseCb, resCb,
			iterator.pendingRow, iterator.accountCount,
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

// createCatchpointStagingHashesIndex creates an index on catchpointpendinghashes to allow faster scanning according to the hash order
func lookupAccountAddressFromAddressID(ctx context.Context, tx *sql.Tx, addrid int64) (address basics.Address, err error) {
	var addrbuf []byte
	err = tx.QueryRowContext(ctx, "SELECT address FROM accountbase WHERE rowid = ?", addrid).Scan(&addrbuf)
	if err != nil {
		if err == sql.ErrNoRows {
			err = fmt.Errorf("no matching address could be found for rowid %d: %w", addrid, err)
		}
		return
	}
	if len(addrbuf) != len(address) {
		err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(address))
		return
	}
	copy(address[:], addrbuf)
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

// before compares the round numbers of two persistedAccountData and determines if the current persistedAccountData
// happened before the other.
func (pac *persistedAccountData) before(other *persistedAccountData) bool {
	return pac.round < other.round
}

// before compares the round numbers of two persistedResourcesData and determines if the current persistedResourcesData
// happened before the other.
func (prd *persistedResourcesData) before(other *persistedResourcesData) bool {
	return prd.round < other.round
}
