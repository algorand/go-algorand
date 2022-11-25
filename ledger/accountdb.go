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
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/mattn/go-sqlite3"

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

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
		ON %s ( normalizedonlinebalance, address, data ) WHERE normalizedonlinebalance>0`, idxname, tablename)
}

// createNormalizedOnlineBalanceIndexOnline handles onlineaccounts/catchpointonlineaccounts tables
func createNormalizedOnlineBalanceIndexOnline(idxname string, tablename string) string {
	return fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s
		ON %s ( normalizedonlinebalance, address )`, idxname, tablename)
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

var createBoxTable = []string{
	`CREATE TABLE IF NOT EXISTS kvstore (
		key blob primary key,
		value blob)`,
}

var createOnlineAccountsTable = []string{
	`CREATE TABLE IF NOT EXISTS onlineaccounts (
		address BLOB NOT NULL,
		updround INTEGER NOT NULL,
		normalizedonlinebalance INTEGER NOT NULL,
		votelastvalid INTEGER NOT NULL,
		data BLOB NOT NULL,
		PRIMARY KEY (address, updround) )`,
	createNormalizedOnlineBalanceIndexOnline("onlineaccountnorm", "onlineaccounts"),
}

var createTxTailTable = []string{
	`CREATE TABLE IF NOT EXISTS txtail (
		rnd INTEGER PRIMARY KEY NOT NULL,
		data BLOB NOT NULL)`,
}

var createOnlineRoundParamsTable = []string{
	`CREATE TABLE IF NOT EXISTS onlineroundparamstail(
		rnd INTEGER NOT NULL PRIMARY KEY,
		data BLOB NOT NULL)`, // contains a msgp encoded OnlineRoundParamsData
}

// Table containing some metadata for a future catchpoint. The `info` column
// contains a serialized object of type catchpointFirstStageInfo.
const createCatchpointFirstStageInfoTable = `
	CREATE TABLE IF NOT EXISTS catchpointfirststageinfo (
	round integer primary key NOT NULL,
	info BLOB NOT NULL)`

const createUnfinishedCatchpointsTable = `
	CREATE TABLE IF NOT EXISTS unfinishedcatchpoints (
	round integer primary key NOT NULL,
	blockhash blob NOT NULL)`

var accountsResetExprs = []string{
	`DROP TABLE IF EXISTS acctrounds`,
	`DROP TABLE IF EXISTS accounttotals`,
	`DROP TABLE IF EXISTS accountbase`,
	`DROP TABLE IF EXISTS kvstore`,
	`DROP TABLE IF EXISTS assetcreators`,
	`DROP TABLE IF EXISTS storedcatchpoints`,
	`DROP TABLE IF EXISTS catchpointstate`,
	`DROP TABLE IF EXISTS accounthashes`,
	`DROP TABLE IF EXISTS resources`,
	`DROP TABLE IF EXISTS onlineaccounts`,
	`DROP TABLE IF EXISTS txtail`,
	`DROP TABLE IF EXISTS onlineroundparamstail`,
	`DROP TABLE IF EXISTS catchpointfirststageinfo`,
	`DROP TABLE IF EXISTS unfinishedcatchpoints`,
}

// accountDBVersion is the database version that this binary would know how to support and how to upgrade to.
// details about the content of each of the versions can be found in the upgrade functions upgradeDatabaseSchemaXXXX
// and their descriptions.
var accountDBVersion = int32(9)

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

const (
	// catchpointStateLastCatchpoint is written by a node once a catchpoint label is created for a round
	catchpointStateLastCatchpoint = store.CatchpointState("lastCatchpoint")
	// This state variable is set to 1 if catchpoint's first stage is unfinished,
	// and is 0 otherwise. Used to clear / restart the first stage after a crash.
	// This key is set in the same db transaction as the account updates, so the
	// unfinished first stage corresponds to the current db round.
	catchpointStateWritingFirstStageInfo = store.CatchpointState("writingFirstStageInfo")
	// If there is an unfinished catchpoint, this state variable is set to
	// the catchpoint's round. Otherwise, it is set to 0.
	// DEPRECATED.
	catchpointStateWritingCatchpoint = store.CatchpointState("writingCatchpoint")
	// catchpointCatchupState is the state of the catchup process. The variable is stored only during the catchpoint catchup process, and removed afterward.
	catchpointStateCatchupState = store.CatchpointState("catchpointCatchupState")
	// catchpointStateCatchupLabel is the label to which the currently catchpoint catchup process is trying to catchup to.
	catchpointStateCatchupLabel = store.CatchpointState("catchpointCatchupLabel")
	// catchpointCatchupBlockRound is the block round that is associated with the current running catchpoint catchup.
	catchpointStateCatchupBlockRound = store.CatchpointState("catchpointCatchupBlockRound")
	// catchpointStateCatchupBalancesRound is the balance round that is associated with the current running catchpoint catchup. Typically it would be
	// equal to catchpointStateCatchupBlockRound - 320.
	catchpointStateCatchupBalancesRound = store.CatchpointState("catchpointCatchupBalancesRound")
	// catchpointStateCatchupHashRound is the round that is associated with the hash of the merkle trie. Normally, it's identical to catchpointStateCatchupBalancesRound,
	// however, it could differ when we catchup from a catchpoint that was created using a different version : in this case,
	// we set it to zero in order to reset the merkle trie. This would force the merkle trie to be re-build on startup ( if needed ).
	catchpointStateCatchupHashRound   = store.CatchpointState("catchpointCatchupHashRound")
	catchpointStateCatchpointLookback = store.CatchpointState("catchpointLookback")
)

// MaxEncodedBaseAccountDataSize is a rough estimate for the worst-case scenario we're going to have of the base account data serialized.
// this number is verified by the TestEncodedBaseAccountDataSize function.
const MaxEncodedBaseAccountDataSize = 350

// MaxEncodedBaseResourceDataSize is a rough estimate for the worst-case scenario we're going to have of the base resource data serialized.
// this number is verified by the TestEncodedBaseResourceSize function.
const MaxEncodedBaseResourceDataSize = 20000

// normalizedAccountBalance is a staging area for a catchpoint file account information before it's being added to the catchpoint staging tables.
type normalizedAccountBalance struct {
	// The public key address to which the account belongs.
	address basics.Address
	// accountData contains the baseAccountData for that account.
	accountData store.BaseAccountData
	// resources is a map, where the key is the creatable index, and the value is the resource data.
	resources map[basics.CreatableIndex]store.ResourcesData
	// encodedAccountData contains the baseAccountData encoded bytes that are going to be written to the accountbase table.
	encodedAccountData []byte
	// accountHashes contains a list of all the hashes that would need to be added to the merkle trie for that account.
	// on V6, we could have multiple hashes, since we have separate account/resource hashes.
	accountHashes [][]byte
	// normalizedBalance contains the normalized balance for the account.
	normalizedBalance uint64
	// encodedResources provides the encoded form of the resources
	encodedResources map[basics.CreatableIndex][]byte
	// partial balance indicates that the original account balance was split into multiple parts in catchpoint creation time
	partialBalance bool
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
			store.ResourcesData
		}
		var resources []resourcesRow
		addResourceRow := func(_ context.Context, _ int64, aidx basics.CreatableIndex, rd *store.ResourcesData) error {
			resources = append(resources, resourcesRow{aidx: aidx, ResourcesData: *rd})
			return nil
		}
		if err = accountDataResources(context.Background(), &accountDataV5, 0, addResourceRow); err != nil {
			return nil, err
		}
		normalizedAccountBalances[i].accountHashes = make([][]byte, 1)
		normalizedAccountBalances[i].accountHashes[0] = accountHashBuilder(balance.Address, accountDataV5, balance.AccountData)
		if len(resources) > 0 {
			normalizedAccountBalances[i].resources = make(map[basics.CreatableIndex]store.ResourcesData, len(resources))
			normalizedAccountBalances[i].encodedResources = make(map[basics.CreatableIndex][]byte, len(resources))
		}
		for _, resource := range resources {
			normalizedAccountBalances[i].resources[resource.aidx] = resource.ResourcesData
			normalizedAccountBalances[i].encodedResources[resource.aidx] = protocol.Encode(&resource.ResourcesData)
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
		curHashIdx := 0
		if balance.ExpectingMoreEntries {
			// There is a single chunk in the catchpoint file with ExpectingMoreEntries
			// set to false for this account. There may be multiple chunks with
			// ExpectingMoreEntries set to true. In this case, we do not have to add the
			// account's own hash to accountHashes.
			normalizedAccountBalances[i].accountHashes = make([][]byte, len(balance.Resources))
			normalizedAccountBalances[i].partialBalance = true
		} else {
			normalizedAccountBalances[i].accountHashes = make([][]byte, 1+len(balance.Resources))
			normalizedAccountBalances[i].accountHashes[0] = accountHashBuilderV6(balance.Address, &normalizedAccountBalances[i].accountData, balance.AccountData)
			curHashIdx++
		}
		if len(balance.Resources) > 0 {
			normalizedAccountBalances[i].resources = make(map[basics.CreatableIndex]store.ResourcesData, len(balance.Resources))
			normalizedAccountBalances[i].encodedResources = make(map[basics.CreatableIndex][]byte, len(balance.Resources))
			for cidx, res := range balance.Resources {
				var resData store.ResourcesData
				err = protocol.Decode(res, &resData)
				if err != nil {
					return nil, err
				}
				normalizedAccountBalances[i].accountHashes[curHashIdx], err = resourcesHashBuilderV6(&resData, balance.Address, basics.CreatableIndex(cidx), resData.UpdateRound, res)
				if err != nil {
					return nil, err
				}
				normalizedAccountBalances[i].resources[basics.CreatableIndex(cidx)] = resData
				normalizedAccountBalances[i].encodedResources[basics.CreatableIndex(cidx)] = res
				curHashIdx++
			}
		}
	}
	return
}

// makeCompactResourceDeltas takes an array of AccountDeltas ( one array entry per round ), and compacts the resource portions of the arrays into a single
// data structure that contains all the resources deltas changes. While doing that, the function eliminate any intermediate resources changes.
// It counts the number of changes each account get modified across the round range by specifying it in the nAcctDeltas field of the resourcesDeltas.
// As an optimization, accountDeltas is passed as a slice and must not be modified.
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

// makeCompactAccountDeltas takes an array of account AccountDeltas ( one array entry per round ), and compacts the arrays into a single
// data structure that contains all the account deltas changes. While doing that, the function eliminate any intermediate account changes.
// It counts the number of changes each account get modified across the round range by specifying it in the nAcctDeltas field of the accountDeltaCount/modifiedCreatable.
// As an optimization, accountDeltas is passed as a slice and must not be modified.
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

// writeCatchpointStagingBalances inserts all the account balances in the provided array into the catchpoint balance staging table catchpointbalances.
func writeCatchpointStagingBalances(ctx context.Context, tx *sql.Tx, bals []normalizedAccountBalance) error {
	selectAcctStmt, err := tx.PrepareContext(ctx, "SELECT rowid FROM catchpointbalances WHERE address = ?")
	if err != nil {
		return err
	}

	insertAcctStmt, err := tx.PrepareContext(ctx, "INSERT INTO catchpointbalances(address, normalizedonlinebalance, data) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}

	insertRscStmt, err := tx.PrepareContext(ctx, "INSERT INTO catchpointresources(addrid, aidx, data) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}

	var result sql.Result
	var rowID int64
	for _, balance := range bals {
		result, err = insertAcctStmt.ExecContext(ctx, balance.address[:], balance.normalizedBalance, balance.encodedAccountData)
		if err == nil {
			var aff int64
			aff, err = result.RowsAffected()
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
		} else {
			var sqliteErr sqlite3.Error
			if errors.As(err, &sqliteErr) && sqliteErr.Code == sqlite3.ErrConstraint && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
				// address exists: overflowed account record: find addrid
				err = selectAcctStmt.QueryRowContext(ctx, balance.address[:]).Scan(&rowID)
				if err != nil {
					return err
				}
			} else {
				return err
			}
		}

		// write resources
		for aidx := range balance.resources {
			var result sql.Result
			result, err = insertRscStmt.ExecContext(ctx, rowID, aidx, balance.encodedResources[aidx])
			if err != nil {
				return err
			}
			var aff int64
			aff, err = result.RowsAffected()
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
					_, err := insertCreatorsStmt.ExecContext(ctx, aidx, balance.address[:], basics.AssetCreatable)
					if err != nil {
						return err
					}
				}
				// determine if it's an application
				if resData.IsApp() {
					_, err := insertCreatorsStmt.ExecContext(ctx, aidx, balance.address[:], basics.AppCreatable)
					if err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// writeCatchpointStagingKVs inserts all the KVs in the provided array into the
// catchpoint kvstore staging table catchpointkvstore, and their hashes to the pending
func writeCatchpointStagingKVs(ctx context.Context, tx *sql.Tx, kvrs []encodedKVRecordV6) error {
	insertKV, err := tx.PrepareContext(ctx, "INSERT INTO catchpointkvstore(key, value) VALUES(?, ?)")
	if err != nil {
		return err
	}
	defer insertKV.Close()

	insertHash, err := tx.PrepareContext(ctx, "INSERT INTO catchpointpendinghashes(data) VALUES(?)")
	if err != nil {
		return err
	}
	defer insertHash.Close()

	for _, kvr := range kvrs {
		_, err := insertKV.ExecContext(ctx, kvr.Key, kvr.Value)
		if err != nil {
			return err
		}

		hash := kvHashBuilderV6(string(kvr.Key), kvr.Value)
		_, err = insertHash.ExecContext(ctx, hash)
		if err != nil {
			return err
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
		"DROP TABLE IF EXISTS catchpointkvstore",
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
			"CREATE TABLE IF NOT EXISTS catchpointkvstore (key blob primary key, value blob)",

			createNormalizedOnlineBalanceIndex(idxnameBalances, "catchpointbalances"), // should this be removed ?
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
		"DROP TABLE IF EXISTS accountbase",
		"DROP TABLE IF EXISTS assetcreators",
		"DROP TABLE IF EXISTS accounthashes",
		"DROP TABLE IF EXISTS resources",
		"DROP TABLE IF EXISTS kvstore",

		"ALTER TABLE catchpointbalances RENAME TO accountbase",
		"ALTER TABLE catchpointassetcreators RENAME TO assetcreators",
		"ALTER TABLE catchpointaccounthashes RENAME TO accounthashes",
		"ALTER TABLE catchpointresources RENAME TO resources",
		"ALTER TABLE catchpointkvstore RENAME TO kvstore",
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

		arw := store.NewAccountsSQLReaderWriter(tx)
		err = arw.AccountsPutTotals(totals, false)
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

func accountsCreateOnlineAccountsTable(ctx context.Context, tx *sql.Tx) error {
	var exists bool
	err := tx.QueryRowContext(ctx, "SELECT 1 FROM pragma_table_info('onlineaccounts') WHERE name='address'").Scan(&exists)
	if err == nil {
		// Already exists.
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	for _, stmt := range createOnlineAccountsTable {
		_, err = tx.ExecContext(ctx, stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

// accountsCreateBoxTable creates the KVStore table for box-storage in the database.
func accountsCreateBoxTable(ctx context.Context, tx *sql.Tx) error {
	var exists bool
	err := tx.QueryRow("SELECT 1 FROM pragma_table_info('kvstore') WHERE name='key'").Scan(&exists)
	if err == nil {
		// already exists
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	for _, stmt := range createBoxTable {
		_, err = tx.ExecContext(ctx, stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

func accountsCreateTxTailTable(ctx context.Context, tx *sql.Tx) (err error) {
	for _, stmt := range createTxTailTable {
		_, err = tx.ExecContext(ctx, stmt)
		if err != nil {
			return
		}
	}
	return nil
}

func accountsCreateOnlineRoundParamsTable(ctx context.Context, tx *sql.Tx) (err error) {
	for _, stmt := range createOnlineRoundParamsTable {
		_, err = tx.ExecContext(ctx, stmt)
		if err != nil {
			return
		}
	}
	return nil
}

func accountsCreateCatchpointFirstStageInfoTable(ctx context.Context, e db.Executable) error {
	_, err := e.ExecContext(ctx, createCatchpointFirstStageInfoTable)
	return err
}

func accountsCreateUnfinishedCatchpointsTable(ctx context.Context, e db.Executable) error {
	_, err := e.ExecContext(ctx, createUnfinishedCatchpointsTable)
	return err
}

func accountDataResources(
	ctx context.Context,
	accountData *basics.AccountData, rowid int64,
	outputResourceCb func(ctx context.Context, rowid int64, cidx basics.CreatableIndex, rd *store.ResourcesData) error,
) error {
	// handle all the assets we can find:
	for aidx, holding := range accountData.Assets {
		var rd store.ResourcesData
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
		var rd store.ResourcesData
		rd.SetAssetParams(aparams, false)
		err := outputResourceCb(ctx, rowid, basics.CreatableIndex(aidx), &rd)
		if err != nil {
			return err
		}
	}

	// handle all the applications we can find:
	for aidx, localState := range accountData.AppLocalStates {
		var rd store.ResourcesData
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
		var rd store.ResourcesData
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

	arw := store.NewAccountsSQLReaderWriter(tx)
	totalBaseAccounts, err = arw.TotalAccounts(ctx)
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
		var newAccountData store.BaseAccountData
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
		insertResourceCallback := func(ctx context.Context, rowID int64, cidx basics.CreatableIndex, rd *store.ResourcesData) error {
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

func performTxTailTableMigration(ctx context.Context, tx *sql.Tx, blockDb db.Accessor) (err error) {
	if tx == nil {
		return nil
	}

	arw := store.NewAccountsSQLReaderWriter(tx)
	dbRound, err := arw.AccountsRound()
	if err != nil {
		return fmt.Errorf("latest block number cannot be retrieved : %w", err)
	}

	// load the latest MaxTxnLife rounds in the txtail and store these in the txtail.
	// when migrating there is only MaxTxnLife blocks in the block DB
	// since the original txTail.commmittedUpTo preserved only (rnd+1)-MaxTxnLife = 1000 blocks back
	err = blockDb.Atomic(func(ctx context.Context, blockTx *sql.Tx) error {
		latestBlockRound, err := blockLatest(blockTx)
		if err != nil {
			return fmt.Errorf("latest block number cannot be retrieved : %w", err)
		}
		latestHdr, err := blockGetHdr(blockTx, dbRound)
		if err != nil {
			return fmt.Errorf("latest block header %d cannot be retrieved : %w", dbRound, err)
		}

		proto := config.Consensus[latestHdr.CurrentProtocol]
		maxTxnLife := basics.Round(proto.MaxTxnLife)
		deeperBlockHistory := basics.Round(proto.DeeperBlockHeaderHistory)
		// firstRound is either maxTxnLife + deeperBlockHistory back from the latest for regular init
		// or maxTxnLife + deeperBlockHistory + CatchpointLookback back for catchpoint apply.
		// Try to check the earliest available and start from there.
		firstRound := (latestBlockRound + 1).SubSaturate(maxTxnLife + deeperBlockHistory + basics.Round(proto.CatchpointLookback))
		// we don't need to have the txtail for round 0.
		if firstRound == basics.Round(0) {
			firstRound++
		}
		if _, err := blockGet(blockTx, firstRound); err != nil {
			// looks like not catchpoint but a regular migration, start from maxTxnLife + deeperBlockHistory back
			firstRound = (latestBlockRound + 1).SubSaturate(maxTxnLife + deeperBlockHistory)
			if firstRound == basics.Round(0) {
				firstRound++
			}
		}
		tailRounds := make([][]byte, 0, maxTxnLife)
		for rnd := firstRound; rnd <= dbRound; rnd++ {
			blk, err := blockGet(blockTx, rnd)
			if err != nil {
				return fmt.Errorf("block for round %d ( %d - %d ) cannot be retrieved : %w", rnd, firstRound, dbRound, err)
			}

			tail, err := store.TxTailRoundFromBlock(blk)
			if err != nil {
				return err
			}

			encodedTail, _ := tail.Encode()
			tailRounds = append(tailRounds, encodedTail)
		}

		return arw.TxtailNewRound(ctx, firstRound, tailRounds, firstRound)
	})

	return err
}

func performOnlineRoundParamsTailMigration(ctx context.Context, tx *sql.Tx, blockDb db.Accessor, newDatabase bool, initProto protocol.ConsensusVersion) (err error) {
	arw := store.NewAccountsSQLReaderWriter(tx)
	totals, err := arw.AccountsTotals(ctx, false)
	if err != nil {
		return err
	}
	rnd, err := arw.AccountsRound()
	if err != nil {
		return err
	}
	var currentProto protocol.ConsensusVersion
	if newDatabase {
		currentProto = initProto
	} else {
		err = blockDb.Atomic(func(ctx context.Context, blockTx *sql.Tx) error {
			hdr, err := blockGetHdr(blockTx, rnd)
			if err != nil {
				return err
			}
			currentProto = hdr.CurrentProtocol
			return nil
		})
		if err != nil {
			return err
		}
	}
	onlineRoundParams := []ledgercore.OnlineRoundParamsData{
		{
			OnlineSupply:    totals.Online.Money.Raw,
			RewardsLevel:    totals.RewardsLevel,
			CurrentProtocol: currentProto,
		},
	}
	return accountsPutOnlineRoundParams(tx, onlineRoundParams, rnd)
}

func performOnlineAccountsTableMigration(ctx context.Context, tx *sql.Tx, progress func(processed, total uint64), log logging.Logger) (err error) {

	var insertOnlineAcct *sql.Stmt
	insertOnlineAcct, err = tx.PrepareContext(ctx, "INSERT INTO onlineaccounts(address, data, normalizedonlinebalance, updround, votelastvalid) VALUES(?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer insertOnlineAcct.Close()

	var updateAcct *sql.Stmt
	updateAcct, err = tx.PrepareContext(ctx, "UPDATE accountbase SET data = ? WHERE addrid = ?")
	if err != nil {
		return err
	}
	defer updateAcct.Close()

	var rows *sql.Rows
	rows, err = tx.QueryContext(ctx, "SELECT addrid, address, data, normalizedonlinebalance FROM accountbase")
	if err != nil {
		return err
	}
	defer rows.Close()

	var insertRes sql.Result
	var updateRes sql.Result
	var rowsAffected int64
	var processedAccounts uint64
	var totalOnlineBaseAccounts uint64

	arw := store.NewAccountsSQLReaderWriter(tx)
	totalOnlineBaseAccounts, err = arw.TotalAccounts(ctx)
	var total uint64
	err = tx.QueryRowContext(ctx, "SELECT count(1) FROM accountbase").Scan(&total)
	if err != nil {
		if err != sql.ErrNoRows {
			return err
		}
		total = 0
		err = nil
	}

	checkSQLResult := func(e error, res sql.Result) (err error) {
		if e != nil {
			err = e
			return
		}
		rowsAffected, err = res.RowsAffected()
		if err != nil {
			return err
		}
		if rowsAffected != 1 {
			return fmt.Errorf("number of affected rows is not 1 - %d", rowsAffected)
		}
		return nil
	}

	type acctState struct {
		old    store.BaseAccountData
		oldEnc []byte
		new    store.BaseAccountData
		newEnc []byte
	}
	acctRehash := make(map[basics.Address]acctState)
	var addr basics.Address

	for rows.Next() {
		var addrid sql.NullInt64
		var addrbuf []byte
		var encodedAcctData []byte
		var normBal sql.NullInt64
		err = rows.Scan(&addrid, &addrbuf, &encodedAcctData, &normBal)
		if err != nil {
			return err
		}
		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return err
		}
		var ba store.BaseAccountData
		err = protocol.Decode(encodedAcctData, &ba)
		if err != nil {
			return err
		}

		// insert entries into online accounts table
		if ba.Status == basics.Online {
			if ba.MicroAlgos.Raw > 0 && !normBal.Valid {
				copy(addr[:], addrbuf)
				return fmt.Errorf("non valid norm balance for online account %s", addr.String())
			}
			var baseOnlineAD store.BaseOnlineAccountData
			baseOnlineAD.BaseVotingData = ba.BaseVotingData
			baseOnlineAD.MicroAlgos = ba.MicroAlgos
			baseOnlineAD.RewardsBase = ba.RewardsBase
			encodedOnlineAcctData := protocol.Encode(&baseOnlineAD)
			insertRes, err = insertOnlineAcct.ExecContext(ctx, addrbuf, encodedOnlineAcctData, normBal.Int64, ba.UpdateRound, baseOnlineAD.VoteLastValid)
			err = checkSQLResult(err, insertRes)
			if err != nil {
				return err
			}
		}

		// remove stateproofID field for offline accounts
		if ba.Status != basics.Online && !ba.StateProofID.IsEmpty() {
			// store old data for account hash update
			state := acctState{old: ba, oldEnc: encodedAcctData}
			ba.StateProofID = merklesignature.Commitment{}
			encodedOnlineAcctData := protocol.Encode(&ba)
			copy(addr[:], addrbuf)
			state.new = ba
			state.newEnc = encodedOnlineAcctData
			acctRehash[addr] = state
			updateRes, err = updateAcct.ExecContext(ctx, encodedOnlineAcctData, addrid.Int64)
			err = checkSQLResult(err, updateRes)
			if err != nil {
				return err
			}
		}

		processedAccounts++
		if progress != nil {
			progress(processedAccounts, totalOnlineBaseAccounts)
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}

	// update accounthashes for the modified accounts
	if len(acctRehash) > 0 {
		var count uint64
		err := tx.QueryRow("SELECT count(1) FROM accounthashes").Scan(&count)
		if err != nil {
			return err
		}
		if count == 0 {
			// no account hashes, done
			return nil
		}

		mc, err := MakeMerkleCommitter(tx, false)
		if err != nil {
			return nil
		}

		trie, err := merkletrie.MakeTrie(mc, TrieMemoryConfig)
		if err != nil {
			return fmt.Errorf("accountsInitialize was unable to MakeTrie: %v", err)
		}
		for addr, state := range acctRehash {
			deleteHash := accountHashBuilderV6(addr, &state.old, state.oldEnc)
			deleted, err := trie.Delete(deleteHash)
			if err != nil {
				return fmt.Errorf("performOnlineAccountsTableMigration failed to delete hash '%s' from merkle trie for account %v: %w", hex.EncodeToString(deleteHash), addr, err)
			}
			if !deleted && log != nil {
				log.Warnf("performOnlineAccountsTableMigration failed to delete hash '%s' from merkle trie for account %v", hex.EncodeToString(deleteHash), addr)
			}

			addHash := accountHashBuilderV6(addr, &state.new, state.newEnc)
			added, err := trie.Add(addHash)
			if err != nil {
				return fmt.Errorf("performOnlineAccountsTableMigration attempted to add duplicate hash '%s' to merkle trie for account %v: %w", hex.EncodeToString(addHash), addr, err)
			}
			if !added && log != nil {
				log.Warnf("performOnlineAccountsTableMigration attempted to add duplicate hash '%s' to merkle trie for account %v", hex.EncodeToString(addHash), addr)
			}
		}
		_, err = trie.Commit()
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

func resetAccountHashes(ctx context.Context, tx *sql.Tx) (err error) {
	_, err = tx.ExecContext(ctx, `DELETE FROM accounthashes`)
	return
}

func accountsReset(ctx context.Context, tx *sql.Tx) error {
	for _, stmt := range accountsResetExprs {
		_, err := tx.ExecContext(ctx, stmt)
		if err != nil {
			return err
		}
	}
	_, err := db.SetUserVersion(ctx, tx, 0)
	return err
}

func accountsOnlineRoundParams(tx *sql.Tx) (onlineRoundParamsData []ledgercore.OnlineRoundParamsData, endRound basics.Round, err error) {
	rows, err := tx.Query("SELECT rnd, data FROM onlineroundparamstail ORDER BY rnd ASC")
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var buf []byte
		err = rows.Scan(&endRound, &buf)
		if err != nil {
			return nil, 0, err
		}

		var data ledgercore.OnlineRoundParamsData
		err = protocol.Decode(buf, &data)
		if err != nil {
			return nil, 0, err
		}

		onlineRoundParamsData = append(onlineRoundParamsData, data)
	}
	return
}

func accountsPutOnlineRoundParams(tx *sql.Tx, onlineRoundParamsData []ledgercore.OnlineRoundParamsData, startRound basics.Round) error {
	insertStmt, err := tx.Prepare("INSERT INTO onlineroundparamstail (rnd, data) VALUES (?, ?)")
	if err != nil {
		return err
	}

	for i, onlineRoundParams := range onlineRoundParamsData {
		_, err = insertStmt.Exec(startRound+basics.Round(i), protocol.Encode(&onlineRoundParams))
		if err != nil {
			return err
		}
	}
	return nil
}

func accountsPruneOnlineRoundParams(tx *sql.Tx, deleteBeforeRound basics.Round) error {
	_, err := tx.Exec("DELETE FROM onlineroundparamstail WHERE rnd<?",
		deleteBeforeRound,
	)
	return err
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
//
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

// loadFullAccount converts baseAccountData into basics.AccountData and loads all resources as needed
func loadFullAccount(ctx context.Context, tx *sql.Tx, resourcesTable string, addr basics.Address, addrid int64, data store.BaseAccountData) (ad basics.AccountData, err error) {
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
		var resData store.ResourcesData
		err = protocol.Decode(buf, &resData)
		if err != nil {
			return
		}
		if resData.ResourceFlags == store.ResourceFlagsNotHolding {
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

		var data store.BaseAccountData
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
		baseCb := func(addr basics.Address, rowid int64, accountData *store.BaseAccountData, encodedAccountData []byte) (err error) {
			hash := accountHashBuilderV6(addr, accountData, encodedAccountData)
			_, err = iterator.insertStmt.ExecContext(ctx, rowid, hash)
			if err != nil {
				return
			}
			lastAddrID = rowid
			return nil
		}

		resCb := func(addr basics.Address, cidx basics.CreatableIndex, resData *store.ResourcesData, encodedResourceData []byte, lastResource bool) error {
			if resData != nil {
				hash, err := resourcesHashBuilderV6(resData, addr, cidx, resData.UpdateRound, encodedResourceData)
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

func selectOldCatchpointFirstStageInfoRounds(ctx context.Context, q db.Queryable, maxRound basics.Round) ([]basics.Round, error) {
	var res []basics.Round

	f := func() error {
		query := "SELECT round FROM catchpointfirststageinfo WHERE round <= ?"
		rows, err := q.QueryContext(ctx, query, maxRound)
		if err != nil {
			return err
		}

		// Clear `res` in case this function is repeated.
		res = res[:0]
		for rows.Next() {
			var r basics.Round
			err = rows.Scan(&r)
			if err != nil {
				return err
			}
			res = append(res, r)
		}

		return nil
	}
	err := db.Retry(f)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func deleteOldCatchpointFirstStageInfo(ctx context.Context, e db.Executable, maxRoundToDelete basics.Round) error {
	f := func() error {
		query := "DELETE FROM catchpointfirststageinfo WHERE round <= ?"
		_, err := e.ExecContext(ctx, query, maxRoundToDelete)
		return err
	}
	return db.Retry(f)
}
