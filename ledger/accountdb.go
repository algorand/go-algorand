// Copyright (C) 2019-2021 Algorand, Inc.
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
	"time"

	"github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// accountsDbQueries is used to cache a prepared SQL statement to look up
// the state of a single account.
type accountsDbQueries struct {
	// initialized in accountsDBInit
	listCreatablesStmt          *sql.Stmt
	lookupStmt                  *sql.Stmt
	lookupCreatorStmt           *sql.Stmt
	deleteStoredCatchpoint      *sql.Stmt
	insertStoredCatchpoint      *sql.Stmt
	selectOldestCatchpointFiles *sql.Stmt
	selectCatchpointStateUint64 *sql.Stmt
	deleteCatchpointState       *sql.Stmt
	insertCatchpointStateUint64 *sql.Stmt
	selectCatchpointStateString *sql.Stmt
	insertCatchpointStateString *sql.Stmt

	loadAccountGroupDataStmt *sql.Stmt
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

var createOnlineAccountIndex = []string{
	`ALTER TABLE accountbase
		ADD COLUMN normalizedonlinebalance INTEGER`,
	createNormalizedOnlineBalanceIndex("onlineaccountbals", "accountbase"),
}

var accountsResetExprs = []string{
	`DROP TABLE IF EXISTS acctrounds`,
	`DROP TABLE IF EXISTS accounttotals`,
	`DROP TABLE IF EXISTS accountext`,
	`DROP TABLE IF EXISTS accountbase`,
	`DROP TABLE IF EXISTS assetcreators`,
	`DROP TABLE IF EXISTS storedcatchpoints`,
	`DROP TABLE IF EXISTS catchpointstate`,
	`DROP TABLE IF EXISTS accounthashes`,
}

// accountDBVersion is the database version that this binary would know how to support and how to upgrade to.
// details about the content of each of the versions can be found in the upgrade functions upgradeDatabaseSchemaXXXX
// and their descriptions.
var accountDBVersion = int32(6)

// dbAccountData is used for representing a single account stored on the disk. In addition to the
// basics.AccountData, it also stores complete referencing information used to maintain the base accounts
// list.
type dbAccountData struct {
	// The address of the account. In contrasts to maps, having this value explicitly here allows us to use this
	// data structure in queues directly, without "attaching" the address as the address as the map key.
	addr basics.Address
	// The underlaying account data
	pad ledgercore.PersistedAccountData
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

// compactAccountDeltas and accountDelta is an extention to ledgercore.AccountDeltas that is being used by the commitRound function for counting the
// number of changes we've made per account. The ndeltas is used exclusively for consistency checking - making sure that
// all the pending changes were written and that there are no outstanding writes missing.
type compactAccountDeltas struct {
	// actual data
	deltas []accountDelta
	// addresses for deltas
	addresses []basics.Address
	// cache for addr to deltas index resolution
	cache map[basics.Address]int
	// misses holds indices of addresses for which old portion of delta needs to be loaded from disk
	misses []int
}

type accountDelta struct {
	old     dbAccountData
	new     ledgercore.PersistedAccountData
	assets  map[basics.AssetIndex]ledgercore.AssetAction
	ndeltas int
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
)

// normalizedAccountBalance is a staging area for a catchpoint file account information before it's being added to the catchpoint staging tables.
type normalizedAccountBalance struct {
	address            basics.Address
	accountData        basics.AccountData
	encodedAccountData []byte
	accountHash        []byte
	normalizedBalance  uint64
}

// prepareNormalizedBalances converts an array of encodedBalanceRecord into an equal size array of normalizedAccountBalances.
func prepareNormalizedBalances(bals []encodedBalanceRecord, proto config.ConsensusParams) (normalizedAccountBalances []normalizedAccountBalance, err error) {
	normalizedAccountBalances = make([]normalizedAccountBalance, len(bals), len(bals))
	for i, balance := range bals {
		normalizedAccountBalances[i].address = balance.Address
		err = protocol.Decode(balance.AccountData, &(normalizedAccountBalances[i].accountData))
		if err != nil {
			return nil, err
		}
		normalizedAccountBalances[i].normalizedBalance = normalizedAccountBalances[i].accountData.NormalizedOnlineBalance(proto)
		normalizedAccountBalances[i].encodedAccountData = balance.AccountData
		normalizedAccountBalances[i].accountHash = accountHashBuilder(balance.Address, normalizedAccountBalances[i].accountData.RewardsBase, balance.AccountData)
	}
	return
}

// makeCompactAccountDeltas takes an array of account AccountDeltas ( one array entry per round ), and compacts the arrays into a single
// data structure that contains all the account deltas changes. While doing that, the function eliminate any intermediate account changes.
// It counts the number of changes per round by specifying it in the ndeltas field of the accountDeltaCount/modifiedCreatable.
func makeCompactAccountDeltas(accountDeltas []ledgercore.AccountDeltas, baseAccounts lruAccounts) (outAccountDeltas compactAccountDeltas) {
	if len(accountDeltas) == 0 {
		return
	}

	// the sizes of the maps here aren't super accurate, but would hopefully be a rough estimate for a reasonable starting point.
	size := accountDeltas[0].Len()*len(accountDeltas) + 1
	outAccountDeltas.cache = make(map[basics.Address]int, size)
	outAccountDeltas.deltas = make([]accountDelta, 0, size)
	outAccountDeltas.misses = make([]int, 0, size)

	for _, roundDelta := range accountDeltas {
		for i := 0; i < roundDelta.Len(); i++ {
			addr, acctDelta := roundDelta.GetByIdx(i)
			hmap := roundDelta.GetAssetDeltas(addr)
			if prev, idx := outAccountDeltas.get(addr); idx != -1 {
				outAccountDeltas.update(idx, accountDelta{ // update instead of upsert economizes one map lookup
					old:     prev.old,
					new:     acctDelta,
					assets:  hmap,
					ndeltas: prev.ndeltas + 1,
				})
			} else {
				// it's a new entry.
				newEntry := accountDelta{
					new:     acctDelta,
					assets:  hmap,
					ndeltas: 1,
				}
				if baseAccountData, has := baseAccounts.read(addr); has {
					newEntry.old = baseAccountData
					outAccountDeltas.insert(addr, newEntry)
				} else {
					// missing old entries will be populated in accountsLoadOld
					outAccountDeltas.insertMissing(addr, newEntry)
				}
			}
		}
	}
	return
}

func loadCreatedDeletedGroups(agl ledgercore.AbstractAssetGroupList, delta accountDelta, create ledgercore.AssetAction, delete ledgercore.AssetAction, fetcher fetcher, adRound basics.Round) (err error) {
	for aidx, action := range delta.assets {
		gi := -1
		if action == create {
			// use FindGroup to find a possible matching group for insertion
			gi = agl.FindGroup(aidx, 0)
		} else if action == delete {
			gi, _ = agl.FindAsset(aidx, 0)
		}
		if gi != -1 {
			g := agl.Get(gi)
			if !g.Loaded() {
				var gdRound basics.Round
				gdRound, err = g.Fetch(fetcher, nil)
				if err != nil {
					return
				}
				if gdRound != adRound {
					return &MismatchingDatabaseRoundError{databaseRound: gdRound, memoryRound: adRound}
				}
			}
		}
	}
	return
}

func loadOldHoldings(dbad dbAccountData, delta accountDelta, fetcher fetcher, adRound basics.Round) (dbAccountData, error) {
	if len(delta.new.Assets) > 0 && len(dbad.pad.AccountData.Assets) == 0 {
		dbad.pad.AccountData.Assets = make(map[basics.AssetIndex]basics.AssetHolding, len(delta.new.Assets))
	}

	// load created and deleted asset holding groups
	err := loadCreatedDeletedGroups(&dbad.pad.ExtendedAssetHolding, delta, ledgercore.ActionHoldingCreate, ledgercore.ActionHoldingDelete, fetcher, adRound)
	if err != nil {
		return dbAccountData{}, err
	}

	// load updated assets
	for aidx := range delta.new.Assets {
		gi, ai := dbad.pad.ExtendedAssetHolding.FindAsset(aidx, 0)
		if gi != -1 {
			g := &dbad.pad.ExtendedAssetHolding.Groups[gi]
			if !g.Loaded() {
				gdRound, err := g.Fetch(fetcher, nil)
				if err != nil {
					return dbAccountData{}, err
				}
				if gdRound != adRound {
					// this should not never happen since accountsLoadOld is called as part of DB update procedure,
					// so the DB cannot be changed
					return dbAccountData{}, &MismatchingDatabaseRoundError{databaseRound: gdRound, memoryRound: adRound}
				}
			}
			_, ai = dbad.pad.ExtendedAssetHolding.FindAsset(aidx, gi)
			if ai != -1 {
				// found!
				dbad.pad.AccountData.Assets[aidx] = g.GetHolding(ai)
			} else {
				// no such asset => newly created
			}
		}
	}
	return dbad, nil
}

func loadOldParams(dbad dbAccountData, delta accountDelta, fetcher fetcher, adRound basics.Round) (dbAccountData, error) {
	if len(delta.new.AssetParams) > 0 && len(dbad.pad.AccountData.AssetParams) == 0 {
		dbad.pad.AccountData.AssetParams = make(map[basics.AssetIndex]basics.AssetParams, len(delta.new.AssetParams))
	}

	err := loadCreatedDeletedGroups(&dbad.pad.ExtendedAssetParams, delta, ledgercore.ActionParamsCreate, ledgercore.ActionParamsDelete, fetcher, adRound)
	if err != nil {
		return dbAccountData{}, err
	}

	// load updated assets
	for aidx := range delta.new.AssetParams {
		gi, ai := dbad.pad.ExtendedAssetParams.FindAsset(aidx, 0)
		if gi != -1 {
			g := &dbad.pad.ExtendedAssetParams.Groups[gi]
			if !g.Loaded() {
				gdRound, err := g.Fetch(fetcher, nil)
				if err != nil {
					return dbAccountData{}, err
				}
				if gdRound != adRound {
					// this should not never happen since accountsLoadOld is called as part of DB update procedure,
					// so the DB cannot be changed
					return dbAccountData{}, &MismatchingDatabaseRoundError{databaseRound: gdRound, memoryRound: adRound}
				}
			}
			_, ai = dbad.pad.ExtendedAssetParams.FindAsset(aidx, gi)
			if ai != -1 {
				// found!
				dbad.pad.AccountData.AssetParams[aidx] = g.GetParams(ai)
			} else {
				// no such asset => newly created
			}
		}
	}
	return dbad, nil
}

// accountsLoadOld updates the entries on the deltas.old map that matches the provided addresses.
// The round number of the dbAccountData is not updated by this function, and the caller is responsible
// for populating this field.
func (a *compactAccountDeltas) accountsLoadOld(tx *sql.Tx) (err error) {
	if len(a.misses) == 0 {
		return nil
	}
	selectStmt, err := tx.Prepare(lookupAcctBaseQuery)
	if err != nil {
		return
	}
	defer selectStmt.Close()

	loadStmt, err := tx.Prepare(loadAcctExtQuery)
	if err != nil {
		return
	}
	defer loadStmt.Close()

	defer func() {
		a.misses = nil
	}()

	fetcher := makeAssetFetcher(loadStmt)

	var rowid sql.NullInt64
	var acctDataBuf []byte
	for _, idx := range a.misses {
		addr := a.addresses[idx]
		dbad := dbAccountData{addr: addr}
		adRound := basics.Round(0)
		err = selectStmt.QueryRow(addr[:]).Scan(&rowid, &adRound, &acctDataBuf)
		switch err {
		case nil:
			dbad.rowid = rowid.Int64
			if len(acctDataBuf) > 0 {
				err = protocol.Decode(acctDataBuf, &dbad.pad)
				if err != nil {
					return err
				}

				// accountsLoadOld is called from commitRound as db.Atomic => safe to load extension data without additional sync

				// fetch holdings/params that are in new to simplify upcoming reconciliation.
				// these are either new or modified, and needed to be written back later.

				if dbad.pad.ExtendedAssetHolding.Count > 0 {
					_, delta := a.getByIdx(idx)
					dbad, err = loadOldHoldings(dbad, delta, fetcher, adRound)
					if err != nil {
						return err
					}
				}
				if dbad.pad.ExtendedAssetParams.Count > 0 {
					_, delta := a.getByIdx(idx)
					dbad, err = loadOldParams(dbad, delta, fetcher, adRound)
					if err != nil {
						return err
					}
				}
			} else {
				// to retain backward compatability, we will treat this condition as if we don't have the account.
			}
			a.updateOld(idx, dbad)
		case sql.ErrNoRows:
			// we don't have that account, just return an empty record.
			a.updateOld(idx, dbad)
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

func (a *compactAccountDeltas) getByIdx(i int) (basics.Address, accountDelta) {
	return a.addresses[i], a.deltas[i]
}

// upsert updates existing or inserts a new entry
func (a *compactAccountDeltas) upsert(addr basics.Address, delta accountDelta) {
	if idx, exist := a.cache[addr]; exist { // nil map lookup is OK
		a.deltas[idx] = delta
		return
	}
	a.insert(addr, delta)
}

// update replaces specific entry by idx
func (a *compactAccountDeltas) update(idx int, delta accountDelta) {
	a.deltas[idx] = delta
}

func (a *compactAccountDeltas) insert(addr basics.Address, delta accountDelta) int {
	last := len(a.deltas)
	a.deltas = append(a.deltas, delta)
	a.addresses = append(a.addresses, addr)

	if a.cache == nil {
		a.cache = make(map[basics.Address]int)
	}
	a.cache[addr] = last
	return last
}

func (a *compactAccountDeltas) insertMissing(addr basics.Address, delta accountDelta) {
	idx := a.insert(addr, delta)
	a.misses = append(a.misses, idx)
}

// upsertOld updates existing or inserts a new partial entry with only old field filled
func (a *compactAccountDeltas) upsertOld(old dbAccountData) {
	addr := old.addr
	if idx, exist := a.cache[addr]; exist {
		a.deltas[idx].old = old
		return
	}
	a.insert(addr, accountDelta{old: old})
}

// updateOld updates existing or inserts a new partial entry with only old field filled
func (a *compactAccountDeltas) updateOld(idx int, old dbAccountData) {
	a.deltas[idx].old = old
}

// writeCatchpointStagingBalances inserts all the account balances in the provided array into the catchpoint balance staging table catchpointbalances.
func writeCatchpointStagingBalances(ctx context.Context, tx *sql.Tx, bals []normalizedAccountBalance) error {
	insertAcctStmt, err := tx.PrepareContext(ctx, "INSERT INTO catchpointbalances(address, normalizedonlinebalance, data) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}

	for _, balance := range bals {
		result, err := insertAcctStmt.ExecContext(ctx, balance.address[:], balance.normalizedBalance, balance.encodedAccountData)
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
	return nil
}

// writeCatchpointStagingHashes inserts all the account hashes in the provided array into the catchpoint pending hashes table catchpointpendinghashes.
func writeCatchpointStagingHashes(ctx context.Context, tx *sql.Tx, bals []normalizedAccountBalance) error {
	insertStmt, err := tx.PrepareContext(ctx, "INSERT INTO catchpointpendinghashes(data) VALUES(?)")
	if err != nil {
		return err
	}

	for _, balance := range bals {
		result, err := insertStmt.ExecContext(ctx, balance.accountHash[:])
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
func writeCatchpointStagingCreatable(ctx context.Context, tx *sql.Tx, bals []normalizedAccountBalance) error {
	insertStmt, err := tx.PrepareContext(ctx, "INSERT INTO catchpointassetcreators(asset, creator, ctype) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}

	for _, balance := range bals {
		// if the account has any asset params, it means that it's the creator of an asset.
		if len(balance.accountData.AssetParams) > 0 {
			for aidx := range balance.accountData.AssetParams {
				_, err := insertStmt.ExecContext(ctx, basics.CreatableIndex(aidx), balance.address[:], basics.AssetCreatable)
				if err != nil {
					return err
				}
			}
		}

		if len(balance.accountData.AppParams) > 0 {
			for aidx := range balance.accountData.AppParams {
				_, err := insertStmt.ExecContext(ctx, basics.CreatableIndex(aidx), balance.address[:], basics.AppCreatable)
				if err != nil {
					return err
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
		"DELETE FROM accounttotals where id='catchpointStaging'",
	}

	if newCatchup {
		// SQLite has no way to rename an existing index.  So, we need
		// to cook up a fresh name for the index, which will be kept
		// around after we rename the table from "catchpointbalances"
		// to "accountbase".  To construct a unique index name, we
		// use the current time.
		// Apply the same logic to
		idxnameBalances := fmt.Sprintf("onlineaccountbals_idx_%d", time.Now().UnixNano())

		s = append(s,
			"CREATE TABLE IF NOT EXISTS catchpointassetcreators (asset integer primary key, creator blob, ctype integer)",
			"CREATE TABLE IF NOT EXISTS catchpointbalances (address blob primary key, data blob, normalizedonlinebalance integer)",
			"CREATE TABLE IF NOT EXISTS catchpointpendinghashes (data blob)",
			"CREATE TABLE IF NOT EXISTS catchpointaccounthashes (id integer primary key, data blob)",
			createNormalizedOnlineBalanceIndex(idxnameBalances, "catchpointbalances"),
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
func applyCatchpointStagingBalances(ctx context.Context, tx *sql.Tx, balancesRound basics.Round) (err error) {
	stmts := []string{
		"ALTER TABLE accountbase RENAME TO accountbase_old",
		"ALTER TABLE assetcreators RENAME TO assetcreators_old",
		"ALTER TABLE accounthashes RENAME TO accounthashes_old",

		"ALTER TABLE catchpointbalances RENAME TO accountbase",
		"ALTER TABLE catchpointassetcreators RENAME TO assetcreators",
		"ALTER TABLE catchpointaccounthashes RENAME TO accounthashes",

		"DROP TABLE IF EXISTS accountbase_old",
		"DROP TABLE IF EXISTS assetcreators_old",
		"DROP TABLE IF EXISTS accounthashes_old",
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
	_, err = tx.Exec("INSERT OR REPLACE INTO acctrounds(id, rnd) VALUES('hashbase', ?)", balancesRound)
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
			totals.AddAccount(proto, data, &ot)
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
				err = fmt.Errorf("Account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
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

func createAccountExtTable(tx *sql.Tx) error {
	tableCreate := `CREATE TABLE IF NOT EXISTS accountext (
		id integer primary key,
		data blob)`
	_, err := tx.Exec(tableCreate)
	return err
}

// accountDataToOnline returns the part of the AccountData that matters
// for online accounts (to answer top-N queries).  We store a subset of
// the full AccountData because we need to store a large number of these
// in memory (say, 1M), and storing that many AccountData could easily
// cause us to run out of memory.
func accountDataToOnline(address basics.Address, ad *basics.AccountData, proto config.ConsensusParams) *onlineAccount {
	return &onlineAccount{
		Address:                 address,
		MicroAlgos:              ad.MicroAlgos,
		RewardsBase:             ad.RewardsBase,
		NormalizedOnlineBalance: ad.NormalizedOnlineBalance(proto),
		VoteID:                  ad.VoteID,
		VoteFirstValid:          ad.VoteFirstValid,
		VoteLastValid:           ad.VoteLastValid,
		VoteKeyDilution:         ad.VoteKeyDilution,
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

// accountsRound returns the tracker balances round number, and the round of the hash tree
// if the hash of the tree doesn't exists, it returns zero.
func accountsRound(tx *sql.Tx) (rnd basics.Round, hashrnd basics.Round, err error) {
	err = tx.QueryRow("SELECT rnd FROM acctrounds WHERE id='acctbase'").Scan(&rnd)
	if err != nil {
		return
	}

	err = tx.QueryRow("SELECT rnd FROM acctrounds WHERE id='hashbase'").Scan(&hashrnd)
	if err == sql.ErrNoRows {
		hashrnd = basics.Round(0)
		err = nil
	}
	return
}

const lookupAcctBaseQuery string = "SELECT accountbase.rowid, rnd, data FROM acctrounds LEFT JOIN accountbase ON address=? WHERE id='acctbase'"
const loadAcctExtQuery string = "SELECT rnd, data FROM acctrounds LEFT JOIN accountext ON accountext.id=? WHERE acctrounds.id='acctbase'"

func accountsDbInit(r db.Queryable, w db.Queryable) (*accountsDbQueries, error) {
	var err error
	qs := &accountsDbQueries{}

	qs.listCreatablesStmt, err = r.Prepare("SELECT rnd, asset, creator FROM acctrounds LEFT JOIN assetcreators ON assetcreators.asset <= ? AND assetcreators.ctype = ? WHERE acctrounds.id='acctbase' ORDER BY assetcreators.asset desc LIMIT ?")
	if err != nil {
		return nil, err
	}

	qs.lookupStmt, err = r.Prepare(lookupAcctBaseQuery)
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

	qs.deleteCatchpointState, err = r.Prepare("DELETE FROM catchpointstate WHERE id=?")
	if err != nil {
		return nil, err
	}

	qs.insertCatchpointStateUint64, err = r.Prepare("INSERT OR REPLACE INTO catchpointstate(id, intval) VALUES(?, ?)")
	if err != nil {
		return nil, err
	}

	qs.insertCatchpointStateString, err = r.Prepare("INSERT OR REPLACE INTO catchpointstate(id, strval) VALUES(?, ?)")
	if err != nil {
		return nil, err
	}

	qs.selectCatchpointStateString, err = r.Prepare("SELECT strval FROM catchpointstate WHERE id=?")
	if err != nil {
		return nil, err
	}

	qs.loadAccountGroupDataStmt, err = r.Prepare(loadAcctExtQuery)
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

// lookup looks up for a the account data given it's address. It returns the dbAccountData, which includes the current database round and the matching
// account data, if such was found. If no matching account data could be found for the given address, an empty account data would
// be retrieved.
func (qs *accountsDbQueries) lookup(addr basics.Address) (data dbAccountData, err error) {
	err = db.Retry(func() error {
		data, err = lookupImpl(qs.lookupStmt, addr)
		return err
	})

	return
}

func lookupImpl(lookupStmt *sql.Stmt, addr basics.Address) (data dbAccountData, err error) {
	var buf []byte
	var rowid sql.NullInt64
	err = lookupStmt.QueryRow(addr[:]).Scan(&rowid, &data.round, &buf)
	if err == nil {
		data.addr = addr
		if len(buf) > 0 && rowid.Valid {
			data.rowid = rowid.Int64
			err = protocol.Decode(buf, &data.pad)
			return data, err
		}
		// we don't have that account, just return the database round.
		return data, nil
	}

	// this should never happen; it indicates that we don't have a current round in the acctrounds table.
	if err == sql.ErrNoRows {
		// Return the zero value of data
		return data, fmt.Errorf("unable to query account data for address %v : %w", addr, err)
	}

	return
}

func lookupExt(rdb db.Accessor, addr basics.Address, extension func(*sql.Stmt, *ledgercore.PersistedAccountData) error) (data dbAccountData, err error) {
	err = db.Retry(func() error {
		err = rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			lookupStmt, err := tx.Prepare(lookupAcctBaseQuery)
			if err != nil {
				return err
			}
			defer lookupStmt.Close()

			loadStmt, err := tx.Prepare(loadAcctExtQuery)
			if err != nil {
				return err
			}
			defer loadStmt.Close()

			data, err = lookupImpl(lookupStmt, addr)
			if err != nil {
				return err
			}

			if extension != nil && data.pad.ExtendedAssetHolding.Count > 0 {
				err = extension(loadStmt, &data.pad)
			}
			return err
		})
		return err
	})
	return
}

// lookupFull atomically loads base account data and all extension groups
func lookupFull(rdb db.Accessor, addr basics.Address) (dbad dbAccountData, err error) {
	err = db.Retry(func() error {
		err = rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			lookupStmt, err := tx.Prepare(lookupAcctBaseQuery)
			if err != nil {
				return err
			}
			defer lookupStmt.Close()

			loadStmt, err := tx.Prepare(loadAcctExtQuery)
			if err != nil {
				return err
			}
			defer loadStmt.Close()

			dbad, err = lookupImpl(lookupStmt, addr)
			if err != nil {
				return err
			}
			if dbad.pad.ExtendedAssetHolding.Count > 0 {
				dbad.pad.Assets, dbad.pad.ExtendedAssetHolding, err = loadHoldings(loadStmt, dbad.pad.ExtendedAssetHolding, dbad.round)
			}
			if dbad.pad.ExtendedAssetParams.Count > 0 {
				dbad.pad.AssetParams, dbad.pad.ExtendedAssetParams, err = loadParams(loadStmt, dbad.pad.ExtendedAssetParams, dbad.round)
			}
		if data.pad.ExtendedAssetParams.Count > 0 {
			data.pad.AssetParams, data.pad.ExtendedAssetParams, err = loadParams(loadStmt, data.pad.ExtendedAssetParams)
		}
			return err
		})
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
		if err == sql.ErrNoRows || (err == nil && false == val.Valid) {
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
		if err == sql.ErrNoRows || (err == nil && false == val.Valid) {
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
		&qs.lookupCreatorStmt,
		&qs.loadAccountGroupDataStmt,
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

func (qs *accountsDbQueries) loadHoldings(eah ledgercore.ExtendedAssetHolding, rnd basics.Round) (holdings map[basics.AssetIndex]basics.AssetHolding, result ledgercore.ExtendedAssetHolding, err error) {
	holdings, result, err = loadHoldings(qs.loadAccountGroupDataStmt, eah, rnd)
	return
}

func (qs *accountsDbQueries) loadParams(eap ledgercore.ExtendedAssetParams, rnd basics.Round) (params map[basics.AssetIndex]basics.AssetParams, result ledgercore.ExtendedAssetParams, err error) {
	params, result, err = loadParams(qs.loadAccountGroupDataStmt, eap, rnd)
	return
}

func (qs *accountsDbQueries) loadParams(eap ledgercore.ExtendedAssetParams) (params map[basics.AssetIndex]basics.AssetParams, result ledgercore.ExtendedAssetParams, err error) {
	err = db.Retry(func() error {
		params, result, err = loadParams(qs.loadAccountGroupDataStmt, eap)
		return err
	})
	return
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
func accountsOnlineTop(tx *sql.Tx, offset, n uint64, proto config.ConsensusParams) (map[basics.Address]*onlineAccount, error) {
	rows, err := tx.Query("SELECT address, data FROM accountbase WHERE normalizedonlinebalance>0 ORDER BY normalizedonlinebalance DESC, address DESC LIMIT ? OFFSET ?", n, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[basics.Address]*onlineAccount, n)
	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		err = rows.Scan(&addrbuf, &buf)
		if err != nil {
			return nil, err
		}

		var pad ledgercore.PersistedAccountData
		err = protocol.Decode(buf, &pad)
		if err != nil {
			return nil, err
		}

		var addr basics.Address
		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("Account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return nil, err
		}

		copy(addr[:], addrbuf)
		res[addr] = accountDataToOnline(addr, &pad.AccountData, proto)
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

type fetcher func(key int64) (buf []byte, rnd basics.Round, err error)

func makeAssetFetcher(stmt *sql.Stmt) fetcher {
	return func(key int64) (buf []byte, rnd basics.Round, err error) {
		buf, rnd, err = loadGroupData(stmt, key)
		return
	}
}

// loadHoldings initiates all holdings mentioned in ExtendedAssetHolding groups.
// baseRound specifies a round number records need satisfy to. If baseRound is zero any data are OK.
func loadHoldings(stmt *sql.Stmt, eah ledgercore.ExtendedAssetHolding, baseRound basics.Round) (map[basics.AssetIndex]basics.AssetHolding, ledgercore.ExtendedAssetHolding, error) {
	if len(eah.Groups) == 0 {
		return nil, ledgercore.ExtendedAssetHolding{}, nil
	}
	var err error
	holdings := make(map[basics.AssetIndex]basics.AssetHolding, eah.Count)
	groups := make([]ledgercore.AssetsHoldingGroup, len(eah.Groups), len(eah.Groups))
	fetcher := makeAssetFetcher(stmt)
	fetchedRound := basics.Round(0)
	for gi := range eah.Groups {
		groups[gi] = eah.Groups[gi]
		fetchedRound, err = groups[gi].Fetch(fetcher, holdings)
		if err != nil {
			return nil, ledgercore.ExtendedAssetHolding{}, err
		}
		if baseRound != 0 && baseRound != fetchedRound {
			return nil, ledgercore.ExtendedAssetHolding{}, &MismatchingDatabaseRoundError{databaseRound: fetchedRound, memoryRound: baseRound}
		}
	}
	eah.Groups = groups
	return holdings, eah, nil
}

// loadParams initiates all params mentioned in ExtendedAssetHolding groups.
// baseRound specifies a round number records need satisfy to. If baseRound is zero any data are OK.
func loadParams(stmt *sql.Stmt, eah ledgercore.ExtendedAssetParams, baseRound basics.Round) (map[basics.AssetIndex]basics.AssetParams, ledgercore.ExtendedAssetParams, error) {
	if len(eah.Groups) == 0 {
		return nil, ledgercore.ExtendedAssetParams{}, nil
	}
	var err error
	params := make(map[basics.AssetIndex]basics.AssetParams, eah.Count)
	groups := make([]ledgercore.AssetsParamsGroup, len(eah.Groups), len(eah.Groups))
	fetcher := makeAssetFetcher(stmt)
	fetchedRound := basics.Round(0)
	for gi := range eah.Groups {
		groups[gi] = eah.Groups[gi]
		fetchedRound, err = groups[gi].Fetch(fetcher, params)
		if err != nil {
			return nil, ledgercore.ExtendedAssetParams{}, err
		}
		if baseRound != 0 && baseRound != fetchedRound {
			return nil, ledgercore.ExtendedAssetParams{}, &MismatchingDatabaseRoundError{databaseRound: fetchedRound, memoryRound: baseRound}
		}
	}
	eap.Groups = groups
	return params, eap, nil
}

// loadGroupData loads a single holdings group data
func loadGroupData(stmt *sql.Stmt, key int64) (buf []byte, rnd basics.Round, err error) {
	err = stmt.QueryRow(key).Scan(&rnd, &buf)
	if err == sql.ErrNoRows {
		err = fmt.Errorf("loadGroupData failed to retrive data for key %d", key)
		return
	}

	// Some other database error
	if err != nil {
		return
	}
	return
}

func modifyAssetGroup(query *sql.Stmt, agl ledgercore.AbstractAssetGroupList) (err error) {
	var result sql.Result
	for i := 0; i < agl.Len(); i++ {
		result, err = query.Exec(agl.Get(i).Encode())
		if err != nil {
			break
		}
		key, err := result.LastInsertId()
		if err != nil {
			break
		}
		agl.Get(i).SetKey(key)
	}
	return err
}

func deleteAssetGroup(query *sql.Stmt, agl ledgercore.AbstractAssetGroupList) (err error) {
	for i := 0; i < agl.Len(); i++ {
		_, err = query.Exec(agl.Get(i).Key())
		if err != nil {
			break
		}
	}
	return err
}

// collapseAssetHoldings moves all assets from ExtendedAssetHolding groups to Assets field
func collapseAssetHoldings(qabq, qaed *sql.Stmt, eah ledgercore.ExtendedAssetHolding, updated map[basics.AssetIndex]basics.AssetHolding, deleted []basics.AssetIndex, rnd basics.Round) (assets map[basics.AssetIndex]basics.AssetHolding, err error) {
	// 1. load all
	assets, _, err = loadHoldings(qabq, eah, rnd)
	if err != nil {
		return nil, err
	}
	// 2. remove deleted
	for _, aidx := range deleted {
		delete(assets, aidx)
	}
	// 3. add created and modified from delta.new
	for aidx, holding := range updated {
		assets[aidx] = holding
	}

	// 4. delete all groups
	for _, g := range eah.Groups {
		qaed.Exec(g.AssetGroupKey)
	}
	return assets, nil
}

// collapseAssetParams moves all assets from ExtendedAssetParams groups to Assets field
func collapseAssetParams(qabq, qaed *sql.Stmt, eap ledgercore.ExtendedAssetParams, updated map[basics.AssetIndex]basics.AssetParams, deleted []basics.AssetIndex, rnd basics.Round) (assets map[basics.AssetIndex]basics.AssetParams, err error) {
	// 1. load all
	assets, _, err = loadParams(qabq, eap, rnd)
	if err != nil {
		return nil, err
	}
	// 2. remove deleted
	for _, aidx := range deleted {
		delete(assets, aidx)
	}
	// 3. add created and modified from delta.new
	for aidx, param := range updated {
		assets[aidx] = param
	}

	// 4. delete all groups
	for _, g := range eap.Groups {
		qaed.Exec(g.AssetGroupKey)
	}
	return assets, nil
}

func assetsUpdateGroupDataDB(qaei, qaeu, qaed *sql.Stmt, agl ledgercore.AbstractAssetGroupList, loadedGroups []int, deletedKeys []int64) (err error) {
	for _, key := range deletedKeys {
		if _, err = qaed.Exec(key); err != nil {
			return err
		}
	}

	var result sql.Result
	for _, i := range loadedGroups {
		ag := agl.Get(i)
		if ag.Key() != 0 { // existing entry, update
			if _, err = qaeu.Exec(ag.Encode(), ag.Key()); err != nil {
				break
			}
		} else {
			// new entry, insert
			if result, err = qaei.Exec(ag.Encode()); err != nil {
				break
			}
			var key int64
			if key, err = result.LastInsertId(); err != nil {
				break
			}
			ag.SetKey(key)
		}
	}
	return
}

func accountsNewCreate(qabi *sql.Stmt, qaei *sql.Stmt, addr basics.Address, pad ledgercore.PersistedAccountData, proto config.ConsensusParams, updatedAccounts []dbAccountData, updateIdx int) ([]dbAccountData, error) {
	assetsThreshold := config.Consensus[protocol.ConsensusV18].MaxAssetsPerAccount
	if len(pad.Assets) > assetsThreshold {
		pad.ExtendedAssetHolding.ConvertToGroups(pad.Assets)
		pad.AccountData.Assets = nil
	}

	if len(pad.AssetParams) > assetsThreshold {
		pad.ExtendedAssetParams.ConvertToGroups(pad.AssetParams)
		pad.AccountData.AssetParams = nil
	}

	// save holdings
	var result sql.Result
	var err error
	err = modifyAssetGroup(qaei, &pad.ExtendedAssetHolding)
	if err != nil {
		return updatedAccounts, err
	}

	// save params
	err = modifyAssetGroup(qaei, &pad.ExtendedAssetParams)
	if err != nil {
		return updatedAccounts, err
	}

	normBalance := pad.AccountData.NormalizedOnlineBalance(proto)
	result, err = qabi.Exec(addr[:], normBalance, protocol.Encode(&pad))
	if err == nil {
		updatedAccounts[updateIdx].rowid, err = result.LastInsertId()
		updatedAccounts[updateIdx].pad = pad
	}
	return updatedAccounts, err
}

func accountsNewDelete(qabd *sql.Stmt, qaed *sql.Stmt, addr basics.Address, dbad dbAccountData, updatedAccounts []dbAccountData, updateIdx int) ([]dbAccountData, error) {
	result, err := qabd.Exec(dbad.rowid)
	if err != nil {
		return updatedAccounts, err
	}

	// we deleted the entry successfully.
	updatedAccounts[updateIdx].rowid = 0
	updatedAccounts[updateIdx].pad = ledgercore.PersistedAccountData{}
	var rowsAffected int64
	rowsAffected, err = result.RowsAffected()
	if rowsAffected != 1 {
		err = fmt.Errorf("failed to delete accountbase row for account %v, rowid %d", addr, dbad.rowid)
	} else {
		// if no error => delete extension records
		err = deleteAssetGroup(qaed, &dbad.pad.ExtendedAssetHolding)
		if err == nil {
			err = deleteAssetGroup(qaed, &dbad.pad.ExtendedAssetParams)
		}
	}
	return updatedAccounts, err
}

func filterCreatedDeleted(assets map[basics.AssetIndex]ledgercore.AssetAction, cr ledgercore.AssetAction, dl ledgercore.AssetAction) (created, deleted []basics.AssetIndex) {
	created = make([]basics.AssetIndex, 0, len(assets)/2)
	deleted = make([]basics.AssetIndex, 0, len(assets)/2)

	for aidx, action := range assets {
		if action == cr {
			created = append(created, aidx)
		} else if action == dl {
			deleted = append(deleted, aidx)
		}
	}
	return
}

// accountsNewUpdate reconciles old and new AccountData in delta.
// Precondition: all modified assets must be loaded into old's groupData and cached into Assets
func accountsNewUpdate(qabu, qabq, qaeu, qaei, qaed *sql.Stmt, addr basics.Address, delta accountDelta, genesisProto config.ConsensusParams, updatedAccounts []dbAccountData, updateIdx int) ([]dbAccountData, error) {
	assetsThreshold := config.Consensus[protocol.ConsensusV18].MaxAssetsPerAccount

	// sanity check: counts must match since all the modications are in delta.new.Assets and mods map
	if delta.old.pad.ExtendedAssetHolding.Count != delta.new.ExtendedAssetHolding.Count {
		return updatedAccounts, fmt.Errorf("extended holdings count mismatch (old) %d != %d (new)", delta.old.pad.ExtendedAssetHolding.Count, delta.new.ExtendedAssetHolding.Count)
	}

	// Reconciliation asset holdings (and asset params) logic:
	// old.Assets must always have the assets modified in new (see accountsLoadOld)
	// PersistedAccountData stores the data either in Assets field or as ExtendedHoldings
	// this means:
	// 1. if both old and new below the threshold then all set
	// 2. if old is below and new is above then create group data and clear Assets field
	// 3. if old is above the threshold
	//  - find created and deleted entries
	//  - if the result is below the threshold then move everything in Assets field
	//  - if the result is above the threshold then merge in changes into group data
	var pad ledgercore.PersistedAccountData
	var err error
	pad.AccountData = delta.new.AccountData

	if delta.old.pad.NumAssetHoldings() <= assetsThreshold && len(delta.new.Assets) <= assetsThreshold {
		// AccountData assigned above
		// Do not use delta.assets map of deleted/created since entire Assets is being replaced
	} else if delta.old.pad.NumAssetHoldings() <= assetsThreshold && len(delta.new.Assets) > assetsThreshold {
		_, deleted := filterCreatedDeleted(delta.assets, ledgercore.ActionHoldingCreate, ledgercore.ActionHoldingDelete)
		assets := make(map[basics.AssetIndex]basics.AssetHolding, len(delta.old.pad.Assets)+len(delta.new.Assets)-len(deleted))
		for aidx, holding := range delta.old.pad.Assets {
			assets[aidx] = holding
		}
		for _, aidx := range deleted {
			delete(assets, aidx)
		}
		for aidx, holding := range delta.new.Assets {
			assets[aidx] = holding
		}

		pad.ExtendedAssetHolding.ConvertToGroups(assets)
		pad.AccountData.Assets = nil

		// update group data DB table
		err = modifyAssetGroup(qaei, &pad.ExtendedAssetHolding)
	} else { // default case: delta.old.pad.NumAssetHoldings() > assetsThreshold

		created, deleted := filterCreatedDeleted(delta.assets, ledgercore.ActionHoldingCreate, ledgercore.ActionHoldingDelete)
		pad.ExtendedAssetHolding = delta.new.ExtendedAssetHolding
		oldPad := delta.old.pad
		oldPadRound := delta.old.round

		newCount := oldPad.NumAssetHoldings() + len(created) - len(deleted)
		if newCount < assetsThreshold {
			// Move all assets from groups to Assets field
			assets, err := collapseAssetHoldings(qabq, qaed, oldPad.ExtendedAssetHolding, delta.new.Assets, deleted, oldPadRound)
			if err != nil {
				return updatedAccounts, err
			}
			pad.AccountData.Assets = assets
			pad.ExtendedAssetHolding = ledgercore.ExtendedAssetHolding{}
		} else {
			// Reconcile groups data:
			// identify groups, load, update, then delete and insert, dump to the disk

			updated := make([]basics.AssetIndex, 0, len(delta.new.Assets))
			for aidx := range delta.new.Assets {
				if _, ok := delta.assets[aidx]; !ok {
					updated = append(updated, aidx)
				}
			}

			pad.ExtendedAssetHolding = oldPad.ExtendedAssetHolding
			if len(updated) > 0 {
				err = pad.ExtendedAssetHolding.Update(updated, delta.new.Assets)
				if err != nil {
					return updatedAccounts, err
				}
			}

			if len(deleted) > 0 {
				keysToDelete, err := pad.ExtendedAssetHolding.Delete(deleted)
				if err != nil {
					return updatedAccounts, err
				}
				for _, key := range keysToDelete {
					_, err = qaed.Exec(key)
					if err != nil {
						return updatedAccounts, err
					}
				}
			}

			if len(created) > 0 {
				pad.ExtendedAssetHolding.Insert(created, delta.new.Assets)
			}

			loaded, deletedKeys := pad.ExtendedAssetHolding.Merge()

			// update DB
			err = assetsUpdateGroupDataDB(qaei, qaeu, qaed, &pad.ExtendedAssetHolding, loaded, deletedKeys)
			pad.AccountData.Assets = nil
		}
	}

	// same logic as above but for asset params
	if delta.old.pad.NumAssetParams() <= assetsThreshold && len(delta.new.AssetParams) <= assetsThreshold {
		// AccountData assigned above
		// Do not use delta.assets map of deleted/created since entire AssetParams is being replaced
	} else if delta.old.pad.NumAssetParams() <= assetsThreshold && len(delta.new.AssetParams) > assetsThreshold {
		_, deleted := filterCreatedDeleted(delta.assets, ledgercore.ActionParamsCreate, ledgercore.ActionParamsDelete)
		assets := make(map[basics.AssetIndex]basics.AssetParams, len(delta.old.pad.AssetParams)+len(delta.new.AssetParams)-len(deleted))
		for aidx, params := range delta.old.pad.AssetParams {
			assets[aidx] = params
		}
		for _, aidx := range deleted {
			delete(assets, aidx)
		}
		for aidx, params := range delta.new.AssetParams {
			assets[aidx] = params
		}

		pad.ExtendedAssetParams.ConvertToGroups(assets)
		pad.AccountData.AssetParams = nil

		// update group data DB table
		err = modifyAssetGroup(qaei, &pad.ExtendedAssetParams)
	} else { // default case: delta.old.pad.NumAssetHoldings() > assetsThreshold

		created, deleted := filterCreatedDeleted(delta.assets, ledgercore.ActionParamsCreate, ledgercore.ActionParamsDelete)

		pad.ExtendedAssetParams = delta.new.ExtendedAssetParams
		oldPad := delta.old.pad
		oldPadRound := delta.old.round

		newCount := oldPad.NumAssetParams() + len(created) - len(deleted)
		if newCount < assetsThreshold {
			// Move all assets from groups to Assets field
			assets, err := collapseAssetParams(qabq, qaed, oldPad.ExtendedAssetParams, delta.new.AssetParams, deleted, oldPadRound)
			if err != nil {
				return updatedAccounts, err
			}
			pad.AccountData.AssetParams = assets
			pad.ExtendedAssetParams = ledgercore.ExtendedAssetParams{}
		} else {
			// Reconcile groups data:
			// identify groups, load, update, then delete and insert, dump to the disk

			updated := make([]basics.AssetIndex, 0, len(delta.new.AssetParams))
			for aidx := range delta.new.AssetParams {
				if _, ok := delta.assets[aidx]; !ok {
					updated = append(updated, aidx)
				}
			}

			pad.ExtendedAssetParams = oldPad.ExtendedAssetParams
			if len(updated) > 0 {
				err = pad.ExtendedAssetParams.Update(updated, delta.new.AssetParams)
				if err != nil {
					return updatedAccounts, err
				}
			}

			if len(deleted) > 0 {
				keysToDelete, err := pad.ExtendedAssetParams.Delete(deleted)
				if err != nil {
					return updatedAccounts, err
				}
				for _, key := range keysToDelete {
					_, err = qaed.Exec(key)
					if err != nil {
						return updatedAccounts, err
					}
				}
			}

			if len(created) > 0 {
				pad.ExtendedAssetParams.Insert(created, delta.new.AssetParams)
			}

			loaded, deletedKeys := pad.ExtendedAssetParams.Merge()

			// update DB
			err = assetsUpdateGroupDataDB(qaei, qaeu, qaed, &pad.ExtendedAssetParams, loaded, deletedKeys)
			pad.AccountData.AssetParams = nil
		}
	}

	// update accountbase
	if err == nil {
		var rowsAffected int64
		normBalance := delta.new.NormalizedOnlineBalance(genesisProto)
		result, err := qabu.Exec(normBalance, protocol.Encode(&pad), delta.old.rowid)
		if err == nil {
			// rowid doesn't change on update.
			updatedAccounts[updateIdx].rowid = delta.old.rowid
			updatedAccounts[updateIdx].pad = pad
			rowsAffected, err = result.RowsAffected()
			if rowsAffected != 1 {
				err = fmt.Errorf("failed to update accountbase row for account %v, rowid %d", addr, delta.old.rowid)
			}
		}
	}

	return updatedAccounts, err
}

type accountsNewQueries struct {
	insertStmt          *sql.Stmt
	updateStmt          *sql.Stmt
	deleteByRowIDStmt   *sql.Stmt
	insertGroupDataStmt *sql.Stmt
	updateGroupDataStmt *sql.Stmt
	deleteGroupDataStmt *sql.Stmt
	queryGroupDataStmt  *sql.Stmt
}

func makeAccountsNewQueries(db db.Queryable) (q accountsNewQueries, err error) {
	defer func() {
		if err != nil {
			q.close()
		}
	}()

	if q.insertStmt, err = db.Prepare("INSERT INTO accountbase (address, normalizedonlinebalance, data) VALUES (?, ?, ?)"); err != nil {
		return
	}

	if q.updateStmt, err = db.Prepare("UPDATE accountbase SET normalizedonlinebalance = ?, data = ? WHERE rowid = ?"); err != nil {
		return
	}

	if q.deleteByRowIDStmt, err = db.Prepare("DELETE FROM accountbase WHERE rowid=?"); err != nil {
		return
	}

	if q.insertGroupDataStmt, err = db.Prepare("INSERT INTO accountext (data) VALUES (?)"); err != nil {
		return
	}

	if q.updateGroupDataStmt, err = db.Prepare("UPDATE accountext SET data = ? WHERE id = ?"); err != nil {
		return
	}

	if q.deleteGroupDataStmt, err = db.Prepare("DELETE FROM accountext WHERE id=?"); err != nil {
		return
	}

	if q.queryGroupDataStmt, err = db.Prepare(loadAcctExtQuery); err != nil {
		return
	}

	return
}

func (q *accountsNewQueries) close() {
	if q.insertStmt != nil {
		q.insertStmt.Close()
		q.insertStmt = nil
	}
	if q.updateStmt != nil {
		q.updateStmt.Close()
		q.updateStmt = nil
	}
	if q.deleteByRowIDStmt != nil {
		q.deleteByRowIDStmt.Close()
		q.deleteByRowIDStmt = nil
	}
	if q.insertGroupDataStmt != nil {
		q.insertGroupDataStmt.Close()
		q.insertGroupDataStmt = nil
	}
	if q.updateGroupDataStmt != nil {
		q.updateGroupDataStmt.Close()
		q.updateGroupDataStmt = nil
	}
	if q.deleteGroupDataStmt != nil {
		q.deleteGroupDataStmt.Close()
		q.deleteGroupDataStmt = nil
	}
	if q.queryGroupDataStmt != nil {
		q.queryGroupDataStmt.Close()
		q.queryGroupDataStmt = nil
	}
}

// accountsNewRound updates the accountbase and assetcreators tables by applying the provided deltas to the accounts / creatables.
// The function returns a dbAccountData for the modified accounts which can be stored in the base cache.
func accountsNewRound(tx *sql.Tx, updates compactAccountDeltas, creatables map[basics.CreatableIndex]ledgercore.ModifiedCreatable, proto config.ConsensusParams, lastUpdateRound basics.Round) (updatedAccounts []dbAccountData, err error) {
	q, err := makeAccountsNewQueries(tx)
	if err != nil {
		return
	}

	updatedAccounts = make([]dbAccountData, updates.len())
	updatedAccountIdx := 0
	for i := 0; i < updates.len(); i++ {
		addr, delta := updates.getByIdx(i)
		if delta.old.rowid == 0 {
			// zero rowid means we don't have a previous value.
			if delta.new.IsZero() {
				// if we didn't had it before, and we don't have anything now, just skip it.
			} else {
				// create a new entry.
				updatedAccounts, err = accountsNewCreate(
					q.insertStmt, q.insertGroupDataStmt,
					addr, delta.new, proto,
					updatedAccounts, updatedAccountIdx)
			}
		} else {
			if delta.new.IsZero() {
				// new value is zero, which means we need to delete the current value.
				updatedAccounts, err = accountsNewDelete(
					q.deleteByRowIDStmt, q.deleteGroupDataStmt,
					addr, delta.old,
					updatedAccounts, updatedAccountIdx)
			} else {
				// non-zero rowid means we had a previous value so make an update.
				updatedAccounts, err = accountsNewUpdate(
					q.updateStmt, q.queryGroupDataStmt,
					q.updateGroupDataStmt, q.insertGroupDataStmt, q.deleteGroupDataStmt,
					addr, delta, proto,
					updatedAccounts, updatedAccountIdx)
			}
		}

		if err != nil {
			return
		}

		// set the returned persisted account states so that we could store that as the baseAccounts in commitRound
		updatedAccounts[updatedAccountIdx].round = lastUpdateRound
		updatedAccounts[updatedAccountIdx].addr = addr
		updatedAccountIdx++
	}

	if len(creatables) > 0 {
		var insertCreatableIdxStmt, deleteCreatableIdxStmt *sql.Stmt

		insertCreatableIdxStmt, err = tx.Prepare("INSERT INTO assetcreators (asset, creator, ctype) VALUES (?, ?, ?)")
		if err != nil {
			return
		}
		defer insertCreatableIdxStmt.Close()

		deleteCreatableIdxStmt, err = tx.Prepare("DELETE FROM assetcreators WHERE asset=? AND ctype=?")
		if err != nil {
			return
		}
		defer deleteCreatableIdxStmt.Close()

		for cidx, cdelta := range creatables {
			if cdelta.Created {
				_, err = insertCreatableIdxStmt.Exec(cidx, cdelta.Creator[:], cdelta.Ctype)
			} else {
				_, err = deleteCreatableIdxStmt.Exec(cidx, cdelta.Ctype)
			}
			if err != nil {
				return
			}
		}
	}

	return
}

// totalsNewRounds updates the accountsTotals by applying series of round changes
func totalsNewRounds(tx *sql.Tx, updates []ledgercore.AccountDeltas, compactUpdates compactAccountDeltas, accountTotals []ledgercore.AccountTotals, proto config.ConsensusParams) (err error) {
	var ot basics.OverflowTracker
	totals, err := accountsTotals(tx, false)
	if err != nil {
		return
	}

	// copy the updates base account map, since we don't want to modify the input map.
	accounts := make(map[basics.Address]basics.AccountData, compactUpdates.len())
	for i := 0; i < compactUpdates.len(); i++ {
		addr, acctData := compactUpdates.getByIdx(i)
		accounts[addr] = acctData.old.pad.AccountData
	}

	for i := 0; i < len(updates); i++ {
		totals.ApplyRewards(accountTotals[i].RewardsLevel, &ot)

		for j := 0; j < updates[i].Len(); j++ {
			addr, pad := updates[i].GetByIdx(j)
			data := pad.AccountData
			if oldAccountData, has := accounts[addr]; has {
				totals.DelAccount(proto, oldAccountData, &ot)
			} else {
				err = fmt.Errorf("missing old account data")
				return
			}

			totals.AddAccount(proto, data, &ot)
			accounts[addr] = data
		}
	}

	if ot.Overflowed {
		err = fmt.Errorf("overflow computing totals")
		return
	}

	err = accountsPutTotals(tx, totals, false)
	if err != nil {
		return
	}

	return
}

// updates the round number associated with the current account data.
func updateAccountsRound(tx *sql.Tx, rnd basics.Round, hashRound basics.Round) (err error) {
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

	res, err = tx.Exec("INSERT OR REPLACE INTO acctrounds(id,rnd) VALUES('hashbase',?)", hashRound)
	if err != nil {
		return
	}

	aff, err = res.RowsAffected()
	if err != nil {
		return
	}

	if aff != 1 {
		err = fmt.Errorf("updateAccountsRound(hashbase,%d): expected to update 1 row but got %d", hashRound, aff)
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
			err = fmt.Errorf("Account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
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
		if bytes.Compare(preencodedAccountData, reencodedAccountData) == 0 {
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

// MerkleCommitter todo
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
	rows *sql.Rows
}

// Next returns an array containing the account data, in the same way it appear in the database
// returning accountCount accounts data at a time.
func (iterator *encodedAccountsBatchIter) Next(ctx context.Context, tx *sql.Tx, accountCount int) (bals []encodedBalanceRecord, err error) {
	if iterator.rows == nil {
		iterator.rows, err = tx.QueryContext(ctx, "SELECT address, data FROM accountbase ORDER BY address")
		if err != nil {
			return
		}
	}

	// gather up to accountCount encoded accounts.
	bals = make([]encodedBalanceRecord, 0, accountCount)
	var addr basics.Address
	for iterator.rows.Next() {
		var addrbuf []byte
		var buf []byte
		err = iterator.rows.Scan(&addrbuf, &buf)
		if err != nil {
			iterator.Close()
			return
		}

		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("Account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return
		}

		copy(addr[:], addrbuf)

		bals = append(bals, encodedBalanceRecord{Address: addr, AccountData: buf})
		if len(bals) == accountCount {
			// we're done with this iteration.
			return
		}
	}

	err = iterator.rows.Err()
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
	if iterator.rows != nil {
		iterator.rows.Close()
		iterator.rows = nil
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
	step         orderedAccountsIterStep
	rows         *sql.Rows
	tx           *sql.Tx
	accountCount int
	insertStmt   *sql.Stmt
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

// accountAddressHash is used by Next to return a single account address and the associated hash.
type accountAddressHash struct {
	address basics.Address
	digest  []byte
}

// Next returns an array containing the account address and hash
// the Next function works in multiple processing stages, where it first processs the current accounts and order them
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
		_, err = iterator.tx.ExecContext(ctx, "CREATE TABLE accountsiteratorhashes(address blob, hash blob)")
		if err != nil {
			return
		}
		iterator.step = oaiStepQueryAccounts
		return
	}
	if iterator.step == oaiStepQueryAccounts {
		// iterate over the existing accounts
		iterator.rows, err = iterator.tx.QueryContext(ctx, "SELECT address, data FROM accountbase")
		if err != nil {
			return
		}
		// prepare the insert statement into the temporary table
		iterator.insertStmt, err = iterator.tx.PrepareContext(ctx, "INSERT INTO accountsiteratorhashes(address, hash) VALUES(?, ?)")
		if err != nil {
			return
		}
		iterator.step = oaiStepInsertAccountData
		return
	}
	if iterator.step == oaiStepInsertAccountData {
		var addr basics.Address
		count := 0
		for iterator.rows.Next() {
			var addrbuf []byte
			var buf []byte
			err = iterator.rows.Scan(&addrbuf, &buf)
			if err != nil {
				iterator.Close(ctx)
				return
			}

			if len(addrbuf) != len(addr) {
				err = fmt.Errorf("Account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
				iterator.Close(ctx)
				return
			}

			copy(addr[:], addrbuf)

			var accountData basics.AccountData
			err = protocol.Decode(buf, &accountData)
			if err != nil {
				iterator.Close(ctx)
				return
			}
			hash := accountHashBuilder(addr, accountData.RewardsBase, buf)
			_, err = iterator.insertStmt.ExecContext(ctx, addrbuf, hash)
			if err != nil {
				iterator.Close(ctx)
				return
			}

			count++
			if count == iterator.accountCount {
				// we're done with this iteration.
				processedRecords = count
				return
			}
		}
		processedRecords = count
		iterator.rows.Close()
		iterator.rows = nil
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
		iterator.rows, err = iterator.tx.QueryContext(ctx, "SELECT address, hash FROM accountsiteratorhashes ORDER BY hash")

		if err != nil {
			iterator.Close(ctx)
			return
		}
		iterator.step = oaiStepIterateOverOrderedTable
		return
	}

	if iterator.step == oaiStepIterateOverOrderedTable {
		acct = make([]accountAddressHash, 0, iterator.accountCount)
		var addr basics.Address
		for iterator.rows.Next() {
			var addrbuf []byte
			var hash []byte
			err = iterator.rows.Scan(&addrbuf, &hash)
			if err != nil {
				iterator.Close(ctx)
				return
			}

			if len(addrbuf) != len(addr) {
				err = fmt.Errorf("Account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
				iterator.Close(ctx)
				return
			}

			copy(addr[:], addrbuf)

			acct = append(acct, accountAddressHash{address: addr, digest: hash})
			if len(acct) == iterator.accountCount {
				// we're done with this iteration.
				return
			}
		}
		iterator.step = oaiStepShutdown
		iterator.rows.Close()
		iterator.rows = nil
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
	if iterator.rows != nil {
		iterator.rows.Close()
		iterator.rows = nil
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
	hashes = make([][]byte, 0, iterator.hashCount)
	for iterator.rows.Next() {
		var hash []byte
		err = iterator.rows.Scan(&hash)
		if err != nil {
			iterator.Close()
			return
		}

		hashes = append(hashes, hash)
		if len(hashes) == iterator.hashCount {
			// we're done with this iteration.
			return
		}
	}

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

// before compares the round numbers of two dbAccountData and determines if the current dbAccountData
// happened before the other.
func (pac *dbAccountData) before(other *dbAccountData) bool {
	return pac.round < other.round
}
