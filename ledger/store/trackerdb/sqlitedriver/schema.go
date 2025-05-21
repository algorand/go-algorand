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

package sqlitedriver

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/blockdb"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/mattn/go-sqlite3"
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

// createNormalizedOnlineBalanceIndexOnline handles onlineaccounts/catchpointonlineaccounts tables
func createNormalizedOnlineBalanceIndexOnline(idxname string, tablename string) string {
	return fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s
		ON %s ( normalizedonlinebalance, address )`, idxname, tablename)
}

// createUniqueAddressBalanceIndex is sql query to create a uninque index on `address`.
func createUniqueAddressBalanceIndex(idxname string, tablename string) string {
	return fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (address)`, idxname, tablename)
}

// createNormalizedOnlineBalanceIndex handles accountbase/catchpointbalances tables
func createNormalizedOnlineBalanceIndex(idxname string, tablename string) string {
	return fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s
		ON %s ( normalizedonlinebalance, address, data ) WHERE normalizedonlinebalance>0`, idxname, tablename)
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

const createStateProofVerificationTableQuery = `
	CREATE TABLE IF NOT EXISTS stateproofverification (
	lastattestedround integer primary key NOT NULL,
	verificationcontext blob NOT NULL)`

const createVoteLastValidIndex = `
	CREATE INDEX IF NOT EXISTS onlineaccounts_votelastvalid_idx
	ON onlineaccounts ( votelastvalid )`

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
	`DROP TABLE IF EXISTS stateproofverification`,
}

// accountsInit fills the database using tx with initAccounts if the
// database has not been initialized yet.
//
// accountsInit returns nil if either it has initialized the database
// correctly, or if the database has already been initialized.
func accountsInit(e db.Executable, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error) {
	for _, tableCreate := range accountsSchema {
		_, err = e.Exec(tableCreate)
		if err != nil {
			return
		}
	}

	// Run creatables migration if it hasn't run yet
	var creatableMigrated bool
	err = e.QueryRow("SELECT 1 FROM pragma_table_info('assetcreators') WHERE name='ctype'").Scan(&creatableMigrated)
	if err == sql.ErrNoRows {
		// Run migration
		for _, migrateCmd := range creatablesMigration {
			_, err = e.Exec(migrateCmd)
			if err != nil {
				return
			}
		}
	} else if err != nil {
		return
	}

	_, err = e.Exec("INSERT INTO acctrounds (id, rnd) VALUES ('acctbase', 0)")
	if err == nil {
		var ot basics.OverflowTracker
		var totals ledgercore.AccountTotals

		for addr, data := range initAccounts {
			_, err = e.Exec("INSERT INTO accountbase (address, data) VALUES (?, ?)",
				addr[:], protocol.Encode(&data)) //nolint:gosec // Encode does not hold on to reference
			if err != nil {
				return true, err
			}

			ad := ledgercore.ToAccountData(data)
			totals.AddAccount(proto, ad, &ot)
		}

		if ot.Overflowed {
			return true, fmt.Errorf("overflow computing totals")
		}

		arw := NewAccountsSQLReaderWriter(e)
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
func accountsAddNormalizedBalance(e db.Executable, proto config.ConsensusParams) error {
	var exists bool
	err := e.QueryRow("SELECT 1 FROM pragma_table_info('accountbase') WHERE name='normalizedonlinebalance'").Scan(&exists)
	if err == nil {
		// Already exists.
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}

	for _, stmt := range createOnlineAccountIndex {
		_, err = e.Exec(stmt)
		if err != nil {
			return err
		}
	}

	rows, err := e.Query("SELECT address, data FROM accountbase")
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
			_, err = e.Exec("UPDATE accountbase SET normalizedonlinebalance=? WHERE address=?", normBalance, addrbuf)
			if err != nil {
				return err
			}
		}
	}

	return rows.Err()
}

// accountsCreateResourceTable creates the resource table in the database.
func accountsCreateResourceTable(ctx context.Context, e db.Executable) error {
	var exists bool
	err := e.QueryRowContext(ctx, "SELECT 1 FROM pragma_table_info('resources') WHERE name='addrid'").Scan(&exists)
	if err == nil {
		// Already exists.
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	for _, stmt := range createResourcesTable {
		_, err = e.ExecContext(ctx, stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

func accountsCreateOnlineAccountsTable(ctx context.Context, e db.Executable) error {
	var exists bool
	err := e.QueryRowContext(ctx, "SELECT 1 FROM pragma_table_info('onlineaccounts') WHERE name='address'").Scan(&exists)
	if err == nil {
		// Already exists.
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	for _, stmt := range createOnlineAccountsTable {
		_, err = e.ExecContext(ctx, stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

// accountsCreateBoxTable creates the KVStore table for box-storage in the database.
func accountsCreateBoxTable(ctx context.Context, e db.Executable) error {
	var exists bool
	err := e.QueryRow("SELECT 1 FROM pragma_table_info('kvstore') WHERE name='key'").Scan(&exists)
	if err == nil {
		// already exists
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	for _, stmt := range createBoxTable {
		_, err = e.ExecContext(ctx, stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

// performKVStoreNullBlobConversion scans keys with null blob value, and convert the value to `[]byte{}`.
func performKVStoreNullBlobConversion(ctx context.Context, e db.Executable) error {
	_, err := e.ExecContext(ctx, "UPDATE kvstore SET value = '' WHERE value is NULL")
	return err
}

func accountsCreateTxTailTable(ctx context.Context, e db.Executable) (err error) {
	for _, stmt := range createTxTailTable {
		_, err = e.ExecContext(ctx, stmt)
		if err != nil {
			return
		}
	}
	return nil
}

func accountsCreateOnlineRoundParamsTable(ctx context.Context, e db.Executable) (err error) {
	for _, stmt := range createOnlineRoundParamsTable {
		_, err = e.ExecContext(ctx, stmt)
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

func createStateProofVerificationTable(ctx context.Context, e db.Executable) error {
	_, err := e.ExecContext(ctx, createStateProofVerificationTableQuery)
	return err
}

// performResourceTableMigration migrate the database to use the resources table.
func performResourceTableMigration(ctx context.Context, e db.Executable, log func(processed, total uint64)) (err error) {
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
		_, err = e.ExecContext(ctx, stmt)
		if err != nil {
			return err
		}
	}
	var insertNewAcctBase *sql.Stmt
	var insertResources *sql.Stmt
	var insertNewAcctBaseNormBal *sql.Stmt
	insertNewAcctBase, err = e.PrepareContext(ctx, "INSERT INTO accountbase_resources_migration(address, data) VALUES(?, ?)")
	if err != nil {
		return err
	}
	defer insertNewAcctBase.Close()

	insertNewAcctBaseNormBal, err = e.PrepareContext(ctx, "INSERT INTO accountbase_resources_migration(address, data, normalizedonlinebalance) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}
	defer insertNewAcctBaseNormBal.Close()

	insertResources, err = e.PrepareContext(ctx, "INSERT INTO resources(addrid, aidx, data) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}
	defer insertResources.Close()

	var rows *sql.Rows
	rows, err = e.QueryContext(ctx, "SELECT address, data, normalizedonlinebalance FROM accountbase ORDER BY address")
	if err != nil {
		return err
	}
	defer rows.Close()

	var insertRes sql.Result
	var rowID int64
	var rowsAffected int64
	var processedAccounts uint64
	var totalBaseAccounts uint64

	arw := NewAccountsSQLReaderWriter(e)
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
		var newAccountData trackerdb.BaseAccountData
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
		insertResourceCallback := func(ctx context.Context, rowID int64, cidx basics.CreatableIndex, rd *trackerdb.ResourcesData) error {
			var err0 error
			if rd != nil {
				encodedData := protocol.Encode(rd)
				_, err0 = insertResources.ExecContext(ctx, rowID, cidx, encodedData)
			}
			return err0
		}
		err = trackerdb.AccountDataResources(ctx, &accountData, rowID, insertResourceCallback)
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
		_, err = e.Exec(stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

func performTxTailTableMigration(ctx context.Context, e db.Executable, blockDb db.Accessor) (err error) {
	if e == nil {
		return nil
	}

	arw := NewAccountsSQLReaderWriter(e)
	dbRound, err := arw.AccountsRound()
	if err != nil {
		return fmt.Errorf("latest block number cannot be retrieved : %w", err)
	}

	// load the latest MaxTxnLife rounds in the txtail and store these in the txtail.
	// when migrating there is only MaxTxnLife blocks in the block DB
	// since the original txTail.commmittedUpTo preserved only (rnd+1)-MaxTxnLife = 1000 blocks back
	err = blockDb.Atomic(func(ctx context.Context, blockTx *sql.Tx) error {
		latestBlockRound, blockErr := blockdb.BlockLatest(blockTx)
		if blockErr != nil {
			return fmt.Errorf("latest block number cannot be retrieved : %w", blockErr)
		}
		latestHdr, hdrErr := blockdb.BlockGetHdr(blockTx, dbRound)
		if hdrErr != nil {
			return fmt.Errorf("latest block header %d cannot be retrieved : %w", dbRound, hdrErr)
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
		if _, getErr := blockdb.BlockGet(blockTx, firstRound); getErr != nil {
			// looks like not catchpoint but a regular migration, start from maxTxnLife + deeperBlockHistory back
			firstRound = (latestBlockRound + 1).SubSaturate(maxTxnLife + deeperBlockHistory)
			if firstRound == basics.Round(0) {
				firstRound++
			}
		}
		tailRounds := make([][]byte, 0, maxTxnLife)
		for rnd := firstRound; rnd <= dbRound; rnd++ {
			blk, getErr := blockdb.BlockGet(blockTx, rnd)
			if getErr != nil {
				return fmt.Errorf("block for round %d ( %d - %d ) cannot be retrieved : %w", rnd, firstRound, dbRound, getErr)
			}

			tail, tErr := trackerdb.TxTailRoundFromBlock(blk)
			if tErr != nil {
				return tErr
			}

			encodedTail, _ := tail.Encode()
			tailRounds = append(tailRounds, encodedTail)
		}

		return arw.TxtailNewRound(ctx, firstRound, tailRounds, firstRound)
	})

	return err
}

func performOnlineRoundParamsTailMigration(ctx context.Context, e db.Executable, blockDb db.Accessor, newDatabase bool, initProto protocol.ConsensusVersion) (err error) {
	arw := NewAccountsSQLReaderWriter(e)
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
			hdr, hdrErr := blockdb.BlockGetHdr(blockTx, rnd)
			if hdrErr != nil {
				return hdrErr
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
	return arw.AccountsPutOnlineRoundParams(onlineRoundParams, rnd)
}

func performOnlineAccountsTableMigration(ctx context.Context, e db.Executable, progress func(processed, total uint64), log logging.Logger) (err error) {

	var insertOnlineAcct *sql.Stmt
	insertOnlineAcct, err = e.PrepareContext(ctx, "INSERT INTO onlineaccounts(address, data, normalizedonlinebalance, updround, votelastvalid) VALUES(?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer insertOnlineAcct.Close()

	var updateAcct *sql.Stmt
	updateAcct, err = e.PrepareContext(ctx, "UPDATE accountbase SET data = ? WHERE addrid = ?")
	if err != nil {
		return err
	}
	defer updateAcct.Close()

	var rows *sql.Rows
	rows, err = e.QueryContext(ctx, "SELECT addrid, address, data, normalizedonlinebalance FROM accountbase")
	if err != nil {
		return err
	}
	defer rows.Close()

	var insertRes sql.Result
	var updateRes sql.Result
	var rowsAffected int64
	var processedAccounts uint64
	var totalOnlineBaseAccounts uint64

	arw := NewAccountsSQLReaderWriter(e)
	totalOnlineBaseAccounts, err = arw.TotalAccounts(ctx)
	var total uint64
	err = e.QueryRowContext(ctx, "SELECT count(1) FROM accountbase").Scan(&total)
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
		old    trackerdb.BaseAccountData
		oldEnc []byte
		new    trackerdb.BaseAccountData
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
		var ba trackerdb.BaseAccountData
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
			var baseOnlineAD trackerdb.BaseOnlineAccountData
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

		// We had a bug that didn't remove StateProofIDs when going offline.
		// Tidy up such accounts.  We don't zero it out based on
		// `!basics.Online` because accounts can be suspended, in which case
		// they are Offline, but retain their voting material. But it remains
		// illegal to have a StateProofID without a SelectionID.
		if ba.SelectionID.IsEmpty() && !ba.StateProofID.IsEmpty() {
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
		err := e.QueryRow("SELECT count(1) FROM accounthashes").Scan(&count)
		if err != nil {
			return err
		}
		if count == 0 {
			// no account hashes, done
			return nil
		}

		mc, err := MakeMerkleCommitter(e, false)
		if err != nil {
			return nil
		}

		trie, err := merkletrie.MakeTrie(mc, trackerdb.TrieMemoryConfig)
		if err != nil {
			return fmt.Errorf("accountsInitialize was unable to MakeTrie: %v", err)
		}
		for addr, state := range acctRehash {
			deleteHash := trackerdb.AccountHashBuilderV6(addr, &state.old, state.oldEnc)
			deleted, delErr := trie.Delete(deleteHash)
			if delErr != nil {
				return fmt.Errorf("performOnlineAccountsTableMigration failed to delete hash '%s' from merkle trie for account %v: %w", hex.EncodeToString(deleteHash), addr, delErr)
			}
			if !deleted && log != nil {
				log.Warnf("performOnlineAccountsTableMigration failed to delete hash '%s' from merkle trie for account %v", hex.EncodeToString(deleteHash), addr)
			}

			addHash := trackerdb.AccountHashBuilderV6(addr, &state.new, state.newEnc)
			added, addErr := trie.Add(addHash)
			if addErr != nil {
				return fmt.Errorf("performOnlineAccountsTableMigration attempted to add duplicate hash '%s' to merkle trie for account %v: %w", hex.EncodeToString(addHash), addr, addErr)
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
func removeEmptyAccountData(tx db.Executable, queryAddresses bool) (num int64, addresses []basics.Address, err error) {
	if queryAddresses {
		rows, qErr := tx.Query("SELECT address FROM accountbase where length(data) = 1 and data = x'80'") // empty AccountData is 0x80
		if qErr != nil {
			return 0, nil, qErr
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

// reencodeAccounts reads all the accounts in the accountbase table, decode and reencode the account data.
// if the account data is found to have a different encoding, it would update the encoded account on disk.
// on return, it returns the number of modified accounts as well as an error ( if we had any )
func reencodeAccounts(ctx context.Context, e db.Executable) (modifiedAccounts uint, err error) {
	modifiedAccounts = 0
	scannedAccounts := 0

	updateStmt, err := e.PrepareContext(ctx, "UPDATE accountbase SET data = ? WHERE address = ?")
	if err != nil {
		return 0, err
	}

	rows, err := e.QueryContext(ctx, "SELECT address, data FROM accountbase")
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
			_, err = db.ResetTransactionWarnDeadline(ctx, e, time.Now().Add(time.Second))
			if err != nil {
				return
			}
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
		result, rowsErr := updateStmt.ExecContext(ctx, reencodedAccountData, addrbuf)
		if rowsErr != nil {
			return 0, rowsErr
		}
		rowsUpdated, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return 0, rowsErr
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

func convertOnlineRoundParamsTail(ctx context.Context, e db.Executable) error {
	// create vote last index
	_, err := e.ExecContext(ctx, createVoteLastValidIndex)
	return err
}

func accountsAddCreatableTypeColumn(ctx context.Context, e db.Executable, populateColumn bool) error {
	// Run ctype resources migration if it hasn't run yet
	var creatableTypeOnResourcesRun bool
	err := e.QueryRow("SELECT 1 FROM pragma_table_info('resources') WHERE name='ctype'").Scan(&creatableTypeOnResourcesRun)
	if err == nil {
		// Check if any ctypes are invalid
		var count uint64
		err0 := e.QueryRow("SELECT COUNT(*) FROM resources WHERE ctype NOT IN (0, 1)").Scan(&count)
		if err0 != nil {
			return err0
		}
		if count > 0 {
			// Invalid ctypes found, return an error
			return fmt.Errorf("invalid ctypes found in resources table; database is corrupted and needs to be rebuilt")
		}
		// Column exists, no ctypes are invalid, no migration needed so return clean
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	} // A sql.ErrNoRows error means the column does not exist, so we need to create it/run the migration

	// If we reached here, a sql.ErrNoRows error was returned, so we need to create the column

	// Add ctype column
	createStmt := `ALTER TABLE resources ADD COLUMN ctype INTEGER NOT NULL DEFAULT -1`

	_, err = e.ExecContext(ctx, createStmt)
	if err != nil {
		return err
	}

	if populateColumn {
		// Populate the new ctype column with the corresponding creatable type from assetcreators where available
		updateStmt := `UPDATE resources SET ctype = (
    SELECT COALESCE((SELECT ac.ctype FROM assetcreators ac WHERE ac.asset = resources.aidx),-1)
	) WHERE ctype = -1`

		_, err0 := e.ExecContext(ctx, updateStmt)
		if err0 != nil {
			return err0
		}

		updatePrepStmt, err0 := e.PrepareContext(ctx, "UPDATE resources SET ctype = ? WHERE addrid = ? AND aidx = ?")
		if err0 != nil {
			return err0
		}
		defer updatePrepStmt.Close()

		// Pull resource entries into memory where ctype is not set
		rows, err0 := e.QueryContext(ctx, "SELECT addrid, aidx, data FROM resources r WHERE ctype = -1")
		if err0 != nil {
			return err0
		}
		defer rows.Close()

		// Update the ctype column for subset of resources where ctype was not resolved from assetcreators
		for rows.Next() {
			var addrid int64
			var aidx int64
			var encodedData []byte
			err0 = rows.Scan(&addrid, &aidx, &encodedData)
			if err0 != nil {
				return err0
			}

			var rd trackerdb.ResourcesData
			err0 = protocol.Decode(encodedData, &rd)
			if err0 != nil {
				return err0
			}

			var ct basics.CreatableType
			if rd.IsAsset() && rd.IsApp() {
				// This should never happen!
				return fmt.Errorf("unable to discern creatable type for addrid %d, resource %d", addrid, aidx)
			} else if rd.IsAsset() {
				ct = basics.AssetCreatable
			} else if rd.IsApp() {
				ct = basics.AppCreatable
			} else { // This should never happen!
				return fmt.Errorf("unable to discern creatable type for addrid %d, resource %d", addrid, aidx)
			}

			_, err0 = updatePrepStmt.ExecContext(ctx, ct, addrid, aidx)
			if err0 != nil {
				return err0
			}
		}

		return rows.Err()
	}

	return nil
}
