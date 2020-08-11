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
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// accountsDbQueries is used to cache a prepared SQL statement to look up
// the state of a single account.
type accountsDbQueries struct {
	listCreatablesStmt           *sql.Stmt
	lookupStmt                   *sql.Stmt
	lookupCreatorStmt            *sql.Stmt
	deleteStoredCatchpoint       *sql.Stmt
	insertStoredCatchpoint       *sql.Stmt
	selectOldestsCatchpointFiles *sql.Stmt
	selectCatchpointStateUint64  *sql.Stmt
	deleteCatchpointState        *sql.Stmt
	insertCatchpointStateUint64  *sql.Stmt
	selectCatchpointStateString  *sql.Stmt
	insertCatchpointStateString  *sql.Stmt
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

var accountsResetExprs = []string{
	`DROP TABLE IF EXISTS acctrounds`,
	`DROP TABLE IF EXISTS accounttotals`,
	`DROP TABLE IF EXISTS accountbase`,
	`DROP TABLE IF EXISTS assetcreators`,
	`DROP TABLE IF EXISTS storedcatchpoints`,
	`DROP TABLE IF EXISTS catchpointstate`,
	`DROP TABLE IF EXISTS accounthashes`,
}

// accountDBVersion is the database version that this binary would know how to support and how to upgrade to.
// details about the content of each of the versions can be found in the upgrade functions upgradeDatabaseSchemaXXXX
// and their descriptions.
var accountDBVersion = int32(2)

type accountDelta struct {
	old basics.AccountData
	new basics.AccountData
}

// catchpointState is used to store catchpoint related varaibles into the catchpointstate table.
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

func writeCatchpointStagingCreatable(ctx context.Context, tx *sql.Tx, addr basics.Address, cidx basics.CreatableIndex, ctype basics.CreatableType) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO catchpointassetcreators(asset, creator, ctype) VALUES(?, ?, ?)", cidx, addr[:], ctype)
	if err != nil {
		return err
	}
	return nil
}

func writeCatchpointStagingBalances(ctx context.Context, tx *sql.Tx, bals []encodedBalanceRecord) error {
	insertStmt, err := tx.PrepareContext(ctx, "INSERT INTO catchpointbalances(address, data) VALUES(?, ?)")
	if err != nil {
		return err
	}

	for _, balance := range bals {
		result, err := insertStmt.ExecContext(ctx, balance.Address[:], balance.AccountData)
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

func resetCatchpointStagingBalances(ctx context.Context, tx *sql.Tx, newCatchup bool) (err error) {
	s := "DROP TABLE IF EXISTS catchpointbalances;"
	s += "DROP TABLE IF EXISTS catchpointassetcreators;"
	s += "DROP TABLE IF EXISTS catchpointaccounthashes;"
	s += "DELETE FROM accounttotals where id='catchpointStaging';"
	if newCatchup {
		s += "CREATE TABLE IF NOT EXISTS catchpointassetcreators(asset integer primary key, creator blob, ctype integer);"
		s += "CREATE TABLE IF NOT EXISTS catchpointbalances(address blob primary key, data blob);"
		s += "CREATE TABLE IF NOT EXISTS catchpointaccounthashes(id integer primary key, data blob);"
	}
	_, err = tx.Exec(s)
	return err
}

// applyCatchpointStagingBalances switches the staged catchpoint catchup tables onto the actual
// tables and update the correct balance round. This is the final step in switching onto the new catchpoint round.
func applyCatchpointStagingBalances(ctx context.Context, tx *sql.Tx, balancesRound basics.Round) (err error) {
	s := "ALTER TABLE accountbase RENAME TO accountbase_old;"
	s += "ALTER TABLE assetcreators RENAME TO assetcreators_old;"
	s += "ALTER TABLE accounthashes RENAME TO accounthashes_old;"
	s += "ALTER TABLE catchpointbalances RENAME TO accountbase;"
	s += "ALTER TABLE catchpointassetcreators RENAME TO assetcreators;"
	s += "ALTER TABLE catchpointaccounthashes RENAME TO accounthashes;"
	s += "DROP TABLE IF EXISTS accountbase_old;"
	s += "DROP TABLE IF EXISTS assetcreators_old;"
	s += "DROP TABLE IF EXISTS accounthashes_old;"

	_, err = tx.Exec(s)
	if err != nil {
		return err
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
func accountsInit(tx *sql.Tx, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) error {
	for _, tableCreate := range accountsSchema {
		_, err := tx.Exec(tableCreate)
		if err != nil {
			return err
		}
	}

	// Run creatables migration if it hasn't run yet
	var creatableMigrated bool
	err := tx.QueryRow("SELECT 1 FROM pragma_table_info('assetcreators') WHERE name='ctype'").Scan(&creatableMigrated)
	if err == sql.ErrNoRows {
		// Run migration
		for _, migrateCmd := range creatablesMigration {
			_, err = tx.Exec(migrateCmd)
			if err != nil {
				return err
			}
		}
	} else if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT INTO acctrounds (id, rnd) VALUES ('acctbase', 0)")
	if err == nil {
		var ot basics.OverflowTracker
		var totals AccountTotals

		for addr, data := range initAccounts {
			_, err = tx.Exec("INSERT INTO accountbase (address, data) VALUES (?, ?)",
				addr[:], protocol.Encode(&data))
			if err != nil {
				return err
			}

			totals.addAccount(proto, data, &ot)
		}

		if ot.Overflowed {
			return fmt.Errorf("overflow computing totals")
		}

		err = accountsPutTotals(tx, totals, false)
		if err != nil {
			return err
		}
	} else {
		serr, ok := err.(sqlite3.Error)
		// serr.Code is sqlite.ErrConstraint if the database has already been initalized;
		// in that case, ignore the error and return nil.
		if !ok || serr.Code != sqlite3.ErrConstraint {
			return err
		}
	}

	return nil
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

func accountsDbInit(r db.Queryable, w db.Queryable) (*accountsDbQueries, error) {
	var err error
	qs := &accountsDbQueries{}

	qs.listCreatablesStmt, err = r.Prepare("SELECT asset, creator FROM assetcreators WHERE asset <= ? AND ctype = ? ORDER BY asset desc LIMIT ?")
	if err != nil {
		return nil, err
	}

	qs.lookupStmt, err = r.Prepare("SELECT data FROM accountbase WHERE address=?")
	if err != nil {
		return nil, err
	}

	qs.lookupCreatorStmt, err = r.Prepare("SELECT creator FROM assetcreators WHERE asset = ? AND ctype = ?")
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

	qs.selectOldestsCatchpointFiles, err = r.Prepare("SELECT round, filename FROM storedcatchpoints WHERE pinned = 0 and round <= COALESCE((SELECT round FROM storedcatchpoints WHERE pinned = 0 ORDER BY round DESC LIMIT ?, 1),0) ORDER BY round ASC LIMIT ?")
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
	return qs, nil
}

func (qs *accountsDbQueries) listCreatables(maxIdx basics.CreatableIndex, maxResults uint64, ctype basics.CreatableType) (results []basics.CreatableLocator, err error) {
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
		for rows.Next() {
			err := rows.Scan(&cl.Index, &buf)
			if err != nil {
				return err
			}
			copy(cl.Creator[:], buf)
			cl.Type = ctype
			results = append(results, cl)
		}
		return nil
	})
	return
}

func (qs *accountsDbQueries) lookupCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (addr basics.Address, ok bool, err error) {
	err = db.Retry(func() error {
		var buf []byte
		err := qs.lookupCreatorStmt.QueryRow(cidx, ctype).Scan(&buf)

		// Common error: creatable does not exist
		if err == sql.ErrNoRows {
			return nil
		}

		// Some other database error
		if err != nil {
			return err
		}

		ok = true
		copy(addr[:], buf)
		return nil
	})
	return
}

func (qs *accountsDbQueries) lookup(addr basics.Address) (data basics.AccountData, err error) {
	err = db.Retry(func() error {
		var buf []byte
		err := qs.lookupStmt.QueryRow(addr[:]).Scan(&buf)
		if err == nil {
			return protocol.Decode(buf, &data)
		}

		if err == sql.ErrNoRows {
			// Return the zero value of data
			return nil
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
		rows, err = qs.selectOldestsCatchpointFiles.QueryContext(ctx, filesToKeep, fileCount)
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
		&qs.deleteStoredCatchpoint,
		&qs.insertStoredCatchpoint,
		&qs.selectOldestsCatchpointFiles,
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

func accountsAll(tx *sql.Tx) (bals map[basics.Address]basics.AccountData, err error) {
	rows, err := tx.Query("SELECT address, data FROM accountbase")
	if err != nil {
		return
	}
	defer rows.Close()

	bals = make(map[basics.Address]basics.AccountData)
	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		err = rows.Scan(&addrbuf, &buf)
		if err != nil {
			return
		}

		var data basics.AccountData
		err = protocol.Decode(buf, &data)
		if err != nil {
			return
		}

		var addr basics.Address
		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("Account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return
		}

		copy(addr[:], addrbuf)
		bals[addr] = data
	}

	err = rows.Err()
	return
}

func accountsTotals(tx *sql.Tx, catchpointStaging bool) (totals AccountTotals, err error) {
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

func accountsPutTotals(tx *sql.Tx, totals AccountTotals, catchpointStaging bool) error {
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

// accountsNewRound updates the accountbase and assetcreators by applying the provided deltas to the accounts / creatables.
func accountsNewRound(tx *sql.Tx, updates map[basics.Address]accountDelta, creatables map[basics.CreatableIndex]modifiedCreatable) (err error) {

	var insertCreatableIdxStmt, deleteCreatableIdxStmt, deleteStmt, replaceStmt *sql.Stmt

	deleteStmt, err = tx.Prepare("DELETE FROM accountbase WHERE address=?")
	if err != nil {
		return
	}
	defer deleteStmt.Close()

	replaceStmt, err = tx.Prepare("REPLACE INTO accountbase (address, data) VALUES (?, ?)")
	if err != nil {
		return
	}
	defer replaceStmt.Close()

	for addr, data := range updates {
		if data.new.IsZero() {
			// prune empty accounts
			_, err = deleteStmt.Exec(addr[:])
		} else {
			_, err = replaceStmt.Exec(addr[:], protocol.Encode(&data.new))
		}
		if err != nil {
			return
		}

	}

	if len(creatables) > 0 {
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
			if cdelta.created {
				_, err = insertCreatableIdxStmt.Exec(cidx, cdelta.creator[:], cdelta.ctype)
			} else {
				_, err = deleteCreatableIdxStmt.Exec(cidx, cdelta.ctype)
			}
			if err != nil {
				return
			}
		}
	}

	return
}

// totalsNewRounds updates the accountsTotals by applying series of round changes
func totalsNewRounds(tx *sql.Tx, updates []map[basics.Address]accountDelta, accountTotals []AccountTotals, protos []config.ConsensusParams) (err error) {
	var ot basics.OverflowTracker
	totals, err := accountsTotals(tx, false)
	if err != nil {
		return
	}

	for i := 0; i < len(updates); i++ {
		totals.applyRewards(accountTotals[i].RewardsLevel, &ot)

		for _, data := range updates[i] {
			totals.delAccount(protos[i], data.old, &ot)
			totals.addAccount(protos[i], data.new, &ot)
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

// encodedAccountsRange returns an array containing the account data, in the same way it appear in the database
// starting at entry startAccountIndex, and up to accountCount accounts long.
func encodedAccountsRange(ctx context.Context, tx *sql.Tx, startAccountIndex, accountCount int) (bals []encodedBalanceRecord, err error) {
	rows, err := tx.QueryContext(ctx, "SELECT address, data FROM accountbase ORDER BY rowid LIMIT ? OFFSET ?", accountCount, startAccountIndex)
	if err != nil {
		return
	}
	defer rows.Close()

	bals = make([]encodedBalanceRecord, 0, accountCount)
	var addr basics.Address
	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		err = rows.Scan(&addrbuf, &buf)
		if err != nil {
			return
		}

		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("Account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return
		}

		copy(addr[:], addrbuf)

		bals = append(bals, encodedBalanceRecord{Address: addr, AccountData: buf})
	}

	err = rows.Err()
	if err == nil {
		// the encodedAccountsRange typically called in a loop iterating over all the accounts. This could clearly take more than the
		// "standard" 1 second, so we want to extend the timeout on each iteration. If the last iteration takes more than a second, then
		// it should be noted. The one second here is quite liberal to ensure symmetrical behaviour on low-power devices.
		// The return value from ResetTransactionWarnDeadline can be safely ignored here since it would only default to writing the warnning
		// message, which would let us know that it failed anyway.
		db.ResetTransactionWarnDeadline(ctx, tx, time.Now().Add(time.Second))
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
			// The return value from ResetTransactionWarnDeadline can be safely ignored here since it would only default to writing the warnning
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

// merkleCommitterNodesPerPage controls how many nodes will be stored in a single page
// value was calibrated using BenchmarkCalibrateNodesPerPage
var merkleCommitterNodesPerPage = int64(116)

type merkleCommitter struct {
	tx         *sql.Tx
	deleteStmt *sql.Stmt
	insertStmt *sql.Stmt
	selectStmt *sql.Stmt
}

func makeMerkleCommitter(tx *sql.Tx, staging bool) (mc *merkleCommitter, err error) {
	mc = &merkleCommitter{tx: tx}
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

// StorePage stores a single page in an in-memory persistence.
func (mc *merkleCommitter) StorePage(page uint64, content []byte) error {
	if len(content) == 0 {
		_, err := mc.deleteStmt.Exec(page)
		return err
	}
	_, err := mc.insertStmt.Exec(page, content)
	return err
}

// LoadPage load a single page from an in-memory persistence.
func (mc *merkleCommitter) LoadPage(page uint64) (content []byte, err error) {
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

// GetNodesCountPerPage returns the page size ( number of nodes per page )
func (mc *merkleCommitter) GetNodesCountPerPage() (pageSize int64) {
	return merkleCommitterNodesPerPage
}
