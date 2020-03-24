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
	"database/sql"
	"fmt"

	"github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// accountsDbQueries is used to cache a prepared SQL statement to look up
// the state of a single account.
type accountsDbQueries struct {
	listCreatablesStmt *sql.Stmt
	lookupStmt         *sql.Stmt
	lookupCreatorStmt  *sql.Stmt
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
}

var creatablesMigration = []string{
	`ALTER TABLE assetcreators RENAME TO creatables`,
	`ALTER TABLE creatables RENAME COLUMN asset TO creatable`,
	`ALTER TABLE creatables ADD COLUMN ctype INTEGER DEFAULT 0`,
	`CREATE INDEX creatable_ctype_idx ON creatables (creatable, ctype)`,
}

var accountsResetExprs = []string{
	`DROP TABLE IF EXISTS acctrounds`,
	`DROP TABLE IF EXISTS accounttotals`,
	`DROP TABLE IF EXISTS accountbase`,
	`DROP TABLE IF EXISTS assetcreators`,
	`DROP TABLE IF EXISTS creatables`,
}

type accountDelta struct {
	old basics.AccountData
	new basics.AccountData
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
	err := tx.QueryRow("SELECT 1 FROM sqlite_master WHERE type='table' AND name='creatables'").Scan(&creatableMigrated)
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

		err = accountsPutTotals(tx, totals)
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

func accountsReset(tx *sql.Tx) error {
	for _, stmt := range accountsResetExprs {
		_, err := tx.Exec(stmt)
		if err != nil {
			return err
		}
	}
	return nil
}

func accountsRound(tx *sql.Tx) (rnd basics.Round, err error) {
	err = tx.QueryRow("SELECT rnd FROM acctrounds WHERE id='acctbase'").Scan(&rnd)
	return
}

func accountsDbInit(q db.Queryable) (*accountsDbQueries, error) {
	var err error
	qs := &accountsDbQueries{}

	qs.listCreatablesStmt, err = q.Prepare("SELECT creatable, creator, ctype FROM creatables WHERE creatable <= ? AND ctype = ? ORDER BY creatable desc LIMIT ?")
	if err != nil {
		return nil, err
	}

	qs.lookupStmt, err = q.Prepare("SELECT data FROM accountbase WHERE address=?")
	if err != nil {
		return nil, err
	}

	qs.lookupCreatorStmt, err = q.Prepare("SELECT creator FROM creatables WHERE creatable = ? AND ctype = ?")
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

		// For each row, copy into a new AssetLocator and append to results
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

func (qs *accountsDbQueries) lookupCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (addr basics.Address, doesNotExist bool, err error) {
	err = db.Retry(func() error {
		var buf []byte
		err := qs.lookupCreatorStmt.QueryRow(cidx, ctype).Scan(&buf)

		if err == sql.ErrNoRows {
			doesNotExist = true
			return nil
		}

		if err != nil {
			return err
		}
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

func accountsTotals(tx *sql.Tx) (totals AccountTotals, err error) {
	row := tx.QueryRow("SELECT online, onlinerewardunits, offline, offlinerewardunits, notparticipating, notparticipatingrewardunits, rewardslevel FROM accounttotals")
	err = row.Scan(&totals.Online.Money.Raw, &totals.Online.RewardUnits,
		&totals.Offline.Money.Raw, &totals.Offline.RewardUnits,
		&totals.NotParticipating.Money.Raw, &totals.NotParticipating.RewardUnits,
		&totals.RewardsLevel)

	return
}

func accountsPutTotals(tx *sql.Tx, totals AccountTotals) error {
	// The "id" field is there so that we can use a convenient REPLACE INTO statement
	_, err := tx.Exec("REPLACE INTO accounttotals (id, online, onlinerewardunits, offline, offlinerewardunits, notparticipating, notparticipatingrewardunits, rewardslevel) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		"",
		totals.Online.Money.Raw, totals.Online.RewardUnits,
		totals.Offline.Money.Raw, totals.Offline.RewardUnits,
		totals.NotParticipating.Money.Raw, totals.NotParticipating.RewardUnits,
		totals.RewardsLevel)
	return err
}

// getChangedCreatabless takes an accountDelta and returns which Creatables
// were created and which were deleted
func getChangedCreatables(creator basics.Address, delta accountDelta) map[basics.CreatableIndex]modifiedCreatable {
	mods := make(map[basics.CreatableIndex]modifiedCreatable)

	// Get assets that were created
	for idx := range delta.new.AssetParams {
		// AssetParams are in now the balance record now, but _weren't_ before
		if _, ok := delta.old.AssetParams[idx]; !ok {
			mods[basics.CreatableIndex(idx)] = modifiedCreatable{
				created: true,
				creator: creator,
				ctype:   basics.AssetCreatable,
			}
		}
	}

	// Get assets that were deleted
	for idx := range delta.old.AssetParams {
		// AssetParams were in the balance record, but _aren't_ anymore
		if _, ok := delta.new.AssetParams[idx]; !ok {
			mods[basics.CreatableIndex(idx)] = modifiedCreatable{
				created: false,
				creator: creator,
				ctype:   basics.AssetCreatable,
			}
		}
	}

	// Get apps that were created
	for idx := range delta.new.AppParams {
		// AppParams are in now the balance record now, but _weren't_ before
		if _, ok := delta.old.AppParams[idx]; !ok {
			mods[basics.CreatableIndex(idx)] = modifiedCreatable{
				created: true,
				creator: creator,
				ctype:   basics.AppCreatable,
			}
		}
	}

	// Get apps that were deleted
	for idx := range delta.old.AppParams {
		// AppParams were in the balance record, but _aren't_ anymore
		if _, ok := delta.new.AppParams[idx]; !ok {
			mods[basics.CreatableIndex(idx)] = modifiedCreatable{
				created: false,
				creator: creator,
				ctype:   basics.AppCreatable,
			}
		}
	}

	return mods
}

func accountsNewRound(tx *sql.Tx, rnd basics.Round, updates map[basics.Address]accountDelta, rewardsLevel uint64, proto config.ConsensusParams) (err error) {
	var base basics.Round
	err = tx.QueryRow("SELECT rnd FROM acctrounds WHERE id='acctbase'").Scan(&base)
	if err != nil {
		return
	}

	if rnd != base+1 {
		err = fmt.Errorf("newRound %d is not immediately after base %d", rnd, base)
		return
	}

	var ot basics.OverflowTracker
	totals, err := accountsTotals(tx)
	if err != nil {
		return
	}

	totals.applyRewards(rewardsLevel, &ot)

	deleteStmt, err := tx.Prepare("DELETE FROM accountbase WHERE address=?")
	if err != nil {
		return
	}
	defer deleteStmt.Close()

	replaceStmt, err := tx.Prepare("REPLACE INTO accountbase (address, data) VALUES (?, ?)")
	if err != nil {
		return
	}
	defer replaceStmt.Close()

	insertCreatableIdxStmt, err := tx.Prepare("INSERT INTO creatables (creatable, creator, ctype) VALUES (?, ?, ?)")
	if err != nil {
		return
	}
	defer insertCreatableIdxStmt.Close()

	deleteCreatableIdxStmt, err := tx.Prepare("DELETE FROM creatables WHERE creatable=? AND ctype=?")
	if err != nil {
		return
	}
	defer deleteCreatableIdxStmt.Close()

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

		totals.delAccount(proto, data.old, &ot)
		totals.addAccount(proto, data.new, &ot)

		cdeltas := getChangedCreatables(addr, data)
		for cidx, delta := range cdeltas {
			if delta.created {
				_, err = insertCreatableIdxStmt.Exec(cidx, addr[:], delta.ctype)
			} else {
				_, err = deleteCreatableIdxStmt.Exec(cidx, delta.ctype)
			}
			if err != nil {
				return
			}
		}
	}

	if ot.Overflowed {
		err = fmt.Errorf("overflow computing totals")
		return
	}

	res, err := tx.Exec("UPDATE acctrounds SET rnd=? WHERE id='acctbase'", rnd)
	if err != nil {
		return
	}

	aff, err := res.RowsAffected()
	if err != nil {
		return
	}

	if aff != 1 {
		err = fmt.Errorf("accountsNewRound: expected to update 1 row but got %d", aff)
		return
	}

	err = accountsPutTotals(tx, totals)
	if err != nil {
		return
	}

	return
}
