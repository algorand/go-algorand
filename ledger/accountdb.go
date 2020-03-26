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

	"github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// accountsDbQueries is used to cache a prepared SQL statement to look up
// the state of a single account.
type accountsDbQueries struct {
	listAssetsStmt         *sql.Stmt
	lookupStmt             *sql.Stmt
	lookupAssetCreatorStmt *sql.Stmt
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
		filesize size NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS accounthashes (
			id integer primary key,
			data blob)`,
	`CREATE TABLE IF NOT EXISTS catchpointstate (
			id string primary key,
			intval integer,
			strval text)`,
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

type accountDelta struct {
	old basics.AccountData
	new basics.AccountData
}

func resetCatchpointStagingBalances(ctx context.Context, tx *sql.Tx) (err error) {
	s := "DROP TABLE IF EXISTS catchpointbalances;"
	s += "CREATE TABLE IF NOT EXISTS catchpointbalances(address blob primary key, data blob);"
	_, err = tx.Exec(s)
	return err
}

func readCatchpointStateUint64(ctx context.Context, tx *sql.Tx, stateName string) (rnd uint64, def bool, err error) {
	var val sql.NullInt64
	err = tx.QueryRowContext(ctx, "SELECT intval FROM catchpointstate WHERE id=?", stateName).Scan(&val)
	if err == sql.ErrNoRows || false == val.Valid {
		rnd = 0 // default to zero.
		err = nil
		def = true
		return
	}
	if err == nil {
		rnd = uint64(val.Int64)
	}
	return
}

func writeCatchpointStateUint64(ctx context.Context, tx *sql.Tx, stateName string, setValue uint64) (cleared bool, err error) {
	if setValue == 0 {
		_, err = tx.Exec("DELETE FROM catchpointstate WHERE id=?", stateName)
		return true, err
	}

	// we don't know if there is an entry in the table for this state, so we'll insert/replace it just in case.
	_, err = tx.Exec("INSERT OR REPLACE INTO catchpointstate(id, intval) VALUES(?, ?)", stateName, setValue)
	return false, err
}

func readCatchpointStateString(ctx context.Context, tx *sql.Tx, stateName string) (str string, def bool, err error) {
	var val sql.NullString
	err = tx.QueryRowContext(ctx, "SELECT strval FROM catchpointstate WHERE id=?", stateName).Scan(&val)
	if err == sql.ErrNoRows || false == val.Valid {
		str = "" // default to empty string
		err = nil
		def = true
		return
	}
	if err == nil {
		str = val.String
	}
	return
}

func writeCatchpointStateString(ctx context.Context, tx *sql.Tx, stateName string, setValue string) (cleared bool, err error) {
	if setValue == "" {
		_, err = tx.Exec("DELETE FROM catchpointstate WHERE id=?", stateName)
		return true, err
	}

	// we don't know if there is an entry in the table for this state, so we'll insert/replace it just in case.
	_, err = tx.Exec("INSERT OR REPLACE INTO catchpointstate(id, strval) VALUES(?, ?)", stateName, setValue)
	return false, err
}

func (cp *catchpointTracker) databaseSize(tx *sql.Tx) (size uint64, err error) {
	err = tx.QueryRow("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()").Scan(&size)
	return
}

func (cp *catchpointTracker) storeCatchpoint(tx *sql.Tx, round basics.Round, fileName string, catchpoint string, fileSize int64) (err error) {
	_, err = tx.Exec("DELETE FROM storedcatchpoints WHERE round=?", round)

	if err != nil {
		return
	}

	_, err = tx.Exec("INSERT INTO storedcatchpoints(round, filename, catchpoint, filesize) VALUES(?, ?, ?, ?)", round, fileName, catchpoint, fileSize)
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

	_, err := tx.Exec("INSERT INTO acctrounds (id, rnd) VALUES ('acctbase', 0)")
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

	qs.listAssetsStmt, err = q.Prepare("SELECT asset, creator FROM assetcreators WHERE asset <= ? ORDER BY asset desc LIMIT ?")
	if err != nil {
		return nil, err
	}

	qs.lookupStmt, err = q.Prepare("SELECT data FROM accountbase WHERE address=?")
	if err != nil {
		return nil, err
	}

	qs.lookupAssetCreatorStmt, err = q.Prepare("SELECT creator FROM assetcreators WHERE asset=?")
	if err != nil {
		return nil, err
	}

	return qs, nil
}

func (qs *accountsDbQueries) listAssets(maxAssetIdx basics.AssetIndex, maxResults uint64) (results []basics.AssetLocator, err error) {
	err = db.Retry(func() error {
		// Query for assets in range
		rows, err := qs.listAssetsStmt.Query(maxAssetIdx, maxResults)
		if err != nil {
			return err
		}
		defer rows.Close()

		// For each row, copy into a new AssetLocator and append to results
		var buf []byte
		var al basics.AssetLocator
		for rows.Next() {
			err := rows.Scan(&al.Index, &buf)
			if err != nil {
				return err
			}
			copy(al.Creator[:], buf)
			results = append(results, al)
		}
		return nil
	})
	return
}

func (qs *accountsDbQueries) lookupAssetCreator(assetIdx basics.AssetIndex) (addr basics.Address, err error) {
	err = db.Retry(func() error {
		var buf []byte
		err := qs.lookupAssetCreatorStmt.QueryRow(assetIdx).Scan(&buf)

		if err == sql.ErrNoRows {
			err = fmt.Errorf("asset %d does not exist or has been deleted", assetIdx)
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

// getChangedAssetIndices takes an accountDelta and returns which AssetIndices
// were created and which were deleted
func getChangedAssetIndices(creator basics.Address, delta accountDelta) map[basics.AssetIndex]modifiedAsset {
	assetMods := make(map[basics.AssetIndex]modifiedAsset)

	// Get assets that were created
	for idx := range delta.new.AssetParams {
		// AssetParams are in now the balance record now, but _weren't_ before
		if _, ok := delta.old.AssetParams[idx]; !ok {
			assetMods[idx] = modifiedAsset{
				created: true,
				creator: creator,
			}
		}
	}

	// Get assets that were deleted
	for idx := range delta.old.AssetParams {
		// AssetParams were in the balance record, but _aren't_ anymore
		if _, ok := delta.new.AssetParams[idx]; !ok {
			assetMods[idx] = modifiedAsset{
				created: false,
				creator: creator,
			}
		}
	}

	return assetMods
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

	insertAssetIdxStmt, err := tx.Prepare("INSERT INTO assetcreators (asset, creator) VALUES (?, ?)")
	if err != nil {
		return
	}
	defer insertAssetIdxStmt.Close()

	deleteAssetIdxStmt, err := tx.Prepare("DELETE FROM assetcreators WHERE asset=?")
	if err != nil {
		return
	}
	defer deleteAssetIdxStmt.Close()

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

		adeltas := getChangedAssetIndices(addr, data)
		for aidx, delta := range adeltas {
			if delta.created {
				_, err = insertAssetIdxStmt.Exec(aidx, addr[:])
			} else {
				_, err = deleteAssetIdxStmt.Exec(aidx)
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

func encodedAccountsRange(tx *sql.Tx, startAccountIndex, accountCount int) (bals []encodedBalanceRecord, err error) {
	rows, err := tx.Query("SELECT address, data FROM accountbase LIMIT ? OFFSET ?", accountCount, startAccountIndex)
	if err != nil {
		return
	}
	defer rows.Close()

	bals = make([]encodedBalanceRecord, 0, accountCount)
	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		err = rows.Scan(&addrbuf, &buf)
		if err != nil {
			return
		}

		bals = append(bals, encodedBalanceRecord{Address: addrbuf, AccountData: buf})
	}

	err = rows.Err()
	return
}

func totalAccounts(ctx context.Context, tx *sql.Tx) (total uint64, err error) {
	err = tx.QueryRowContext(ctx, "SELECT count(*) FROM accountbase").Scan(&total)
	if err == sql.ErrNoRows {
		total = 0
		err = nil
		return
	}
	return
}

const (
	merkleCommitterNodesPerPage = 128
)

type merkleCommitter struct {
	tx *sql.Tx
}

// StorePage stores a single page in an in-memory persistence.
func (mc *merkleCommitter) StorePage(page uint64, content []byte) error {
	if len(content) == 0 {
		_, err := mc.tx.Exec("DELETE FROM accounthashes WHERE id=?", page)
		return err
	}
	_, err := mc.tx.Exec("INSERT OR REPLACE INTO accounthashes(id, data) VALUES(?, ?)", page, content)
	return err
}

// LoadPage load a single page from an in-memory persistence.
func (mc *merkleCommitter) LoadPage(page uint64) (content []byte, err error) {
	err = mc.tx.QueryRow("SELECT data FROM accounthashes WHERE id = ?", page).Scan(&content)
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
