// Copyright (C) 2019-2023 Algorand, Inc.
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
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/util/db"
	"github.com/mattn/go-sqlite3"
)

type catchpointWriter struct {
	e        db.Executable
	isShared bool
}

// MakeCatchpointApplier creates a Catchpoint SQL reader+writer
func MakeCatchpointApplier(e db.Executable, isShared bool) trackerdb.CatchpointApply {
	return &catchpointWriter{e, isShared}
}

// Write implements trackerdb.CatchpointApply
func (c *catchpointWriter) Write(ctx context.Context, payload trackerdb.CatchpointPayload) (trackerdb.CatchpointReport, error) {
	wg := sync.WaitGroup{}

	var report trackerdb.CatchpointReport

	var errBalances error
	var errCreatables error
	var errHashes error
	var errKVs error

	// start the balances writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		errBalances = c.writeCatchpointStagingBalances(ctx, payload.Accounts)
		report.BalancesWriteDuration = time.Since(start)
	}()

	// on a in-memory database, wait for the writer to finish before starting the new writer
	if c.isShared {
		wg.Wait()
	}

	// starts the creatables writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		hasCreatables := false
		for _, accBal := range payload.Accounts {
			for _, res := range accBal.Resources {
				if res.IsOwning() {
					hasCreatables = true
					break
				}
			}
		}
		if hasCreatables {
			start := time.Now()
			errCreatables = c.writeCatchpointStagingCreatable(ctx, payload.Accounts)
			report.CreatablesWriteDuration = time.Since(start)
		}
	}()

	// on a in-memory database, wait for the writer to finish before starting the new writer
	if c.isShared {
		wg.Wait()
	}

	// start the accounts pending hashes writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		errHashes = c.writeCatchpointStagingHashes(ctx, payload.Accounts)
		report.HashesWriteDuration = time.Since(start)
	}()

	// on a in-memory database, wait for the writer to finish before starting the new writer
	if c.isShared {
		wg.Wait()
	}

	// start the kv store writer
	wg.Add(1)
	go func() {
		defer wg.Done()

		start := time.Now()
		keys := make([][]byte, len(payload.KVRecords))
		values := make([][]byte, len(payload.KVRecords))
		hashes := make([][]byte, len(payload.KVRecords))
		for i := 0; i < len(payload.KVRecords); i++ {
			keys[i] = payload.KVRecords[i].Key
			values[i] = payload.KVRecords[i].Value
			hashes[i] = trackerdb.KvHashBuilderV6(string(keys[i]), values[i])
		}
		errKVs = c.writeCatchpointStagingKVs(ctx, keys, values, hashes)
		report.KVWriteDuration = time.Since(start)
	}()

	wg.Wait()

	if errBalances != nil {
		return report, errBalances
	}
	if errCreatables != nil {
		return report, errCreatables
	}
	if errHashes != nil {
		return report, errHashes
	}
	if errKVs != nil {
		return report, errKVs
	}

	return report, nil
}

// WriteCatchpointStagingBalances inserts all the account balances in the provided array into the catchpoint balance staging table catchpointbalances.
func (cw *catchpointWriter) writeCatchpointStagingBalances(ctx context.Context, bals []trackerdb.NormalizedAccountBalance) error {
	selectAcctStmt, err := cw.e.PrepareContext(ctx, "SELECT rowid FROM catchpointbalances WHERE address = ?")
	if err != nil {
		return err
	}

	insertAcctStmt, err := cw.e.PrepareContext(ctx, "INSERT INTO catchpointbalances(address, normalizedonlinebalance, data) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}

	insertRscStmt, err := cw.e.PrepareContext(ctx, "INSERT INTO catchpointresources(addrid, aidx, data) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}

	var result sql.Result
	var rowID int64
	for _, balance := range bals {
		result, err = insertAcctStmt.ExecContext(ctx, balance.Address[:], balance.NormalizedBalance, balance.EncodedAccountData)
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
				err = selectAcctStmt.QueryRowContext(ctx, balance.Address[:]).Scan(&rowID)
				if err != nil {
					return err
				}
			} else {
				return err
			}
		}

		// write resources
		for aidx := range balance.Resources {
			var result sql.Result
			result, err = insertRscStmt.ExecContext(ctx, rowID, aidx, balance.EncodedResources[aidx])
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

// WriteCatchpointStagingHashes inserts all the account hashes in the provided array into the catchpoint pending hashes table catchpointpendinghashes.
func (cw *catchpointWriter) writeCatchpointStagingHashes(ctx context.Context, bals []trackerdb.NormalizedAccountBalance) error {
	insertStmt, err := cw.e.PrepareContext(ctx, "INSERT INTO catchpointpendinghashes(data) VALUES(?)")
	if err != nil {
		return err
	}

	for _, balance := range bals {
		for _, hash := range balance.AccountHashes {
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

// WriteCatchpointStagingCreatable inserts all the creatables in the provided array into the catchpoint asset creator staging table catchpointassetcreators.
// note that we cannot insert the resources here : in order to insert the resources, we need the rowid of the accountbase entry. This is being inserted by
// writeCatchpointStagingBalances via a separate go-routine.
func (cw *catchpointWriter) writeCatchpointStagingCreatable(ctx context.Context, bals []trackerdb.NormalizedAccountBalance) error {
	var insertCreatorsStmt *sql.Stmt
	var err error
	insertCreatorsStmt, err = cw.e.PrepareContext(ctx, "INSERT INTO catchpointassetcreators(asset, creator, ctype) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}
	defer insertCreatorsStmt.Close()

	for _, balance := range bals {
		for aidx, resData := range balance.Resources {
			if resData.IsOwning() {
				// determine if it's an asset
				if resData.IsAsset() {
					_, err := insertCreatorsStmt.ExecContext(ctx, aidx, balance.Address[:], basics.AssetCreatable)
					if err != nil {
						return err
					}
				}
				// determine if it's an application
				if resData.IsApp() {
					_, err := insertCreatorsStmt.ExecContext(ctx, aidx, balance.Address[:], basics.AppCreatable)
					if err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// WriteCatchpointStagingKVs inserts all the KVs in the provided array into the
// catchpoint kvstore staging table catchpointkvstore, and their hashes to the pending
func (cw *catchpointWriter) writeCatchpointStagingKVs(ctx context.Context, keys [][]byte, values [][]byte, hashes [][]byte) error {
	insertKV, err := cw.e.PrepareContext(ctx, "INSERT INTO catchpointkvstore(key, value) VALUES(?, ?)")
	if err != nil {
		return err
	}
	defer insertKV.Close()

	insertHash, err := cw.e.PrepareContext(ctx, "INSERT INTO catchpointpendinghashes(data) VALUES(?)")
	if err != nil {
		return err
	}
	defer insertHash.Close()

	for i := 0; i < len(keys); i++ {
		_, err := insertKV.ExecContext(ctx, keys[i], values[i])
		if err != nil {
			return err
		}

		_, err = insertHash.ExecContext(ctx, hashes[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func (cw *catchpointWriter) Reset(ctx context.Context, newCatchup bool) (err error) {
	s := []string{
		"DROP TABLE IF EXISTS catchpointbalances",
		"DROP TABLE IF EXISTS catchpointassetcreators",
		"DROP TABLE IF EXISTS catchpointaccounthashes",
		"DROP TABLE IF EXISTS catchpointpendinghashes",
		"DROP TABLE IF EXISTS catchpointresources",
		"DROP TABLE IF EXISTS catchpointkvstore",
		"DROP TABLE IF EXISTS catchpointstateproofverification",
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
			"CREATE TABLE IF NOT EXISTS catchpointstateproofverification (lastattestedround INTEGER PRIMARY KEY NOT NULL, verificationContext BLOB NOT NULL)",

			createNormalizedOnlineBalanceIndex(idxnameBalances, "catchpointbalances"), // should this be removed ?
			createUniqueAddressBalanceIndex(idxnameAddress, "catchpointbalances"),
			"CREATE INDEX IF NOT EXISTS catchpointpendinghashesidx ON catchpointpendinghashes(data)",
		)
	}

	for _, stmt := range s {
		_, err = cw.e.Exec(stmt)
		if err != nil {
			return err
		}
	}

	return nil
}

// ApplyCatchpointStagingBalances switches the staged catchpoint catchup tables onto the actual
// tables and update the correct balance round. This is the final step in switching onto the new catchpoint round.
func (cw *catchpointWriter) Apply(ctx context.Context, balancesRound basics.Round, merkleRootRound basics.Round) (err error) {
	stmts := []string{
		"DROP TABLE IF EXISTS accountbase",
		"DROP TABLE IF EXISTS assetcreators",
		"DROP TABLE IF EXISTS accounthashes",
		"DROP TABLE IF EXISTS resources",
		"DROP TABLE IF EXISTS kvstore",
		"DROP TABLE IF EXISTS stateproofverification",

		"ALTER TABLE catchpointbalances RENAME TO accountbase",
		"ALTER TABLE catchpointassetcreators RENAME TO assetcreators",
		"ALTER TABLE catchpointaccounthashes RENAME TO accounthashes",
		"ALTER TABLE catchpointresources RENAME TO resources",
		"ALTER TABLE catchpointkvstore RENAME TO kvstore",
		"ALTER TABLE catchpointstateproofverification RENAME TO stateproofverification",
	}

	for _, stmt := range stmts {
		_, err = cw.e.Exec(stmt)
		if err != nil {
			return err
		}
	}

	_, err = cw.e.Exec("INSERT OR REPLACE INTO acctrounds(id, rnd) VALUES('acctbase', ?)", balancesRound)
	if err != nil {
		return err
	}

	_, err = cw.e.Exec("INSERT OR REPLACE INTO acctrounds(id, rnd) VALUES('hashbase', ?)", merkleRootRound)
	if err != nil {
		return err
	}

	return
}
