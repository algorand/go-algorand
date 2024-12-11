// Copyright (C) 2019-2024 Algorand, Inc.
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
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/encoded"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/mattn/go-sqlite3"
)

type catchpointReader struct {
	q db.Queryable
}

type catchpointWriter struct {
	e db.Executable
}

type catchpointReaderWriter struct {
	catchpointReader
	catchpointWriter
}

// NewCatchpointSQLReaderWriter creates a Catchpoint SQL reader+writer
func NewCatchpointSQLReaderWriter(e db.Executable) *catchpointReaderWriter {
	return &catchpointReaderWriter{
		catchpointReader{q: e},
		catchpointWriter{e: e},
	}
}

func makeCatchpointReader(e db.Queryable) trackerdb.CatchpointReader {
	return &catchpointReader{q: e}
}

func (cr *catchpointReader) GetCatchpoint(ctx context.Context, round basics.Round) (fileName string, catchpoint string, fileSize int64, err error) {
	err = cr.q.QueryRowContext(ctx, "SELECT filename, catchpoint, filesize FROM storedcatchpoints WHERE round=?", int64(round)).Scan(&fileName, &catchpoint, &fileSize)
	return
}

func (cr *catchpointReader) GetOldestCatchpointFiles(ctx context.Context, fileCount int, filesToKeep int) (fileNames map[basics.Round]string, err error) {
	err = db.Retry(func() (err error) {
		query := "SELECT round, filename FROM storedcatchpoints WHERE pinned = 0 and round <= COALESCE((SELECT round FROM storedcatchpoints WHERE pinned = 0 ORDER BY round DESC LIMIT ?, 1),0) ORDER BY round ASC LIMIT ?"
		rows, err := cr.q.QueryContext(ctx, query, filesToKeep, fileCount)
		if err != nil {
			return err
		}
		defer rows.Close()

		fileNames = make(map[basics.Round]string)
		for rows.Next() {
			var fileName string
			var round basics.Round
			err = rows.Scan(&round, &fileName)
			if err != nil {
				return err
			}
			fileNames[round] = fileName
		}

		return rows.Err()
	})
	if err != nil {
		fileNames = nil
	}
	return
}

func (cr *catchpointReader) ReadCatchpointStateUint64(ctx context.Context, stateName trackerdb.CatchpointState) (val uint64, err error) {
	err = db.Retry(func() (err error) {
		query := "SELECT intval FROM catchpointstate WHERE id=?"
		var v sql.NullInt64
		err = cr.q.QueryRowContext(ctx, query, stateName).Scan(&v)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		if v.Valid {
			val = uint64(v.Int64)
		}
		return nil
	})
	return val, err
}

func (cr *catchpointReader) ReadCatchpointStateString(ctx context.Context, stateName trackerdb.CatchpointState) (val string, err error) {
	err = db.Retry(func() (err error) {
		query := "SELECT strval FROM catchpointstate WHERE id=?"
		var v sql.NullString
		err = cr.q.QueryRowContext(ctx, query, stateName).Scan(&v)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}

		if v.Valid {
			val = v.String
		}
		return nil
	})
	return val, err
}

func (cr *catchpointReader) SelectUnfinishedCatchpoints(ctx context.Context) ([]trackerdb.UnfinishedCatchpointRecord, error) {
	var res []trackerdb.UnfinishedCatchpointRecord

	f := func() error {
		query := "SELECT round, blockhash FROM unfinishedcatchpoints ORDER BY round"
		rows, err := cr.q.QueryContext(ctx, query)
		if err != nil {
			return err
		}

		// Clear `res` in case this function is repeated.
		res = res[:0]
		for rows.Next() {
			var record trackerdb.UnfinishedCatchpointRecord
			var blockHash []byte
			err = rows.Scan(&record.Round, &blockHash)
			if err != nil {
				return err
			}
			copy(record.BlockHash[:], blockHash)
			res = append(res, record)
		}

		return nil
	}
	err := db.Retry(f)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (cr *catchpointReader) SelectCatchpointFirstStageInfo(ctx context.Context, round basics.Round) (trackerdb.CatchpointFirstStageInfo, bool /*exists*/, error) {
	var data []byte
	f := func() error {
		query := "SELECT info FROM catchpointfirststageinfo WHERE round=?"
		err := cr.q.QueryRowContext(ctx, query, round).Scan(&data)
		if err == sql.ErrNoRows {
			data = nil
			return nil
		}
		return err
	}
	err := db.Retry(f)
	if err != nil {
		return trackerdb.CatchpointFirstStageInfo{}, false, err
	}

	if data == nil {
		return trackerdb.CatchpointFirstStageInfo{}, false, nil
	}

	var res trackerdb.CatchpointFirstStageInfo
	err = protocol.Decode(data, &res)
	if err != nil {
		return trackerdb.CatchpointFirstStageInfo{}, false, err
	}

	return res, true, nil
}

func (cr *catchpointReader) SelectOldCatchpointFirstStageInfoRounds(ctx context.Context, maxRound basics.Round) ([]basics.Round, error) {
	var res []basics.Round

	f := func() error {
		query := "SELECT round FROM catchpointfirststageinfo WHERE round <= ?"
		rows, err := cr.q.QueryContext(ctx, query, maxRound)
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

func (cw *catchpointWriter) StoreCatchpoint(ctx context.Context, round basics.Round, fileName string, catchpoint string, fileSize int64) (err error) {
	err = db.Retry(func() (err error) {
		query := "DELETE FROM storedcatchpoints WHERE round=?"
		_, err = cw.e.ExecContext(ctx, query, round)
		if err != nil || (fileName == "" && catchpoint == "" && fileSize == 0) {
			return err
		}

		query = "INSERT INTO storedcatchpoints(round, filename, catchpoint, filesize, pinned) VALUES(?, ?, ?, ?, 0)"
		_, err = cw.e.ExecContext(ctx, query, round, fileName, catchpoint, fileSize)
		return err
	})
	return
}

func (cw *catchpointWriter) WriteCatchpointStateUint64(ctx context.Context, stateName trackerdb.CatchpointState, setValue uint64) (err error) {
	err = db.Retry(func() (err error) {
		if setValue == 0 {
			return deleteCatchpointStateImpl(ctx, cw.e, stateName)
		}

		// we don't know if there is an entry in the table for this state, so we'll insert/replace it just in case.
		query := "INSERT OR REPLACE INTO catchpointstate(id, intval) VALUES(?, ?)"
		_, err = cw.e.ExecContext(ctx, query, stateName, setValue)
		return err
	})
	return err
}

func (cw *catchpointWriter) WriteCatchpointStateString(ctx context.Context, stateName trackerdb.CatchpointState, setValue string) (err error) {
	err = db.Retry(func() (err error) {
		if setValue == "" {
			return deleteCatchpointStateImpl(ctx, cw.e, stateName)
		}

		// we don't know if there is an entry in the table for this state, so we'll insert/replace it just in case.
		query := "INSERT OR REPLACE INTO catchpointstate(id, strval) VALUES(?, ?)"
		_, err = cw.e.ExecContext(ctx, query, stateName, setValue)
		return err
	})
	return err
}

func (cw *catchpointWriter) InsertUnfinishedCatchpoint(ctx context.Context, round basics.Round, blockHash crypto.Digest) error {
	f := func() error {
		query := "INSERT INTO unfinishedcatchpoints(round, blockhash) VALUES(?, ?)"
		_, err := cw.e.ExecContext(ctx, query, round, blockHash[:])
		return err
	}
	return db.Retry(f)
}

func (cw *catchpointWriter) DeleteUnfinishedCatchpoint(ctx context.Context, round basics.Round) error {
	f := func() error {
		query := "DELETE FROM unfinishedcatchpoints WHERE round = ?"
		_, err := cw.e.ExecContext(ctx, query, round)
		return err
	}
	return db.Retry(f)
}

func deleteCatchpointStateImpl(ctx context.Context, e db.Executable, stateName trackerdb.CatchpointState) error {
	query := "DELETE FROM catchpointstate WHERE id=?"
	_, err := e.ExecContext(ctx, query, stateName)
	return err
}

func (cw *catchpointWriter) InsertOrReplaceCatchpointFirstStageInfo(ctx context.Context, round basics.Round, info *trackerdb.CatchpointFirstStageInfo) error {
	infoSerialized := protocol.Encode(info)
	f := func() error {
		query := "INSERT OR REPLACE INTO catchpointfirststageinfo(round, info) VALUES(?, ?)"
		_, err := cw.e.ExecContext(ctx, query, round, infoSerialized)
		return err
	}
	return db.Retry(f)
}

func (cw *catchpointWriter) DeleteOldCatchpointFirstStageInfo(ctx context.Context, maxRoundToDelete basics.Round) error {
	f := func() error {
		query := "DELETE FROM catchpointfirststageinfo WHERE round <= ?"
		_, err := cw.e.ExecContext(ctx, query, maxRoundToDelete)
		return err
	}
	return db.Retry(f)
}

// WriteCatchpointStagingBalances inserts all the account balances in the provided array into the catchpoint balance staging table catchpointbalances.
func (cw *catchpointWriter) WriteCatchpointStagingBalances(ctx context.Context, bals []trackerdb.NormalizedAccountBalance) error {
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
func (cw *catchpointWriter) WriteCatchpointStagingHashes(ctx context.Context, bals []trackerdb.NormalizedAccountBalance) error {
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
func (cw *catchpointWriter) WriteCatchpointStagingCreatable(ctx context.Context, bals []trackerdb.NormalizedAccountBalance) error {
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
func (cw *catchpointWriter) WriteCatchpointStagingKVs(ctx context.Context, keys [][]byte, values [][]byte, hashes [][]byte) error {
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

// WriteCatchpointStagingOnlineAccounts inserts all the onlineaccounts in the provided array
// into the catchpoint staging table catchpointonlineaccounts, and their hashes to the pending
func (cw *catchpointWriter) WriteCatchpointStagingOnlineAccounts(ctx context.Context, oas []encoded.OnlineAccountRecordV6) error {
	insertStmt, err := cw.e.PrepareContext(ctx, "INSERT INTO catchpointonlineaccounts(address, updround, normalizedonlinebalance, votelastvalid, data) VALUES(?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer insertStmt.Close()

	for i := 0; i < len(oas); i++ {
		_, err := insertStmt.ExecContext(ctx, oas[i].Address[:], oas[i].UpdateRound, oas[i].NormalizedOnlineBalance, oas[i].VoteLastValid, oas[i].Data)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteCatchpointStagingOnlineRoundParams inserts all the online round params in the provided array
// into the catchpoint staging table catchpointonlineroundparamstail, and their hashes to the pending
func (cw *catchpointWriter) WriteCatchpointStagingOnlineRoundParams(ctx context.Context, orps []encoded.OnlineRoundParamsRecordV6) error {
	insertStmt, err := cw.e.PrepareContext(ctx, "INSERT INTO catchpointonlineroundparamstail(rnd, data) VALUES(?, ?)")
	if err != nil {
		return err
	}
	defer insertStmt.Close()

	for i := 0; i < len(orps); i++ {
		_, err := insertStmt.ExecContext(ctx, orps[i].Round, orps[i].Data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cw *catchpointWriter) ResetCatchpointStagingBalances(ctx context.Context, newCatchup bool) (err error) {
	s := []string{
		"DROP TABLE IF EXISTS catchpointbalances",
		"DROP TABLE IF EXISTS catchpointassetcreators",
		"DROP TABLE IF EXISTS catchpointaccounthashes",
		"DROP TABLE IF EXISTS catchpointpendinghashes",
		"DROP TABLE IF EXISTS catchpointresources",
		"DROP TABLE IF EXISTS catchpointkvstore",
		"DROP TABLE IF EXISTS catchpointonlineaccounts",
		"DROP TABLE IF EXISTS catchpointonlineroundparamstail",
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
		idxnameOnlineAccounts := fmt.Sprintf("onlineaccountnorm_idx_%d", now)

		s = append(s,
			"CREATE TABLE IF NOT EXISTS catchpointassetcreators (asset integer primary key, creator blob, ctype integer)",
			"CREATE TABLE IF NOT EXISTS catchpointbalances (addrid INTEGER PRIMARY KEY NOT NULL, address blob NOT NULL, data blob, normalizedonlinebalance INTEGER)",
			"CREATE TABLE IF NOT EXISTS catchpointpendinghashes (data blob)",
			"CREATE TABLE IF NOT EXISTS catchpointaccounthashes (id integer primary key, data blob)",
			"CREATE TABLE IF NOT EXISTS catchpointresources (addrid INTEGER NOT NULL, aidx INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (addrid, aidx) ) WITHOUT ROWID",
			"CREATE TABLE IF NOT EXISTS catchpointkvstore (key blob primary key, value blob)",
			"CREATE TABLE IF NOT EXISTS catchpointonlineaccounts (address BLOB NOT NULL, updround INTEGER NOT NULL, normalizedonlinebalance INTEGER NOT NULL, votelastvalid INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (address, updround) )",
			"CREATE TABLE IF NOT EXISTS catchpointonlineroundparamstail(rnd INTEGER NOT NULL PRIMARY KEY, data BLOB NOT NULL)",
			"CREATE TABLE IF NOT EXISTS catchpointstateproofverification (lastattestedround INTEGER PRIMARY KEY NOT NULL, verificationContext BLOB NOT NULL)",

			createNormalizedOnlineBalanceIndex(idxnameBalances, "catchpointbalances"), // should this be removed ?
			createUniqueAddressBalanceIndex(idxnameAddress, "catchpointbalances"),
			createNormalizedOnlineBalanceIndexOnline(idxnameOnlineAccounts, "catchpointonlineaccounts"),
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
func (cw *catchpointWriter) ApplyCatchpointStagingBalances(ctx context.Context, balancesRound basics.Round, merkleRootRound basics.Round) (err error) {
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

// ApplyCatchpointStagingTablesV7 drops the existing onlineaccounts and onlineroundparamstail tables,
// replacing them with data from the catchpoint staging tables. It should only be used for CatchpointFileVersionV8,
// after the ApplyCatchpointStagingBalances function has been run on DB v6, then upgraded to DB v7.
func (cw *catchpointWriter) ApplyCatchpointStagingTablesV7(ctx context.Context) (err error) {
	stmts := []string{
		"DROP TABLE IF EXISTS onlineaccounts",
		"DROP TABLE IF EXISTS onlineroundparamstail",
		"ALTER TABLE catchpointonlineaccounts RENAME TO onlineaccounts",
		"ALTER TABLE catchpointonlineroundparamstail RENAME TO onlineroundparamstail",
	}
	for _, stmt := range stmts {
		_, err = cw.e.Exec(stmt)
		if err != nil {
			return err
		}
	}
	return
}

// CreateCatchpointStagingHashesIndex creates an index on catchpointpendinghashes to allow faster scanning according to the hash order
func (cw *catchpointWriter) CreateCatchpointStagingHashesIndex(ctx context.Context) (err error) {
	_, err = cw.e.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS catchpointpendinghashesidx ON catchpointpendinghashes(data)")
	if err != nil {
		return
	}
	return
}

// DeleteStoredCatchpoints iterates over the storedcatchpoints table and deletes all the files stored on disk.
// once all the files have been deleted, it would go ahead and remove the entries from the table.
func (crw *catchpointReaderWriter) DeleteStoredCatchpoints(ctx context.Context, dbDirectory string) (err error) {
	catchpointsFilesChunkSize := 50
	for {
		fileNames, err := crw.GetOldestCatchpointFiles(ctx, catchpointsFilesChunkSize, 0)
		if err != nil {
			return err
		}
		if len(fileNames) == 0 {
			break
		}

		for round, fileName := range fileNames {
			err = trackerdb.RemoveSingleCatchpointFileFromDisk(dbDirectory, fileName)
			if err != nil {
				return err
			}
			// clear the entry from the database
			err = crw.StoreCatchpoint(ctx, round, "", "", 0)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
