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
	"database/sql"
	"fmt"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// accountsDbQueries is used to cache a prepared SQL statement to look up
// the state of a single account.
type accountsDbQueries struct {
	lookupAccountStmt          *sql.Stmt
	lookupResourcesStmt        *sql.Stmt
	lookupAllResourcesStmt     *sql.Stmt
	lookupLimitedResourcesStmt *sql.Stmt
	lookupKvPairStmt           *sql.Stmt
	lookupKeysByRangeStmt      *sql.Stmt
	lookupCreatorStmt          *sql.Stmt
}

type onlineAccountsDbQueries struct {
	lookupOnlineStmt        *sql.Stmt
	lookupOnlineHistoryStmt *sql.Stmt
	lookupOnlineTotalsStmt  *sql.Stmt
}

type accountsSQLWriter struct {
	insertCreatableIdxStmt, deleteCreatableIdxStmt             *sql.Stmt
	deleteByRowIDStmt, insertStmt, updateStmt                  *sql.Stmt
	deleteResourceStmt, insertResourceStmt, updateResourceStmt *sql.Stmt
	deleteKvPairStmt, upsertKvPairStmt                         *sql.Stmt
}

type onlineAccountsSQLWriter struct {
	insertStmt *sql.Stmt
}

type sqlRowRef struct {
	rowid int64
}

func (sqlRowRef) AccountRefMarker() {}
func (ref sqlRowRef) String() string {
	return fmt.Sprintf("sqlRowRef{%d}", ref.rowid)
}
func (sqlRowRef) OnlineAccountRefMarker() {}
func (sqlRowRef) ResourceRefMarker()      {}
func (sqlRowRef) CreatableRefMarker()     {}

// AccountsInitDbQueries constructs an AccountsReader backed by sql queries.
func AccountsInitDbQueries(q db.Queryable) (*accountsDbQueries, error) {
	var err error
	qs := &accountsDbQueries{}

	qs.lookupAccountStmt, err = q.Prepare("SELECT accountbase.rowid, acctrounds.rnd, accountbase.data FROM acctrounds LEFT JOIN accountbase ON address=? WHERE id='acctbase'")
	if err != nil {
		return nil, err
	}

	qs.lookupResourcesStmt, err = q.Prepare("SELECT accountbase.rowid, acctrounds.rnd, resources.data FROM acctrounds LEFT JOIN accountbase ON accountbase.address = ? LEFT JOIN resources ON accountbase.rowid = resources.addrid AND resources.aidx = ? WHERE id='acctbase'")
	if err != nil {
		return nil, err
	}

	qs.lookupAllResourcesStmt, err = q.Prepare("SELECT accountbase.rowid, acctrounds.rnd, resources.aidx, resources.data FROM acctrounds LEFT JOIN accountbase ON accountbase.address = ? LEFT JOIN resources ON accountbase.rowid = resources.addrid WHERE id='acctbase'")
	if err != nil {
		return nil, err
	}

	qs.lookupLimitedResourcesStmt, err = q.Prepare(
		`SELECT ab.rowid,
						ar.rnd,
       					r.aidx,
      	 				ac.creator,
       					r.data,
       					cr.data
				FROM acctrounds ar
				JOIN accountbase ab ON ab.address = ?
				JOIN resources r ON r.addrid = ab.addrid
				LEFT JOIN assetcreators ac ON r.aidx = ac.asset
				LEFT JOIN accountbase cab ON ac.creator = cab.address
				LEFT JOIN resources cr ON cr.addrid = cab.addrid
				AND cr.aidx = r.aidx
				WHERE ar.id = 'acctbase'
  					AND r.ctype = ?
  					AND r.aidx > ?
				ORDER BY r.aidx ASC
				LIMIT ?`)
	if err != nil {
		return nil, err
	}

	qs.lookupKvPairStmt, err = q.Prepare("SELECT acctrounds.rnd, kvstore.key, kvstore.value FROM acctrounds LEFT JOIN kvstore ON key = ? WHERE id='acctbase';")
	if err != nil {
		return nil, err
	}

	qs.lookupKeysByRangeStmt, err = q.Prepare("SELECT acctrounds.rnd, kvstore.key FROM acctrounds LEFT JOIN kvstore ON kvstore.key >= ? AND kvstore.key < ? WHERE id='acctbase'")
	if err != nil {
		return nil, err
	}

	qs.lookupCreatorStmt, err = q.Prepare("SELECT acctrounds.rnd, assetcreators.creator FROM acctrounds LEFT JOIN assetcreators ON asset = ? AND ctype = ? WHERE id='acctbase'")
	if err != nil {
		return nil, err
	}

	return qs, nil
}

// OnlineAccountsInitDbQueries constructs an OnlineAccountsReader backed by sql queries.
func OnlineAccountsInitDbQueries(r db.Queryable) (*onlineAccountsDbQueries, error) {
	var err error
	qs := &onlineAccountsDbQueries{}

	qs.lookupOnlineStmt, err = r.Prepare("SELECT onlineaccounts.rowid, onlineaccounts.updround, acctrounds.rnd, onlineaccounts.data FROM acctrounds LEFT JOIN onlineaccounts ON address=? AND updround <= ? WHERE id='acctbase' ORDER BY updround DESC LIMIT 1")
	if err != nil {
		return nil, err
	}

	qs.lookupOnlineHistoryStmt, err = r.Prepare("SELECT onlineaccounts.rowid, onlineaccounts.updround, acctrounds.rnd, onlineaccounts.data FROM acctrounds LEFT JOIN onlineaccounts ON address=? WHERE id='acctbase' ORDER BY updround ASC")
	if err != nil {
		return nil, err
	}

	qs.lookupOnlineTotalsStmt, err = r.Prepare("SELECT data FROM onlineroundparamstail WHERE rnd=?")
	if err != nil {
		return nil, err
	}
	return qs, nil
}

// MakeOnlineAccountsSQLWriter constructs an OnlineAccountsWriter backed by sql queries.
func MakeOnlineAccountsSQLWriter(e db.Executable, hasAccounts bool) (w *onlineAccountsSQLWriter, err error) {
	w = new(onlineAccountsSQLWriter)

	if hasAccounts {
		w.insertStmt, err = e.Prepare("INSERT INTO onlineaccounts (address, normalizedonlinebalance, data, updround, votelastvalid) VALUES (?, ?, ?, ?, ?)")
		if err != nil {
			return
		}
	}

	return
}

// MakeAccountsSQLWriter constructs an AccountsWriter backed by sql queries.
func MakeAccountsSQLWriter(e db.Executable, hasAccounts, hasResources, hasKvPairs, hasCreatables bool) (w *accountsSQLWriter, err error) {
	w = new(accountsSQLWriter)

	if hasAccounts {
		w.deleteByRowIDStmt, err = e.Prepare("DELETE FROM accountbase WHERE rowid=?")
		if err != nil {
			return
		}

		w.insertStmt, err = e.Prepare("INSERT INTO accountbase (address, normalizedonlinebalance, data) VALUES (?, ?, ?)")
		if err != nil {
			return
		}

		w.updateStmt, err = e.Prepare("UPDATE accountbase SET normalizedonlinebalance = ?, data = ? WHERE rowid = ?")
		if err != nil {
			return
		}
	}

	if hasResources {
		w.deleteResourceStmt, err = e.Prepare("DELETE FROM resources WHERE addrid = ? AND aidx = ?")
		if err != nil {
			return
		}

		w.insertResourceStmt, err = e.Prepare("INSERT INTO resources(addrid, aidx, data, ctype) VALUES(?, ?, ?, ?)")
		if err != nil {
			return
		}

		w.updateResourceStmt, err = e.Prepare("UPDATE resources SET data = ? WHERE addrid = ? AND aidx = ?")
		if err != nil {
			return
		}
	}

	if hasKvPairs {
		w.upsertKvPairStmt, err = e.Prepare("INSERT INTO kvstore (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
		if err != nil {
			return
		}

		w.deleteKvPairStmt, err = e.Prepare("DELETE FROM kvstore WHERE key=?")
		if err != nil {
			return
		}
	}

	if hasCreatables {
		w.insertCreatableIdxStmt, err = e.Prepare("INSERT INTO assetcreators (asset, creator, ctype) VALUES (?, ?, ?)")
		if err != nil {
			return
		}

		w.deleteCreatableIdxStmt, err = e.Prepare("DELETE FROM assetcreators WHERE asset=? AND ctype=?")
		if err != nil {
			return
		}
	}
	return
}

// sql.go has the following contradictory comments:

// Reference types such as []byte are only valid until the next call to Scan
// and should not be retained. Their underlying memory is owned by the driver.
// If retention is necessary, copy their values before the next call to Scan.

// If a dest argument has type *[]byte, Scan saves in that argument a
// copy of the corresponding data. The copy is owned by the caller and
// can be modified and held indefinitely. The copy can be avoided by
// using an argument of type *RawBytes instead; see the documentation
// for RawBytes for restrictions on its use.

// After check source code, a []byte slice destination is definitely cloned.

// LookupKeyValue returns the application boxed value associated with the key.
func (qs *accountsDbQueries) LookupKeyValue(key string) (pv trackerdb.PersistedKVData, err error) {
	err = db.Retry(func() error {
		var rawkey []byte
		var val []byte
		// Cast to []byte to avoid interpretation as character string, see note in upsertKvPair
		err := qs.lookupKvPairStmt.QueryRow([]byte(key)).Scan(&pv.Round, &rawkey, &val)
		if err != nil {
			// this should never happen; it indicates that we don't have a current round in the acctrounds table.
			if err == sql.ErrNoRows {
				// Return the zero value of data
				err = fmt.Errorf("unable to query value for key %v : %w", key, err)
			}
			return err
		}
		if rawkey != nil { // We got a non-null key, so it exists
			if val == nil {
				val = []byte{}
			}
			pv.Value = val
			return nil
		}
		// we don't have that key, just return pv with the database round (pv.value==nil)
		return nil
	})
	return
}

// LookupKeysByPrefix returns a set of application boxed values matching the prefix.
func (qs *accountsDbQueries) LookupKeysByPrefix(prefix string, maxKeyNum uint64, results map[string]bool, resultCount uint64) (round basics.Round, err error) {
	start, end := keyPrefixIntervalPreprocessing([]byte(prefix))
	if end == nil {
		// Not an expected use case, it's asking for all keys, or all keys
		// prefixed by some number of 0xFF bytes.
		return 0, fmt.Errorf("lookup by strange prefix %#v", prefix)
	}
	err = db.Retry(func() error {
		var rows *sql.Rows
		rows, err = qs.lookupKeysByRangeStmt.Query(start, end)
		if err != nil {
			return err
		}
		defer rows.Close()

		var v sql.NullString

		for rows.Next() {
			if resultCount == maxKeyNum {
				return nil
			}
			err = rows.Scan(&round, &v)
			if err != nil {
				return err
			}
			if v.Valid {
				if _, ok := results[v.String]; ok {
					continue
				}
				results[v.String] = true
				resultCount++
			}
		}
		return nil
	})
	return
}

// keyPrefixIntervalPreprocessing is implemented to generate an interval for DB queries that look up keys by prefix.
// Such DB query was designed this way, to trigger the binary search optimization in SQLITE3.
// The DB comparison for blob typed primary key is lexicographic, i.e., byte by byte.
// In this way, we can introduce an interval that a primary key should be >= some prefix, < some prefix increment.
// A corner case to consider is that, the prefix has last byte 0xFF, or the prefix is full of 0xFF.
// - The first case can be solved by carrying, e.g., prefix = 0x1EFF -> interval being >= 0x1EFF and < 0x1F
// - The second case can be solved by disregarding the upper limit, i.e., prefix = 0xFFFF -> interval being >= 0xFFFF
// Another corner case to consider is empty byte, []byte{} or nil.
// - In both cases, the results are interval >= "", i.e., returns []byte{} for prefix, and nil for prefixIncr.
func keyPrefixIntervalPreprocessing(prefix []byte) ([]byte, []byte) {
	if prefix == nil {
		prefix = []byte{}
	}
	prefixIncr := make([]byte, len(prefix))
	copy(prefixIncr, prefix)
	for i := len(prefix) - 1; i >= 0; i-- {
		currentByteIncr := int(prefix[i]) + 1
		if currentByteIncr > 0xFF {
			prefixIncr = prefixIncr[:len(prefixIncr)-1]
			continue
		}
		prefixIncr[i] = byte(currentByteIncr)
		return prefix, prefixIncr
	}
	return prefix, nil
}

// LookupCreator returns the address and round of the creator.
func (qs *accountsDbQueries) LookupCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (addr basics.Address, ok bool, dbRound basics.Round, err error) {
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

// LookupResources returns the requested resource.
func (qs *accountsDbQueries) LookupResources(addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (data trackerdb.PersistedResourcesData, err error) {
	err = db.Retry(func() error {
		var buf []byte
		var rowid sql.NullInt64
		err := qs.lookupResourcesStmt.QueryRow(addr[:], aidx).Scan(&rowid, &data.Round, &buf)
		if err == nil {
			data.Aidx = aidx
			if len(buf) > 0 && rowid.Valid {
				data.AcctRef = sqlRowRef{rowid.Int64}
				err = protocol.Decode(buf, &data.Data)
				if err != nil {
					return err
				}
				if ctype == basics.AssetCreatable && !data.Data.IsAsset() {
					return fmt.Errorf("lookupResources asked for an asset but got %v", data.Data)
				}
				if ctype == basics.AppCreatable && !data.Data.IsApp() {
					return fmt.Errorf("lookupResources asked for an app but got %v", data.Data)
				}
				return nil
			}
			data.Data = trackerdb.MakeResourcesData(0)
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

// LookupAllResources returns all resources associated with the given address.
func (qs *accountsDbQueries) LookupAllResources(addr basics.Address) (data []trackerdb.PersistedResourcesData, rnd basics.Round, err error) {
	err = db.Retry(func() error {
		// Query for all resources
		rows, err0 := qs.lookupAllResourcesStmt.Query(addr[:])
		if err0 != nil {
			return err0
		}
		defer rows.Close()

		var addrid, aidx sql.NullInt64
		var dbRound basics.Round
		data = nil
		var buf []byte
		for rows.Next() {
			err = rows.Scan(&addrid, &dbRound, &aidx, &buf)
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
			var resData trackerdb.ResourcesData
			err = protocol.Decode(buf, &resData)
			if err != nil {
				return err
			}
			data = append(data, trackerdb.PersistedResourcesData{
				AcctRef: sqlRowRef{addrid.Int64},
				Aidx:    basics.CreatableIndex(aidx.Int64),
				Data:    resData,
				Round:   dbRound,
			})
			rnd = dbRound
		}
		return nil
	})
	return
}

func (qs *accountsDbQueries) LookupLimitedResources(addr basics.Address, minIdx basics.CreatableIndex, maxCreatables uint64, ctype basics.CreatableType) (data []trackerdb.PersistedResourcesDataWithCreator, rnd basics.Round, err error) {
	err = db.Retry(func() error {
		rows, err0 := qs.lookupLimitedResourcesStmt.Query(addr[:], ctype, minIdx, maxCreatables)
		if err0 != nil {
			return err0
		}
		defer rows.Close()

		var addrid, aidx sql.NullInt64
		var dbRound basics.Round
		data = nil
		var actAssetBuf []byte
		var crtAssetBuf []byte
		var creatorAddrBuf []byte
		for rows.Next() {
			err = rows.Scan(&addrid, &dbRound, &aidx, &creatorAddrBuf, &actAssetBuf, &crtAssetBuf)
			if err != nil {
				return err
			}
			if !addrid.Valid || !aidx.Valid {
				// we received an entry without any index. This would happen only on the first entry when there are no resources for this address.
				// ensure this is the first entry, set the round and return
				if len(data) != 0 {
					return fmt.Errorf("LookupLimitedResources: unexpected invalid result on non-first resource record: (%v, %v)", addrid.Valid, aidx.Valid)
				}
				rnd = dbRound
				break
			}
			var actResData trackerdb.ResourcesData
			var crtResData trackerdb.ResourcesData
			err = protocol.Decode(actAssetBuf, &actResData)
			if err != nil {
				return err
			}

			var prdwc trackerdb.PersistedResourcesDataWithCreator
			if len(crtAssetBuf) > 0 {
				err = protocol.Decode(crtAssetBuf, &crtResData)
				if err != nil {
					return err
				}

				// Since there is a creator, we want to return all of the asset params along with the asset holdings.
				// The most simple way to do this is to set the necessary asset holding data on the creator resource data
				// retrieved from the database. Note that this is unique way of setting resource flags, making this structure
				// not suitable for use in other contexts (where the params would only be present colocated with the asset holding
				// of the creator).
				crtResData.Amount = actResData.Amount
				crtResData.Frozen = actResData.Frozen
				crtResData.ResourceFlags = actResData.ResourceFlags

				creatorAddr := basics.Address{}
				copy(creatorAddr[:], creatorAddrBuf)

				prdwc = trackerdb.PersistedResourcesDataWithCreator{
					PersistedResourcesData: trackerdb.PersistedResourcesData{
						AcctRef: sqlRowRef{addrid.Int64},
						Aidx:    basics.CreatableIndex(aidx.Int64),
						Data:    crtResData,
						Round:   dbRound,
					},
					Creator: creatorAddr,
				}
			} else { // no creator found, asset was likely deleted, will not have asset params
				prdwc = trackerdb.PersistedResourcesDataWithCreator{
					PersistedResourcesData: trackerdb.PersistedResourcesData{
						AcctRef: sqlRowRef{addrid.Int64},
						Aidx:    basics.CreatableIndex(aidx.Int64),
						Data:    actResData,
						Round:   dbRound,
					},
				}
			}

			data = append(data, prdwc)

			rnd = dbRound
		}
		return nil
	})
	return
}

// LookupAccount looks up for a the account data given it's address. It returns the persistedAccountData, which includes the current database round and the matching
// account data, if such was found. If no matching account data could be found for the given address, an empty account data would
// be retrieved.
func (qs *accountsDbQueries) LookupAccount(addr basics.Address) (data trackerdb.PersistedAccountData, err error) {
	err = db.Retry(func() error {
		var buf []byte
		var rowid sql.NullInt64
		err := qs.lookupAccountStmt.QueryRow(addr[:]).Scan(&rowid, &data.Round, &buf)
		if err == nil {
			data.Addr = addr
			if len(buf) > 0 && rowid.Valid {
				data.Ref = sqlRowRef{rowid.Int64}
				err = protocol.Decode(buf, &data.AccountData)
				return err
			} else if len(buf) == 0 && rowid.Valid {
				// we are sure empty valid accounts do not exist in the database.
				return fmt.Errorf("account %v exists but has no data in the database", addr)
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

// LookupOnline returns the online account data for the given address.
func (qs *onlineAccountsDbQueries) LookupOnline(addr basics.Address, rnd basics.Round) (data trackerdb.PersistedOnlineAccountData, err error) {
	err = db.Retry(func() error {
		var buf []byte
		var rowid sql.NullInt64
		var updround sql.NullInt64
		err := qs.lookupOnlineStmt.QueryRow(addr[:], rnd).Scan(&rowid, &updround, &data.Round, &buf)
		if err == nil {
			data.Addr = addr
			if len(buf) > 0 && rowid.Valid && updround.Valid {
				data.Ref = sqlRowRef{rowid.Int64}
				data.UpdRound = basics.Round(updround.Int64)
				err = protocol.Decode(buf, &data.AccountData)
				return err
			}
			// we don't have that account, just return the database round.
			return nil
		}

		// this should never happen; it indicates that we don't have a current round in the acctrounds table.
		if err == sql.ErrNoRows {
			// Return the zero value of data
			return fmt.Errorf("unable to query online account data for address %v : %w", addr, err)
		}

		return err
	})
	return
}

func (qs *onlineAccountsDbQueries) LookupOnlineRoundParams(round basics.Round) (ledgercore.OnlineRoundParamsData, error) {
	data := ledgercore.OnlineRoundParamsData{}
	err := db.Retry(func() error {
		row := qs.lookupOnlineTotalsStmt.QueryRow(round)
		var buf []byte
		err := row.Scan(&buf)
		if err == sql.ErrNoRows {
			return trackerdb.ErrNotFound
		} else if err != nil {
			return err
		}
		err = protocol.Decode(buf, &data)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return ledgercore.OnlineRoundParamsData{}, err
	}
	return data, nil
}

func (qs *onlineAccountsDbQueries) LookupOnlineHistory(addr basics.Address) (result []trackerdb.PersistedOnlineAccountData, rnd basics.Round, err error) {
	err = db.Retry(func() error {
		rows, err := qs.lookupOnlineHistoryStmt.Query(addr[:])
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var buf []byte
			data := trackerdb.PersistedOnlineAccountData{}
			var rowid int64
			err = rows.Scan(&rowid, &data.UpdRound, &rnd, &buf)
			if err != nil {
				return err
			}
			data.Ref = sqlRowRef{rowid}
			err = protocol.Decode(buf, &data.AccountData)
			if err != nil {
				return err
			}
			data.Addr = addr
			result = append(result, data)
		}
		return nil
	})
	return
}

func (qs *accountsDbQueries) Close() {
	preparedQueries := []**sql.Stmt{
		&qs.lookupAccountStmt,
		&qs.lookupResourcesStmt,
		&qs.lookupAllResourcesStmt,
		&qs.lookupLimitedResourcesStmt,
		&qs.lookupKvPairStmt,
		&qs.lookupKeysByRangeStmt,
		&qs.lookupCreatorStmt,
	}
	for _, preparedQuery := range preparedQueries {
		if (*preparedQuery) != nil {
			(*preparedQuery).Close()
			*preparedQuery = nil
		}
	}
}

func (qs *onlineAccountsDbQueries) Close() {
	preparedQueries := []**sql.Stmt{
		&qs.lookupOnlineStmt,
		&qs.lookupOnlineHistoryStmt,
	}
	for _, preparedQuery := range preparedQueries {
		if (*preparedQuery) != nil {
			(*preparedQuery).Close()
			*preparedQuery = nil
		}
	}
}

func (w *accountsSQLWriter) Close() {
	// Formatted to match the type definition above
	preparedStmts := []**sql.Stmt{
		&w.insertCreatableIdxStmt, &w.deleteCreatableIdxStmt,
		&w.deleteByRowIDStmt, &w.insertStmt, &w.updateStmt,
		&w.deleteResourceStmt, &w.insertResourceStmt, &w.updateResourceStmt,
		&w.deleteKvPairStmt, &w.upsertKvPairStmt,
	}

	for _, stmt := range preparedStmts {
		if (*stmt) != nil {
			(*stmt).Close()
			*stmt = nil
		}
	}

}

func (w *onlineAccountsSQLWriter) Close() {
	if w.insertStmt != nil {
		w.insertStmt.Close()
		w.insertStmt = nil
	}
}

func (w accountsSQLWriter) InsertAccount(addr basics.Address, normBalance uint64, data trackerdb.BaseAccountData) (ref trackerdb.AccountRef, err error) {
	result, err := w.insertStmt.Exec(addr[:], normBalance, protocol.Encode(&data))
	if err != nil {
		return
	}
	rowid, err := result.LastInsertId()
	return sqlRowRef{rowid}, err
}

func (w accountsSQLWriter) DeleteAccount(ref trackerdb.AccountRef) (rowsAffected int64, err error) {
	if ref == nil {
		return 0, nil
	}
	rowid := ref.(sqlRowRef).rowid
	result, err := w.deleteByRowIDStmt.Exec(rowid)
	if err != nil {
		return
	}
	rowsAffected, err = result.RowsAffected()
	return
}

func (w accountsSQLWriter) UpdateAccount(ref trackerdb.AccountRef, normBalance uint64, data trackerdb.BaseAccountData) (rowsAffected int64, err error) {
	if ref == nil {
		err = sql.ErrNoRows
		return 0, fmt.Errorf("no account could be found for rowid = nil: %w", err)
	}
	rowid := ref.(sqlRowRef).rowid
	result, err := w.updateStmt.Exec(normBalance, protocol.Encode(&data), rowid)
	if err != nil {
		return
	}
	rowsAffected, err = result.RowsAffected()
	return
}

func (w accountsSQLWriter) InsertResource(accountRef trackerdb.AccountRef, aidx basics.CreatableIndex, data trackerdb.ResourcesData) (ref trackerdb.ResourceRef, err error) {
	if accountRef == nil {
		err = sql.ErrNoRows
		return nil, fmt.Errorf("no account could be found for rowid = nil: %w", err)
	}
	addrid := accountRef.(sqlRowRef).rowid
	var ctype basics.CreatableType
	if data.IsAsset() && data.IsApp() {
		return nil, fmt.Errorf("unable to resolve single creatable type for account ref %d, creatable idx %d", addrid, aidx)
	} else if data.IsAsset() {
		ctype = basics.AssetCreatable
	} else if data.IsApp() {
		ctype = basics.AppCreatable
	} else {
		return nil, fmt.Errorf("unable to resolve creatable type for account ref %d, creatable idx %d", addrid, aidx)
	}
	result, err := w.insertResourceStmt.Exec(addrid, aidx, protocol.Encode(&data), ctype)
	if err != nil {
		return
	}
	rowid, err := result.LastInsertId()
	return sqlRowRef{rowid}, err
}

func (w accountsSQLWriter) DeleteResource(accountRef trackerdb.AccountRef, aidx basics.CreatableIndex) (rowsAffected int64, err error) {
	if accountRef == nil {
		err = sql.ErrNoRows
		return 0, fmt.Errorf("no account could be found for rowid = nil: %w", err)
	}
	addrid := accountRef.(sqlRowRef).rowid
	result, err := w.deleteResourceStmt.Exec(addrid, aidx)
	if err != nil {
		return
	}
	rowsAffected, err = result.RowsAffected()
	return
}

func (w accountsSQLWriter) UpdateResource(accountRef trackerdb.AccountRef, aidx basics.CreatableIndex, data trackerdb.ResourcesData) (rowsAffected int64, err error) {
	if accountRef == nil {
		err = sql.ErrNoRows
		return 0, fmt.Errorf("no account could be found for rowid = nil: %w", err)
	}
	addrid := accountRef.(sqlRowRef).rowid
	result, err := w.updateResourceStmt.Exec(protocol.Encode(&data), addrid, aidx)
	if err != nil {
		return
	}
	rowsAffected, err = result.RowsAffected()
	return
}

func (w accountsSQLWriter) UpsertKvPair(key string, value []byte) error {
	// NOTE! If we are passing in `string`, then for `BoxKey` case,
	// we might contain 0-byte in boxKey, coming from uint64 appID.
	// The consequence would be DB key write in be cut off after such 0-byte.
	// Casting `string` to `[]byte` avoids such trouble, and test:
	// - `TestBoxNamesByAppIDs` in `acctupdates_test`
	// relies on such modification.
	result, err := w.upsertKvPairStmt.Exec([]byte(key), value)
	if err != nil {
		return err
	}
	_, err = result.LastInsertId()
	return err
}

func (w accountsSQLWriter) DeleteKvPair(key string) error {
	// Cast to []byte to avoid interpretation as character string, see note in upsertKvPair
	result, err := w.deleteKvPairStmt.Exec([]byte(key))
	if err != nil {
		return err
	}
	_, err = result.RowsAffected()
	return err
}

func (w accountsSQLWriter) InsertCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType, creator []byte) (ref trackerdb.CreatableRef, err error) {
	result, err := w.insertCreatableIdxStmt.Exec(cidx, creator, ctype)
	if err != nil {
		return
	}
	rowid, err := result.LastInsertId()
	return sqlRowRef{rowid}, err
}

func (w accountsSQLWriter) DeleteCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType) (rowsAffected int64, err error) {
	result, err := w.deleteCreatableIdxStmt.Exec(cidx, ctype)
	if err != nil {
		return
	}
	rowsAffected, err = result.RowsAffected()
	return
}

func (w onlineAccountsSQLWriter) InsertOnlineAccount(addr basics.Address, normBalance uint64, data trackerdb.BaseOnlineAccountData, updRound uint64, voteLastValid uint64) (ref trackerdb.OnlineAccountRef, err error) {
	result, err := w.insertStmt.Exec(addr[:], normBalance, protocol.Encode(&data), updRound, voteLastValid)
	if err != nil {
		return
	}
	rowid, err := result.LastInsertId()
	return sqlRowRef{rowid}, err
}
