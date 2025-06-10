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
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
	"github.com/stretchr/testify/require"
)

type accountsV2Reader struct {
	q                  db.Queryable
	preparedStatements map[string]*sql.Stmt
}

type accountsV2Writer struct {
	e db.Executable
}

type accountsV2ReaderWriter struct {
	accountsV2Reader
	accountsV2Writer
}

// NewAccountsSQLReaderWriter creates an SQL reader+writer
func NewAccountsSQLReaderWriter(e db.Executable) *accountsV2ReaderWriter {
	return &accountsV2ReaderWriter{
		accountsV2Reader{q: e, preparedStatements: make(map[string]*sql.Stmt)},
		accountsV2Writer{e: e},
	}
}

// NewAccountsSQLReader creates an SQL reader
func NewAccountsSQLReader(q db.Queryable) *accountsV2Reader {
	return &accountsV2Reader{q: q, preparedStatements: make(map[string]*sql.Stmt)}
}

// Testing returns this reader, exposed as an interface with test functions
func (r *accountsV2Reader) Testing() trackerdb.AccountsReaderTestExt {
	return r
}

func (r *accountsV2Reader) getOrPrepare(queryString string) (*sql.Stmt, error) {
	// fetch statement (use the query as the key)
	if stmt, ok := r.preparedStatements[queryString]; ok {
		return stmt, nil
	}
	// we do not have it, prepare it
	stmt, err := r.q.Prepare(queryString)
	if err != nil {
		return nil, err
	}
	// cache the statement
	r.preparedStatements[queryString] = stmt

	return stmt, nil
}

// AccountsTotals returns account totals
func (r *accountsV2Reader) AccountsTotals(ctx context.Context, catchpointStaging bool) (totals ledgercore.AccountTotals, err error) {
	id := ""
	if catchpointStaging {
		id = "catchpointStaging"
	}
	row := r.q.QueryRowContext(ctx, "SELECT online, onlinerewardunits, offline, offlinerewardunits, notparticipating, notparticipatingrewardunits, rewardslevel FROM accounttotals WHERE id=?", id)
	err = row.Scan(&totals.Online.Money.Raw, &totals.Online.RewardUnits,
		&totals.Offline.Money.Raw, &totals.Offline.RewardUnits,
		&totals.NotParticipating.Money.Raw, &totals.NotParticipating.RewardUnits,
		&totals.RewardsLevel)

	return
}

// AccountsAllTest iterates the account table and returns a map of the data
// It is meant only for testing purposes - it is heavy and has no production use case.
// implements Testing interface
func (r *accountsV2Reader) AccountsAllTest() (bals map[basics.Address]basics.AccountData, err error) {
	rows, err := r.q.Query("SELECT rowid, address, data FROM accountbase")
	if err != nil {
		return
	}
	defer rows.Close()

	bals = make(map[basics.Address]basics.AccountData)
	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		var rowid sql.NullInt64
		err = rows.Scan(&rowid, &addrbuf, &buf)
		if err != nil {
			return
		}

		var data trackerdb.BaseAccountData
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
		ad, err = r.LoadFullAccount(context.Background(), "resources", addr, rowid.Int64, data)
		if err != nil {
			return
		}

		bals[addr] = ad
	}

	err = rows.Err()
	return
}

// implements Testing interface
func (r *accountsV2Reader) CheckCreatablesTest(t *testing.T,
	iteration int,
	expectedDbImage map[basics.CreatableIndex]ledgercore.ModifiedCreatable) {
	stmt, err := r.q.Prepare("SELECT asset, creator, ctype FROM assetcreators")
	require.NoError(t, err)

	defer stmt.Close()
	rows, err := stmt.Query()
	if err != sql.ErrNoRows {
		require.NoError(t, err)
	}
	defer rows.Close()
	counter := 0
	for rows.Next() {
		counter++
		mc := ledgercore.ModifiedCreatable{}
		var buf []byte
		var asset basics.CreatableIndex
		err := rows.Scan(&asset, &buf, &mc.Ctype)
		require.NoError(t, err)
		copy(mc.Creator[:], buf)

		require.NotNil(t, expectedDbImage[asset])
		require.Equal(t, expectedDbImage[asset].Creator, mc.Creator)
		require.Equal(t, expectedDbImage[asset].Ctype, mc.Ctype)
		require.True(t, expectedDbImage[asset].Created)
	}
	require.Equal(t, len(expectedDbImage), counter)
}

// AccountsRound returns the tracker balances round number
func (r *accountsV2Reader) AccountsRound() (rnd basics.Round, err error) {
	err = r.q.QueryRow("SELECT rnd FROM acctrounds WHERE id='acctbase'").Scan(&rnd)
	if err != nil {
		return
	}
	return
}

// AccountsHashRound returns the round of the hash tree
// if the hash of the tree doesn't exists, it returns zero.
func (r *accountsV2Reader) AccountsHashRound(ctx context.Context) (hashrnd basics.Round, err error) {
	err = r.q.QueryRowContext(ctx, "SELECT rnd FROM acctrounds WHERE id='hashbase'").Scan(&hashrnd)
	if err == sql.ErrNoRows {
		hashrnd = basics.Round(0)
		err = nil
	}
	return
}

// AccountsOnlineTop returns the top n online accounts starting at position offset
// (that is, the top offset'th account through the top offset+n-1'th account).
//
// The accounts are sorted by their normalized balance and address.  The normalized
// balance has to do with the reward parts of online account balances.  See the
// normalization procedure in AccountData.NormalizedOnlineBalance().
//
// Note that this does not check if the accounts have a vote key valid for any
// particular round (past, present, or future).
func (r *accountsV2Reader) AccountsOnlineTop(rnd basics.Round, offset uint64, n uint64, rewardUnit uint64) (map[basics.Address]*ledgercore.OnlineAccount, error) {
	// onlineaccounts has historical data ordered by updround for both online and offline accounts.
	// This means some account A might have norm balance != 0 at round N and norm balance == 0 at some round K > N.
	// For online top query one needs to find entries not fresher than X with norm balance != 0.
	// To do that the query groups row by address and takes the latest updround, and then filters out rows with zero nor balance.
	rows, err := r.q.Query(`SELECT address, normalizedonlinebalance, data, max(updround) FROM onlineaccounts
WHERE updround <= ?
GROUP BY address HAVING normalizedonlinebalance > 0
ORDER BY normalizedonlinebalance DESC, address DESC LIMIT ? OFFSET ?`, rnd, n, offset)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[basics.Address]*ledgercore.OnlineAccount, n)
	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		var normBal sql.NullInt64
		var updround sql.NullInt64
		err = rows.Scan(&addrbuf, &normBal, &buf, &updround)
		if err != nil {
			return nil, err
		}

		var data trackerdb.BaseOnlineAccountData
		err = protocol.Decode(buf, &data)
		if err != nil {
			return nil, err
		}

		var addr basics.Address
		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return nil, err
		}

		if !normBal.Valid {
			return nil, fmt.Errorf("non valid norm balance for online account %s", addr.String())
		}

		copy(addr[:], addrbuf)
		// TODO: figure out protocol to use for rewards
		// The original implementation uses current proto to recalculate norm balance
		// In the same time, in accountsNewRound genesis protocol is used to fill norm balance value
		// In order to be consistent with the original implementation recalculate the balance with current proto
		normBalance := basics.NormalizedOnlineAccountBalance(basics.Online, data.RewardsBase, data.MicroAlgos, rewardUnit)
		oa := data.GetOnlineAccount(addr, normBalance)
		res[addr] = &oa
	}

	return res, rows.Err()
}

// OnlineAccountsAll returns all online accounts
func (r *accountsV2Reader) OnlineAccountsAll(maxAccounts uint64) ([]trackerdb.PersistedOnlineAccountData, error) {
	rows, err := r.q.Query("SELECT rowid, address, updround, data FROM onlineaccounts ORDER BY address, updround ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]trackerdb.PersistedOnlineAccountData, 0, maxAccounts)
	var numAccounts uint64
	seenAddr := make([]byte, len(basics.Address{}))
	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		var rowid int64
		data := trackerdb.PersistedOnlineAccountData{}
		err := rows.Scan(&rowid, &addrbuf, &data.UpdRound, &buf)
		if err != nil {
			return nil, err
		}
		data.Ref = sqlRowRef{rowid}
		if len(addrbuf) != len(data.Addr) {
			err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(data.Addr))
			return nil, err
		}
		if maxAccounts > 0 {
			if !bytes.Equal(seenAddr, addrbuf) {
				numAccounts++
				if numAccounts > maxAccounts {
					break
				}
				copy(seenAddr, addrbuf)
			}
		}
		copy(data.Addr[:], addrbuf)
		err = protocol.Decode(buf, &data.AccountData)
		if err != nil {
			return nil, err
		}
		result = append(result, data)
	}
	return result, nil
}

// ExpiredOnlineAccountsForRound returns all online accounts known at `rnd` that will be expired by `voteRnd`.
func (r *accountsV2Reader) ExpiredOnlineAccountsForRound(rnd, voteRnd basics.Round, rewardUnit uint64, rewardsLevel uint64) (map[basics.Address]*basics.OnlineAccountData, error) {
	// This relies on SQLite's handling of max(updround) and bare columns not in the GROUP BY.
	// The values of votelastvalid, votefirstvalid, and data will all be from the same row as max(updround)
	rows, err := r.q.Query(`SELECT address, data, max(updround)
FROM onlineaccounts
WHERE updround <= ?
GROUP BY address
HAVING votelastvalid < ? and votelastvalid > 0
ORDER BY address`, rnd, voteRnd)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ret := make(map[basics.Address]*basics.OnlineAccountData)
	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		var addr basics.Address
		var baseData trackerdb.BaseOnlineAccountData
		var updround sql.NullInt64
		err := rows.Scan(&addrbuf, &buf, &updround)
		if err != nil {
			return nil, err
		}
		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return nil, err
		}
		copy(addr[:], addrbuf)
		err = protocol.Decode(buf, &baseData)
		if err != nil {
			return nil, err
		}
		oadata := baseData.GetOnlineAccountData(rewardUnit, rewardsLevel)
		if _, ok := ret[addr]; ok {
			return nil, fmt.Errorf("duplicate address in expired online accounts: %s", addr.String())
		}
		ret[addr] = &oadata
	}
	return ret, nil
}

// TotalResources returns the total number of resources
func (r *accountsV2Reader) TotalResources(ctx context.Context) (total uint64, err error) {
	err = r.q.QueryRowContext(ctx, "SELECT count(1) FROM resources").Scan(&total)
	if err == sql.ErrNoRows {
		total = 0
		err = nil
		return
	}
	return
}

// TotalAccounts returns the total number of accounts
func (r *accountsV2Reader) TotalAccounts(ctx context.Context) (total uint64, err error) {
	err = r.q.QueryRowContext(ctx, "SELECT count(1) FROM accountbase").Scan(&total)
	if err == sql.ErrNoRows {
		total = 0
		err = nil
		return
	}
	return
}

// TotalKVs returns the total number of kv items
func (r *accountsV2Reader) TotalKVs(ctx context.Context) (total uint64, err error) {
	err = r.q.QueryRowContext(ctx, "SELECT count(1) FROM kvstore").Scan(&total)
	if err == sql.ErrNoRows {
		total = 0
		err = nil
		return
	}
	return
}

// TotalOnlineAccountRows returns the total number of rows in the onlineaccounts table.
func (r *accountsV2Reader) TotalOnlineAccountRows(ctx context.Context) (total uint64, err error) {
	err = r.q.QueryRowContext(ctx, "SELECT count(1) FROM onlineaccounts").Scan(&total)
	if err == sql.ErrNoRows {
		total = 0
		err = nil
		return
	}
	return
}

// TotalOnlineRoundParams returns the total number of rows in the onlineroundparamstail table.
func (r *accountsV2Reader) TotalOnlineRoundParams(ctx context.Context) (total uint64, err error) {
	err = r.q.QueryRowContext(ctx, "SELECT count(1) FROM onlineroundparamstail").Scan(&total)
	if err == sql.ErrNoRows {
		total = 0
		err = nil
		return
	}
	return
}

// LoadTxTail returns the tx tails
func (r *accountsV2Reader) LoadTxTail(ctx context.Context, dbRound basics.Round) (roundData []*trackerdb.TxTailRound, roundHash []crypto.Digest, baseRound basics.Round, err error) {
	rows, err := r.q.QueryContext(ctx, "SELECT rnd, data FROM txtail ORDER BY rnd DESC")
	if err != nil {
		return nil, nil, 0, err
	}
	defer rows.Close()

	expectedRound := dbRound
	for rows.Next() {
		var round basics.Round
		var data []byte
		err = rows.Scan(&round, &data)
		if err != nil {
			return nil, nil, 0, err
		}
		if round != expectedRound {
			return nil, nil, 0, fmt.Errorf("txtail table contain unexpected round %d; round %d was expected", round, expectedRound)
		}
		tail := &trackerdb.TxTailRound{}
		err = protocol.Decode(data, tail)
		if err != nil {
			return nil, nil, 0, err
		}
		roundData = append(roundData, tail)
		roundHash = append(roundHash, crypto.Hash(data))
		expectedRound--
	}
	// reverse the array ordering in-place so that it would be incremental order.
	for i := 0; i < len(roundData)/2; i++ {
		roundData[i], roundData[len(roundData)-i-1] = roundData[len(roundData)-i-1], roundData[i]
		roundHash[i], roundHash[len(roundHash)-i-1] = roundHash[len(roundHash)-i-1], roundHash[i]
	}
	return roundData, roundHash, expectedRound + 1, nil
}

// LookupAccountAddressFromAddressID looks up an account based on a rowid
func (r *accountsV2Reader) LookupAccountAddressFromAddressID(ctx context.Context, accountRef trackerdb.AccountRef) (address basics.Address, err error) {
	if accountRef == nil {
		err = sql.ErrNoRows
		return address, fmt.Errorf("no matching address could be found for rowid = nil: %w", err)
	}
	addrid := accountRef.(sqlRowRef).rowid
	var addrbuf []byte
	err = r.q.QueryRowContext(ctx, "SELECT address FROM accountbase WHERE rowid = ?", addrid).Scan(&addrbuf)
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

// LookupOnlineAccountDataByAddress looks up online account data by address.
func (r *accountsV2Reader) LookupOnlineAccountDataByAddress(addr basics.Address) (ref trackerdb.OnlineAccountRef, data []byte, err error) {
	// optimize this query for repeated usage
	selectStmt, err := r.getOrPrepare("SELECT rowid, data FROM onlineaccounts WHERE address=? ORDER BY updround DESC LIMIT 1")
	if err != nil {
		return
	}

	var rowid int64
	err = selectStmt.QueryRow(addr[:]).Scan(&rowid, &data)
	if err == sql.ErrNoRows {
		err = trackerdb.ErrNotFound
		return
	} else if err != nil {
		return
	}
	return sqlRowRef{rowid}, data, err
}

// LookupAccountRowID looks up the rowid of an account based on its address.
func (r *accountsV2Reader) LookupAccountRowID(addr basics.Address) (ref trackerdb.AccountRef, err error) {
	// optimize this query for repeated usage
	addrRowidStmt, err := r.getOrPrepare("SELECT rowid FROM accountbase WHERE address=?")
	if err != nil {
		return
	}

	var rowid int64
	err = addrRowidStmt.QueryRow(addr[:]).Scan(&rowid)
	if err == sql.ErrNoRows {
		err = trackerdb.ErrNotFound
		return
	} else if err != nil {
		return
	}
	return sqlRowRef{rowid}, err
}

// LookupResourceDataByAddrID looks up the resource data by account rowid + resource aidx.
func (r *accountsV2Reader) LookupResourceDataByAddrID(accountRef trackerdb.AccountRef, aidx basics.CreatableIndex) (data []byte, err error) {
	if accountRef == nil {
		return data, trackerdb.ErrNotFound
	}
	addrid := accountRef.(sqlRowRef).rowid
	// optimize this query for repeated usage
	selectStmt, err := r.getOrPrepare("SELECT data FROM resources WHERE addrid = ? AND aidx = ?")
	if err != nil {
		return
	}

	err = selectStmt.QueryRow(addrid, aidx).Scan(&data)
	if err == sql.ErrNoRows {
		err = trackerdb.ErrNotFound
		return
	} else if err != nil {
		return
	}
	return data, err
}

// LoadAllFullAccounts loads all accounts from balancesTable and resourcesTable.
// On every account full load it invokes acctCb callback to report progress and data.
func (r *accountsV2Reader) LoadAllFullAccounts(
	ctx context.Context,
	balancesTable string, resourcesTable string,
	acctCb func(basics.Address, basics.AccountData),
) (count int, err error) {
	baseRows, err := r.q.QueryContext(ctx, fmt.Sprintf("SELECT rowid, address, data FROM %s ORDER BY address", balancesTable))
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

		var data trackerdb.BaseAccountData
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
		ad, err = r.LoadFullAccount(ctx, resourcesTable, addr, rowid.Int64, data)
		if err != nil {
			return
		}

		acctCb(addr, ad)

		count++
	}
	return
}

// LoadFullAccount converts BaseAccountData into basics.AccountData and loads all resources as needed
func (r *accountsV2Reader) LoadFullAccount(ctx context.Context, resourcesTable string, addr basics.Address, addrid int64, data trackerdb.BaseAccountData) (ad basics.AccountData, err error) {
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
	resRows, err = r.q.QueryContext(ctx, query, addrid)
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
		var resData trackerdb.ResourcesData
		err = protocol.Decode(buf, &resData)
		if err != nil {
			return
		}
		if resData.ResourceFlags == trackerdb.ResourceFlagsNotHolding {
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

	return ad, err
}

func (r *accountsV2Reader) AccountsOnlineRoundParams() (onlineRoundParamsData []ledgercore.OnlineRoundParamsData, endRound basics.Round, err error) {
	rows, err := r.q.Query("SELECT rnd, data FROM onlineroundparamstail ORDER BY rnd ASC")
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

// AccountsPutTotals updates account totals
func (w *accountsV2Writer) AccountsPutTotals(totals ledgercore.AccountTotals, catchpointStaging bool) error {
	id := ""
	if catchpointStaging {
		id = "catchpointStaging"
	}
	_, err := w.e.Exec("REPLACE INTO accounttotals (id, online, onlinerewardunits, offline, offlinerewardunits, notparticipating, notparticipatingrewardunits, rewardslevel) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		id,
		totals.Online.Money.Raw, totals.Online.RewardUnits,
		totals.Offline.Money.Raw, totals.Offline.RewardUnits,
		totals.NotParticipating.Money.Raw, totals.NotParticipating.RewardUnits,
		totals.RewardsLevel)
	return err
}

func (w *accountsV2Writer) TxtailNewRound(ctx context.Context, baseRound basics.Round, roundData [][]byte, forgetBeforeRound basics.Round) error {
	insertStmt, err := w.e.PrepareContext(ctx, "INSERT INTO txtail(rnd, data) VALUES(?, ?)")
	if err != nil {
		return err
	}
	defer insertStmt.Close()

	for i, data := range roundData {
		_, err = insertStmt.ExecContext(ctx, int(baseRound)+i, data[:])
		if err != nil {
			return err
		}
	}

	_, err = w.e.ExecContext(ctx, "DELETE FROM txtail WHERE rnd < ?", forgetBeforeRound)
	return err
}

// OnlineAccountsDelete cleans up the Online Accounts table to prune expired entires.
// it will delete entries with an updRound <= expRound
// EXCEPT, it will not delete the *latest* entry for an account, no matter how old.
// this is so that accounts whos last update is before expRound still maintain an Online Account Balance
// After this cleanup runs, accounts in this table will have either one entry (if all entries besides the latest are expired),
// or will have more than one entry (if multiple entries are not yet expired).
func (w *accountsV2Writer) OnlineAccountsDelete(forgetBefore basics.Round) (err error) {
	return w.onlineAccountsDelete(forgetBefore, "onlineaccounts")
}

func (w *accountsV2Writer) onlineAccountsDelete(forgetBefore basics.Round, table string) (err error) {
	rows, err := w.e.Query(fmt.Sprintf("SELECT rowid, address, updRound, data FROM %s WHERE updRound < ? ORDER BY address, updRound DESC", table), forgetBefore)
	if err != nil {
		return err
	}
	defer rows.Close()

	var rowids []int64
	var rowid sql.NullInt64
	var updRound sql.NullInt64
	var buf []byte
	var addrbuf []byte

	var prevAddr []byte

	for rows.Next() {
		err = rows.Scan(&rowid, &addrbuf, &updRound, &buf)
		if err != nil {
			return err
		}
		if !rowid.Valid || !updRound.Valid {
			return fmt.Errorf("onlineAccountsDelete: invalid rowid or updRound")
		}
		if len(addrbuf) != len(basics.Address{}) {
			err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(basics.Address{}))
			return
		}

		if !bytes.Equal(addrbuf, prevAddr) {
			// new address
			// if the first (latest) entry is
			//  - offline then delete all
			//  - online then safe to delete all previous except this first (latest)

			// reset the state
			prevAddr = addrbuf

			var oad trackerdb.BaseOnlineAccountData
			err = protocol.Decode(buf, &oad)
			if err != nil {
				return
			}
			if oad.IsVotingEmpty() {
				// delete this and all subsequent
				rowids = append(rowids, rowid.Int64)
			}

			// restart the loop
			// if there are some subsequent entries, they will deleted on the next iteration
			// if no subsequent entries, the loop will reset the state and the latest entry does not get deleted
			continue
		}
		// delete all subsequent entries
		rowids = append(rowids, rowid.Int64)
	}

	return onlineAccountsDeleteByRowIDs(w.e, rowids, table)
}

func onlineAccountsDeleteByRowIDs(e db.Executable, rowids []int64, table string) (err error) {
	if len(rowids) == 0 {
		return
	}

	// sqlite3 < 3.32.0 allows SQLITE_MAX_VARIABLE_NUMBER = 999 bindings
	// see https://www.sqlite.org/limits.html
	// rowids might be larger => split to chunks are remove
	chunks := rowidsToChunkedArgs(rowids)
	for _, chunk := range chunks {
		_, err = e.Exec("DELETE FROM "+table+" WHERE rowid IN (?"+strings.Repeat(",?", len(chunk)-1)+")", chunk...)
		if err != nil {
			return
		}
	}
	return
}

func rowidsToChunkedArgs(rowids []int64) [][]interface{} {
	const sqliteMaxVariableNumber = 999

	numChunks := len(rowids)/sqliteMaxVariableNumber + 1
	if len(rowids)%sqliteMaxVariableNumber == 0 {
		numChunks--
	}
	chunks := make([][]interface{}, numChunks)
	if numChunks == 1 {
		// optimize memory consumption for the most common case
		chunks[0] = make([]interface{}, len(rowids))
		for i, rowid := range rowids {
			chunks[0][i] = interface{}(rowid)
		}
	} else {
		for i := 0; i < numChunks; i++ {
			chunkSize := sqliteMaxVariableNumber
			if i == numChunks-1 {
				chunkSize = len(rowids) - (numChunks-1)*sqliteMaxVariableNumber
			}
			chunks[i] = make([]interface{}, chunkSize)
		}
		for i, rowid := range rowids {
			chunkIndex := i / sqliteMaxVariableNumber
			chunks[chunkIndex][i%sqliteMaxVariableNumber] = interface{}(rowid)
		}
	}
	return chunks
}

// UpdateAccountsRound updates the round number associated with the current account data.
func (w *accountsV2Writer) UpdateAccountsRound(rnd basics.Round) (err error) {
	res, err := w.e.Exec("UPDATE acctrounds SET rnd=? WHERE id='acctbase' AND rnd<?", rnd, rnd)
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
		err = w.e.QueryRow("SELECT rnd FROM acctrounds WHERE id='acctbase'").Scan(&base)
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

// UpdateAccountsHashRound updates the round number associated with the hash of current account data.
func (w *accountsV2Writer) UpdateAccountsHashRound(ctx context.Context, hashRound basics.Round) (err error) {
	res, err := w.e.ExecContext(ctx, "INSERT OR REPLACE INTO acctrounds(id,rnd) VALUES('hashbase',?)", hashRound)
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

// ResetAccountHashes resets the account hashes generated by the merkle commiter.
func (w *accountsV2Writer) ResetAccountHashes(ctx context.Context) (err error) {
	_, err = w.e.ExecContext(ctx, `DELETE FROM accounthashes`)
	return
}

func (w *accountsV2Writer) AccountsPutOnlineRoundParams(onlineRoundParamsData []ledgercore.OnlineRoundParamsData, startRound basics.Round) error {
	insertStmt, err := w.e.Prepare("INSERT INTO onlineroundparamstail (rnd, data) VALUES (?, ?)")
	if err != nil {
		return err
	}

	for i := range onlineRoundParamsData {
		_, err = insertStmt.Exec(startRound+basics.Round(i), protocol.Encode(&onlineRoundParamsData[i]))
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *accountsV2Writer) AccountsPruneOnlineRoundParams(deleteBeforeRound basics.Round) error {
	_, err := w.e.Exec("DELETE FROM onlineroundparamstail WHERE rnd<?",
		deleteBeforeRound,
	)
	return err
}

func (w *accountsV2Writer) AccountsReset(ctx context.Context) error {
	for _, stmt := range accountsResetExprs {
		_, err := w.e.ExecContext(ctx, stmt)
		if err != nil {
			return err
		}
	}
	_, err := db.SetUserVersion(ctx, w.e, 0)
	return err
}
