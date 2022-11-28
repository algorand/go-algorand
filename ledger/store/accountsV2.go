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

package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

type accountsV2Reader struct {
	q db.Queryable
}

type accountsV2Writer struct {
	e db.Executable
}

type accountsV2ReaderWriter struct {
	accountsV2Reader
	accountsV2Writer
}

// NewAccountsSQLReaderWriter creates a Catchpoint SQL reader+writer
func NewAccountsSQLReaderWriter(e db.Executable) *accountsV2ReaderWriter {
	return &accountsV2ReaderWriter{
		accountsV2Reader{q: e},
		accountsV2Writer{e: e},
	}
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
func (r *accountsV2Reader) AccountsOnlineTop(rnd basics.Round, offset uint64, n uint64, proto config.ConsensusParams) (map[basics.Address]*ledgercore.OnlineAccount, error) {
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

		var data BaseOnlineAccountData
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
		normBalance := basics.NormalizedOnlineAccountBalance(basics.Online, data.RewardsBase, data.MicroAlgos, proto)
		oa := data.GetOnlineAccount(addr, normBalance)
		res[addr] = &oa
	}

	return res, rows.Err()
}

// OnlineAccountsAll returns all online accounts
func (r *accountsV2Reader) OnlineAccountsAll(maxAccounts uint64) ([]PersistedOnlineAccountData, error) {
	rows, err := r.q.Query("SELECT rowid, address, updround, data FROM onlineaccounts ORDER BY address, updround ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]PersistedOnlineAccountData, 0, maxAccounts)
	var numAccounts uint64
	seenAddr := make([]byte, len(basics.Address{}))
	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		data := PersistedOnlineAccountData{}
		err := rows.Scan(&data.Rowid, &addrbuf, &data.UpdRound, &buf)
		if err != nil {
			return nil, err
		}
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

// LoadTxTail returns the tx tails
func (r *accountsV2Reader) LoadTxTail(ctx context.Context, dbRound basics.Round) (roundData []*TxTailRound, roundHash []crypto.Digest, baseRound basics.Round, err error) {
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
		tail := &TxTailRound{}
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
func (r *accountsV2Reader) LookupAccountAddressFromAddressID(ctx context.Context, addrid int64) (address basics.Address, err error) {
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

// OnlineAccountsDelete deleted entries with updRound <= expRound
func (w *accountsV2Writer) OnlineAccountsDelete(forgetBefore basics.Round) (err error) {
	rows, err := w.e.Query("SELECT rowid, address, updRound, data FROM onlineaccounts WHERE updRound < ? ORDER BY address, updRound DESC", forgetBefore)
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

			var oad BaseOnlineAccountData
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

	return onlineAccountsDeleteByRowIDs(w.e, rowids)
}

func onlineAccountsDeleteByRowIDs(e db.Executable, rowids []int64) (err error) {
	if len(rowids) == 0 {
		return
	}

	// sqlite3 < 3.32.0 allows SQLITE_MAX_VARIABLE_NUMBER = 999 bindings
	// see https://www.sqlite.org/limits.html
	// rowids might be larger => split to chunks are remove
	chunks := rowidsToChunkedArgs(rowids)
	for _, chunk := range chunks {
		_, err = e.Exec("DELETE FROM onlineaccounts WHERE rowid IN (?"+strings.Repeat(",?", len(chunk)-1)+")", chunk...)
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
