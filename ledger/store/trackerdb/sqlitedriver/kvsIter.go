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
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/encoded"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

type kvsIter struct {
	q    db.Queryable
	rows *sql.Rows
}

// MakeKVsIter creates a KV iterator.
func MakeKVsIter(ctx context.Context, q db.Queryable) (*kvsIter, error) {
	rows, err := q.QueryContext(ctx, "SELECT key, value FROM kvstore")
	if err != nil {
		return nil, err
	}

	return &kvsIter{
		q:    q,
		rows: rows,
	}, nil
}

func (iter *kvsIter) Next() bool {
	return iter.rows.Next()
}

func (iter *kvsIter) KeyValue() (k []byte, v []byte, err error) {
	err = iter.rows.Scan(&k, &v)
	return k, v, err
}

func (iter *kvsIter) Close() {
	iter.rows.Close()
}

// tableIterator is used to dump onlineaccounts and onlineroundparams tables for catchpoints.
type tableIterator[T any] struct {
	rows    *sql.Rows
	scan    func(*sql.Rows) (T, error)
	onClose func()
}

func (iter *tableIterator[T]) Next() bool { return iter.rows.Next() }
func (iter *tableIterator[T]) Close() {
	iter.rows.Close()
	if iter.onClose != nil {
		iter.onClose()
	}
}
func (iter *tableIterator[T]) GetItem() (T, error) {
	return iter.scan(iter.rows)
}

// MakeOnlineAccountsIter creates an onlineAccounts iterator, used by the catchpoint system to dump the
// onlineaccounts table to a catchpoint snapshot file.
//
// If excludeBefore is non-zero, the iterator will exclude all data that would have been deleted if
// OnlineAccountsDelete(excludeBefore) were called on this DB before calling MakeOnlineAccountsIter.
func MakeOnlineAccountsIter(ctx context.Context, q db.Queryable, useStaging bool, excludeBefore basics.Round) (trackerdb.TableIterator[*encoded.OnlineAccountRecordV6], error) {
	table := "onlineaccounts"
	if useStaging {
		table = "catchpointonlineaccounts"
	}

	var onClose func()
	if excludeBefore != 0 {
		// This is a special case to resolve the issue found in #6214. When the state proof votersTracker has not
		// yet validated the recent state proof, the onlineaccounts table will hold more than 320 rows,
		// to support state proof recovery (votersTracker.lowestRound() sets deferredCommitRange.lowestRound).
		//
		// While rare, this may happen e.g. during catchup, where blocks may be flying by so quickly that the
		// catchpoint snapshot is started before the latest state proof was validated. In this case, excludeBefore
		// will be set to R-320 (MaxBalLookback) where R is the DB snapshot round (specified by CatchpointLookback).
		//
		// Unfortunately catchpoint snapshots occur within a SnapshotScope, and so a db.Queryable cannot
		// execute DDL statements. To work around this, we create a temporary table that we will delete
		// when the iterator is closed.
		e, ok := q.(*sql.Tx)
		if !ok {
			return nil, fmt.Errorf("MakeOnlineAccountsIter: cannot convert Queryable to sql.Tx, q is %T", q)
		}
		// create a new table by selecting from the original table
		destTable := table + "_iterator"
		_, err := e.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", destTable))
		if err != nil {
			return nil, err
		}
		_, err = e.ExecContext(ctx, fmt.Sprintf("CREATE TABLE %s AS SELECT * FROM %s", destTable, table))
		if err != nil {
			return nil, err
		}
		// call prune on the new copied table, using the same logic as OnlineAccountsDelete
		aw := accountsV2Writer{e: e}
		err = aw.onlineAccountsDelete(excludeBefore, destTable)
		if err != nil {
			return nil, err
		}
		// remember to drop the table when the iterator is closed
		onClose = func() {
			_, err = e.ExecContext(ctx, fmt.Sprintf("DROP TABLE %s", destTable))
			if err != nil {
				logging.Base().Errorf("Failed to drop table %s: %v", destTable, err)
			}
		}
		// use the new table to create the iterator
		table = destTable
	}

	rows, err := q.QueryContext(ctx, fmt.Sprintf("SELECT address, updround, normalizedonlinebalance, votelastvalid, data FROM %s ORDER BY address, updround", table))
	if err != nil {
		return nil, err
	}

	return &tableIterator[*encoded.OnlineAccountRecordV6]{
		rows:    rows,
		scan:    scanOnlineAccount,
		onClose: onClose,
	}, nil
}

func scanOnlineAccount(rows *sql.Rows) (*encoded.OnlineAccountRecordV6, error) {
	var ret encoded.OnlineAccountRecordV6
	var updRound, normBal, lastValid sql.NullInt64
	var addr, data []byte

	err := rows.Scan(&addr, &updRound, &normBal, &lastValid, &data)
	if err != nil {
		return nil, err
	}
	if len(addr) != len(ret.Address) {
		err = fmt.Errorf("onlineaccounts DB address length mismatch: %d != %d", len(addr), len(ret.Address))
		return nil, err
	}
	copy(ret.Address[:], addr)

	if !updRound.Valid || updRound.Int64 < 0 {
		return nil, fmt.Errorf("invalid updateRound (%v) for online account %s", updRound, ret.Address.String())
	}
	ret.UpdateRound = basics.Round(updRound.Int64)

	if !normBal.Valid || normBal.Int64 < 0 {
		return nil, fmt.Errorf("invalid norm balance (%v) for online account %s", normBal, ret.Address.String())
	}
	ret.NormalizedOnlineBalance = uint64(normBal.Int64)

	if !lastValid.Valid || lastValid.Int64 < 0 {
		return nil, fmt.Errorf("invalid lastValid (%v) for online account %s", lastValid, ret.Address)
	}
	ret.VoteLastValid = basics.Round(lastValid.Int64)

	var oaData trackerdb.BaseOnlineAccountData
	err = protocol.Decode(data, &oaData)
	if err != nil {
		return nil, fmt.Errorf("encoding error for online account %s: %v", ret.Address, err)
	}

	// check consistency of the decoded data against row data
	// skip checking NormalizedOnlineBalance, requires proto
	if ret.VoteLastValid != oaData.VoteLastValid {
		return nil, fmt.Errorf("decoded voteLastValid %d does not match row voteLastValid %d", oaData.VoteLastValid, ret.VoteLastValid)
	}

	// return original encoded column value
	ret.Data = data

	return &ret, nil
}

// MakeOnlineRoundParamsIter creates an onlineRoundParams iterator.
func MakeOnlineRoundParamsIter(ctx context.Context, q db.Queryable, useStaging bool, excludeBefore basics.Round) (trackerdb.TableIterator[*encoded.OnlineRoundParamsRecordV6], error) {
	table := "onlineroundparamstail"
	if useStaging {
		table = "catchpointonlineroundparamstail"
	}

	where := ""
	if excludeBefore != 0 {
		where = fmt.Sprintf("WHERE rnd >= %d", excludeBefore)
	}

	rows, err := q.QueryContext(ctx, fmt.Sprintf("SELECT rnd, data FROM %s %s ORDER BY rnd", table, where))
	if err != nil {
		return nil, err
	}

	return &tableIterator[*encoded.OnlineRoundParamsRecordV6]{rows: rows, scan: scanOnlineRoundParams}, nil
}

func scanOnlineRoundParams(rows *sql.Rows) (*encoded.OnlineRoundParamsRecordV6, error) {
	var ret encoded.OnlineRoundParamsRecordV6
	var rnd sql.NullInt64
	var data []byte

	err := rows.Scan(&rnd, &data)
	if err != nil {
		return nil, err
	}

	if !rnd.Valid || rnd.Int64 < 0 {
		return nil, fmt.Errorf("invalid round (%v) for online round params", rnd)
	}
	ret.Round = basics.Round(rnd.Int64)

	// test decode
	var orpData ledgercore.OnlineRoundParamsData
	err = protocol.Decode(data, &orpData)
	if err != nil {
		return nil, fmt.Errorf("encoding error for online round params round %v: %v", ret.Round, err)
	}

	// return original encoded column value
	ret.Data = data

	return &ret, nil
}
