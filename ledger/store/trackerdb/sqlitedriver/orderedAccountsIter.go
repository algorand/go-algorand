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
	"math"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// orderedAccountsIter allows us to iterate over the accounts addresses in the order of the account hashes.
type orderedAccountsIter struct {
	step               orderedAccountsIterStep
	accountBaseRows    *sql.Rows
	hashesRows         *sql.Rows
	resourcesRows      *sql.Rows
	e                  db.Executable
	pendingBaseRow     pendingBaseRow
	pendingResourceRow pendingResourceRow
	accountCount       int
	insertStmt         *sql.Stmt
}

// orderedAccountsIterStep is used by orderedAccountsIter to define the current step
//
//msgp:ignore orderedAccountsIterStep
type orderedAccountsIterStep int

const (
	// startup step
	oaiStepStartup = orderedAccountsIterStep(0)
	// delete old ordering table if we have any leftover from previous invocation
	oaiStepDeleteOldOrderingTable = orderedAccountsIterStep(0)
	// create new ordering table
	oaiStepCreateOrderingTable = orderedAccountsIterStep(1)
	// query the existing accounts
	oaiStepQueryAccounts = orderedAccountsIterStep(2)
	// iterate over the existing accounts and insert their hash & address into the staging ordering table
	oaiStepInsertAccountData = orderedAccountsIterStep(3)
	// create an index on the ordering table so that we can efficiently scan it.
	oaiStepCreateOrderingAccountIndex = orderedAccountsIterStep(4)
	// query the ordering table
	oaiStepSelectFromOrderedTable = orderedAccountsIterStep(5)
	// iterate over the ordering table
	oaiStepIterateOverOrderedTable = orderedAccountsIterStep(6)
	// cleanup and delete ordering table
	oaiStepShutdown = orderedAccountsIterStep(7)
	// do nothing as we're done.
	oaiStepDone = orderedAccountsIterStep(8)
)

type pendingBaseRow struct {
	addr               basics.Address
	rowid              int64
	accountData        *trackerdb.BaseAccountData
	encodedAccountData []byte
}

type pendingResourceRow struct {
	addrid int64
	aidx   basics.CreatableIndex
	buf    []byte
}

// MakeOrderedAccountsIter creates an ordered account iterator. Note that due to implementation reasons,
// only a single iterator can be active at a time.
func MakeOrderedAccountsIter(e db.Executable, accountCount int) *orderedAccountsIter {
	return &orderedAccountsIter{
		e:            e,
		accountCount: accountCount,
		step:         oaiStepStartup,
	}
}

// Next returns an array containing the account address and hash
// the Next function works in multiple processing stages, where it first processes the current accounts and order them
// followed by returning the ordered accounts. In the first phase, it would return empty accountAddressHash array
// and sets the processedRecords to the number of accounts that were processed. On the second phase, the acct
// would contain valid data ( and optionally the account data as well, if was asked in makeOrderedAccountsIter) and
// the processedRecords would be zero. If err is sql.ErrNoRows it means that the iterator have completed it's work and no further
// accounts exists. Otherwise, the caller is expected to keep calling "Next" to retrieve the next set of accounts
// ( or let the Next function make some progress toward that goal )
func (iterator *orderedAccountsIter) Next(ctx context.Context) (acct []trackerdb.AccountAddressHash, processedRecords int, err error) {
	if iterator.step == oaiStepDeleteOldOrderingTable {
		// although we're going to delete this table anyway when completing the iterator execution, we'll try to
		// clean up any intermediate table.
		_, err = iterator.e.ExecContext(ctx, "DROP TABLE IF EXISTS accountsiteratorhashes")
		if err != nil {
			return
		}
		iterator.step = oaiStepCreateOrderingTable
		return
	}
	if iterator.step == oaiStepCreateOrderingTable {
		// create the temporary table
		_, err = iterator.e.ExecContext(ctx, "CREATE TABLE accountsiteratorhashes(addrid INTEGER, hash blob)")
		if err != nil {
			return
		}
		iterator.step = oaiStepQueryAccounts
		return
	}
	if iterator.step == oaiStepQueryAccounts {
		// iterate over the existing accounts
		iterator.accountBaseRows, err = iterator.e.QueryContext(ctx, "SELECT rowid, address, data FROM accountbase ORDER BY rowid")
		if err != nil {
			return
		}
		// iterate over the existing resources
		iterator.resourcesRows, err = iterator.e.QueryContext(ctx, "SELECT addrid, aidx, data FROM resources ORDER BY addrid, aidx")
		if err != nil {
			return
		}
		// prepare the insert statement into the temporary table
		iterator.insertStmt, err = iterator.e.PrepareContext(ctx, "INSERT INTO accountsiteratorhashes(addrid, hash) VALUES(?, ?)")
		if err != nil {
			return
		}
		iterator.step = oaiStepInsertAccountData
		return
	}
	if iterator.step == oaiStepInsertAccountData {
		var lastAddrID int64
		baseCb := func(addr basics.Address, rowid int64, accountData *trackerdb.BaseAccountData, encodedAccountData []byte) (err error) {
			hash := trackerdb.AccountHashBuilderV6(addr, accountData, encodedAccountData)
			_, err = iterator.insertStmt.ExecContext(ctx, rowid, hash)
			if err != nil {
				return
			}
			lastAddrID = rowid
			return nil
		}

		resCb := func(addr basics.Address, cidx basics.CreatableIndex, resData *trackerdb.ResourcesData, encodedResourceData []byte, lastResource bool) error {
			if resData != nil {
				hash, err2 := trackerdb.ResourcesHashBuilderV6(resData, addr, cidx, resData.UpdateRound, encodedResourceData)
				if err2 != nil {
					return err2
				}
				_, err2 = iterator.insertStmt.ExecContext(ctx, lastAddrID, hash)
				return err2
			}
			return nil
		}

		count := 0
		count, iterator.pendingBaseRow, iterator.pendingResourceRow, err = processAllBaseAccountRecords(
			iterator.accountBaseRows, iterator.resourcesRows,
			baseCb, resCb,
			iterator.pendingBaseRow, iterator.pendingResourceRow, iterator.accountCount, math.MaxInt,
		)
		if err != nil {
			iterator.Close(ctx)
			return
		}

		if count == iterator.accountCount {
			// we're done with this iteration.
			processedRecords = count
			return
		}

		// make sure the resource iterator has no more entries.
		if iterator.resourcesRows.Next() {
			iterator.Close(ctx)
			err = errors.New("resource table entries exceed the ones specified in the accountbase table")
			return
		}

		processedRecords = count
		iterator.accountBaseRows.Close()
		iterator.accountBaseRows = nil
		iterator.resourcesRows.Close()
		iterator.resourcesRows = nil
		iterator.insertStmt.Close()
		iterator.insertStmt = nil
		iterator.step = oaiStepCreateOrderingAccountIndex
		return
	}
	if iterator.step == oaiStepCreateOrderingAccountIndex {
		// create an index. It shown that even when we're making a single select statement in step 5, it would be better to have this index vs. not having it at all.
		// note that this index is using the rowid of the accountsiteratorhashes table.
		_, err = iterator.e.ExecContext(ctx, "CREATE INDEX accountsiteratorhashesidx ON accountsiteratorhashes(hash)")
		if err != nil {
			iterator.Close(ctx)
			return
		}
		iterator.step = oaiStepSelectFromOrderedTable
		return
	}
	if iterator.step == oaiStepSelectFromOrderedTable {
		// select the data from the ordered table
		iterator.hashesRows, err = iterator.e.QueryContext(ctx, "SELECT addrid, hash FROM accountsiteratorhashes ORDER BY hash")

		if err != nil {
			iterator.Close(ctx)
			return
		}
		iterator.step = oaiStepIterateOverOrderedTable
		return
	}

	if iterator.step == oaiStepIterateOverOrderedTable {
		acct = make([]trackerdb.AccountAddressHash, iterator.accountCount)
		acctIdx := 0
		for iterator.hashesRows.Next() {
			var addrid int64
			err = iterator.hashesRows.Scan(&addrid, &(acct[acctIdx].Digest))
			acct[acctIdx].AccountRef = sqlRowRef{addrid}
			if err != nil {
				iterator.Close(ctx)
				return
			}
			acctIdx++
			if acctIdx == iterator.accountCount {
				// we're done with this iteration.
				return
			}
		}
		acct = acct[:acctIdx]
		iterator.step = oaiStepShutdown
		iterator.hashesRows.Close()
		iterator.hashesRows = nil
		return
	}
	if iterator.step == oaiStepShutdown {
		err = iterator.Close(ctx)
		if err != nil {
			return
		}
		iterator.step = oaiStepDone
		// fallthrough
	}
	return nil, 0, sql.ErrNoRows
}

// Close shuts down the orderedAccountsBuilderIter, releasing database resources.
func (iterator *orderedAccountsIter) Close(ctx context.Context) (err error) {
	if iterator.accountBaseRows != nil {
		iterator.accountBaseRows.Close()
		iterator.accountBaseRows = nil
	}
	if iterator.resourcesRows != nil {
		iterator.resourcesRows.Close()
		iterator.resourcesRows = nil
	}
	if iterator.hashesRows != nil {
		iterator.hashesRows.Close()
		iterator.hashesRows = nil
	}
	if iterator.insertStmt != nil {
		iterator.insertStmt.Close()
		iterator.insertStmt = nil
	}
	_, err = iterator.e.ExecContext(ctx, "DROP TABLE IF EXISTS accountsiteratorhashes")
	return
}

func processAllBaseAccountRecords(
	baseRows *sql.Rows,
	resRows *sql.Rows,
	baseCb func(addr basics.Address, rowid int64, accountData *trackerdb.BaseAccountData, encodedAccountData []byte) error,
	resCb func(addr basics.Address, creatableIdx basics.CreatableIndex, resData *trackerdb.ResourcesData, encodedResourceData []byte, lastResource bool) error,
	pendingBase pendingBaseRow, pendingResource pendingResourceRow, accountCount int, resourceCount int,
) (int, pendingBaseRow, pendingResourceRow, error) {
	var addr basics.Address
	var prevAddr basics.Address
	var err error
	count := 0

	var accountData trackerdb.BaseAccountData
	var addrbuf []byte
	var buf []byte
	var rowid int64
	for {
		if pendingBase.rowid != 0 {
			addr = pendingBase.addr
			rowid = pendingBase.rowid
			accountData = *pendingBase.accountData
			buf = pendingBase.encodedAccountData
			pendingBase = pendingBaseRow{}
		} else {
			if !baseRows.Next() {
				break
			}

			err = baseRows.Scan(&rowid, &addrbuf, &buf)
			if err != nil {
				return 0, pendingBaseRow{}, pendingResourceRow{}, err
			}

			if len(addrbuf) != len(addr) {
				err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
				return 0, pendingBaseRow{}, pendingResourceRow{}, err
			}

			copy(addr[:], addrbuf)

			accountData = trackerdb.BaseAccountData{}
			err = protocol.Decode(buf, &accountData)
			if err != nil {
				return 0, pendingBaseRow{}, pendingResourceRow{}, err
			}
		}

		err = baseCb(addr, rowid, &accountData, buf)
		if err != nil {
			return 0, pendingBaseRow{}, pendingResourceRow{}, err
		}

		var resourcesProcessed int
		pendingResource, resourcesProcessed, err = processAllResources(resRows, addr, &accountData, rowid, pendingResource, resourceCount, resCb)
		if err != nil {
			err = fmt.Errorf("failed to gather resources for account %v, addrid %d, prev address %v : %w", addr, rowid, prevAddr, err)
			return 0, pendingBaseRow{}, pendingResourceRow{}, err
		}

		if resourcesProcessed == resourceCount {
			// we're done with this iteration.
			pendingBase := pendingBaseRow{
				addr:               addr,
				rowid:              rowid,
				accountData:        &accountData,
				encodedAccountData: buf,
			}
			return count, pendingBase, pendingResource, nil
		}
		resourceCount -= resourcesProcessed

		count++
		if accountCount > 0 && count == accountCount {
			// we're done with this iteration.
			return count, pendingBaseRow{}, pendingResource, nil
		}
		prevAddr = addr
	}

	return count, pendingBaseRow{}, pendingResource, nil
}

func processAllResources(
	resRows *sql.Rows,
	addr basics.Address, accountData *trackerdb.BaseAccountData, acctRowid int64, pr pendingResourceRow, resourceCount int,
	callback func(addr basics.Address, creatableIdx basics.CreatableIndex, resData *trackerdb.ResourcesData, encodedResourceData []byte, lastResource bool) error,
) (pendingResourceRow, int, error) {
	var err error
	count := 0

	// Declare variabled outside of the loop to prevent allocations per iteration.
	// At least resData is resolved as "escaped" because of passing it by a pointer to protocol.Decode()
	var buf []byte
	var addrid int64
	var aidx basics.CreatableIndex
	var resData trackerdb.ResourcesData
	for {
		if pr.addrid != 0 {
			// some accounts may not have resources, consider the following case:
			// acct 1 and 3 has resources, account 2 does not
			// in this case addrid = 3 after processing resources from 1, but acctRowid = 2
			// and we need to skip accounts without resources
			if pr.addrid > acctRowid {
				err = callback(addr, 0, nil, nil, false)
				return pr, count, err
			}
			if pr.addrid < acctRowid {
				err = fmt.Errorf("resource table entries mismatches accountbase table entries : reached addrid %d while expecting resource for %d", pr.addrid, acctRowid)
				return pendingResourceRow{}, count, err
			}
			addrid = pr.addrid
			buf = pr.buf
			aidx = pr.aidx
			pr = pendingResourceRow{}
		} else {
			if !resRows.Next() {
				err = callback(addr, 0, nil, nil, false)
				if err != nil {
					return pendingResourceRow{}, count, err
				}
				break
			}
			err = resRows.Scan(&addrid, &aidx, &buf)
			if err != nil {
				return pendingResourceRow{}, count, err
			}
			if addrid < acctRowid {
				err = fmt.Errorf("resource table entries mismatches accountbase table entries : reached addrid %d while expecting resource for %d", addrid, acctRowid)
				return pendingResourceRow{}, count, err
			} else if addrid > acctRowid {
				err = callback(addr, 0, nil, nil, false)
				return pendingResourceRow{addrid, aidx, buf}, count, err
			}
		}
		resData = trackerdb.ResourcesData{}
		err = protocol.Decode(buf, &resData)
		if err != nil {
			return pendingResourceRow{}, count, err
		}
		count++
		if resourceCount > 0 && count == resourceCount {
			// last resource to be included in chunk
			err = callback(addr, aidx, &resData, buf, true)
			return pendingResourceRow{}, count, err
		}
		err = callback(addr, aidx, &resData, buf, false)
		if err != nil {
			return pendingResourceRow{}, count, err
		}
	}
	return pendingResourceRow{}, count, nil
}
