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

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/encoded"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/msgp/msgp"
)

// encodedAccountsBatchIter allows us to iterate over the accounts data stored in the accountbase table.
type encodedAccountsBatchIter struct {
	q               db.Queryable
	accountsRows    *sql.Rows
	resourcesRows   *sql.Rows
	nextBaseRow     pendingBaseRow
	nextResourceRow pendingResourceRow
	acctResCnt      catchpointAccountResourceCounter
}

// catchpointAccountResourceCounter keeps track of the resources processed for the current account
type catchpointAccountResourceCounter struct {
	totalAppParams      uint64
	totalAppLocalStates uint64
	totalAssetParams    uint64
	totalAssets         uint64
}

// MakeEncodedAccoutsBatchIter creates an empty accounts batch iterator.
func MakeEncodedAccoutsBatchIter(q db.Queryable) *encodedAccountsBatchIter {
	return &encodedAccountsBatchIter{q: q}
}

// Next returns an array containing the account data, in the same way it appear in the database
// returning accountCount accounts data at a time.
func (iterator *encodedAccountsBatchIter) Next(ctx context.Context, accountCount int, resourceCount int) (bals []encoded.BalanceRecordV6, numAccountsProcessed uint64, err error) {
	if iterator.accountsRows == nil {
		iterator.accountsRows, err = iterator.q.QueryContext(ctx, "SELECT rowid, address, data FROM accountbase ORDER BY rowid")
		if err != nil {
			return
		}
	}
	if iterator.resourcesRows == nil {
		iterator.resourcesRows, err = iterator.q.QueryContext(ctx, "SELECT addrid, aidx, data FROM resources ORDER BY addrid, aidx")
		if err != nil {
			return
		}
	}

	// gather up to accountCount encoded accounts.
	bals = make([]encoded.BalanceRecordV6, 0, accountCount)
	var encodedRecord encoded.BalanceRecordV6
	var baseAcct trackerdb.BaseAccountData
	var numAcct int
	baseCb := func(addr basics.Address, rowid int64, accountData *trackerdb.BaseAccountData, encodedAccountData []byte) (err error) {
		encodedRecord = encoded.BalanceRecordV6{Address: addr, AccountData: encodedAccountData}
		baseAcct = *accountData
		numAcct++
		return nil
	}

	var totalResources int

	// emptyCount := 0
	resCb := func(addr basics.Address, cidx basics.CreatableIndex, resData *trackerdb.ResourcesData, encodedResourceData []byte, lastResource bool) error {

		emptyBaseAcct := baseAcct.TotalAppParams == 0 && baseAcct.TotalAppLocalStates == 0 && baseAcct.TotalAssetParams == 0 && baseAcct.TotalAssets == 0
		if !emptyBaseAcct && resData != nil {
			if encodedRecord.Resources == nil {
				encodedRecord.Resources = make(map[uint64]msgp.Raw)
			}
			encodedRecord.Resources[uint64(cidx)] = encodedResourceData
			if resData.IsApp() && resData.IsOwning() {
				iterator.acctResCnt.totalAppParams++
			}
			if resData.IsApp() && resData.IsHolding() {
				iterator.acctResCnt.totalAppLocalStates++
			}

			if resData.IsAsset() && resData.IsOwning() {
				iterator.acctResCnt.totalAssetParams++
			}
			if resData.IsAsset() && resData.IsHolding() {
				iterator.acctResCnt.totalAssets++
			}
			totalResources++
		}

		if baseAcct.TotalAppParams == iterator.acctResCnt.totalAppParams &&
			baseAcct.TotalAppLocalStates == iterator.acctResCnt.totalAppLocalStates &&
			baseAcct.TotalAssetParams == iterator.acctResCnt.totalAssetParams &&
			baseAcct.TotalAssets == iterator.acctResCnt.totalAssets {

			encodedRecord.ExpectingMoreEntries = false
			bals = append(bals, encodedRecord)
			numAccountsProcessed++

			iterator.acctResCnt = catchpointAccountResourceCounter{}

			return nil
		}

		// max resources per chunk reached, stop iterating.
		if lastResource {
			encodedRecord.ExpectingMoreEntries = true
			bals = append(bals, encodedRecord)
			encodedRecord.Resources = nil
		}

		return nil
	}

	_, iterator.nextBaseRow, iterator.nextResourceRow, err = processAllBaseAccountRecords(
		iterator.accountsRows, iterator.resourcesRows,
		baseCb, resCb,
		iterator.nextBaseRow, iterator.nextResourceRow, accountCount, resourceCount,
	)
	if err != nil {
		iterator.Close()
		return
	}

	if len(bals) == accountCount || totalResources == resourceCount {
		// we're done with this iteration.
		return
	}

	err = iterator.accountsRows.Err()
	if err != nil {
		iterator.Close()
		return
	}
	// Do not Close() the iterator here.  It is the caller's responsibility to
	// do so, signalled by the return of an empty chunk. If we Close() here, the
	// next call to Next() will start all over!
	return
}

// Close shuts down the encodedAccountsBatchIter, releasing database resources.
func (iterator *encodedAccountsBatchIter) Close() {
	if iterator.accountsRows != nil {
		iterator.accountsRows.Close()
		iterator.accountsRows = nil
	}
	if iterator.resourcesRows != nil {
		iterator.resourcesRows.Close()
		iterator.resourcesRows = nil
	}
}
