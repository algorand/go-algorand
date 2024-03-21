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

	"github.com/algorand/go-algorand/util/db"
)

// catchpointPendingHashesIterator allows us to iterate over the hashes in the catchpointpendinghashes table in their order.
type catchpointPendingHashesIterator struct {
	hashCount int
	q         db.Queryable
	rows      *sql.Rows
}

// MakeCatchpointPendingHashesIterator create a pending hashes iterator that retrieves the hashes in the catchpointpendinghashes table.
func MakeCatchpointPendingHashesIterator(hashCount int, q db.Queryable) *catchpointPendingHashesIterator {
	return &catchpointPendingHashesIterator{
		hashCount: hashCount,
		q:         q,
	}
}

// Next returns an array containing the hashes, returning HashCount hashes at a time.
func (iterator *catchpointPendingHashesIterator) Next(ctx context.Context) (hashes [][]byte, err error) {
	if iterator.rows == nil {
		iterator.rows, err = iterator.q.QueryContext(ctx, "SELECT data FROM catchpointpendinghashes ORDER BY data")
		if err != nil {
			return
		}
	}

	// gather up to accountCount encoded accounts.
	hashes = make([][]byte, iterator.hashCount)
	hashIdx := 0
	for iterator.rows.Next() {
		err = iterator.rows.Scan(&hashes[hashIdx])
		if err != nil {
			iterator.Close()
			return
		}

		hashIdx++
		if hashIdx == iterator.hashCount {
			// we're done with this iteration.
			return
		}
	}
	hashes = hashes[:hashIdx]
	err = iterator.rows.Err()
	if err != nil {
		iterator.Close()
		return
	}
	// we just finished reading the table.
	iterator.Close()
	return
}

// Close shuts down the catchpointPendingHashesIterator, releasing database resources.
func (iterator *catchpointPendingHashesIterator) Close() {
	if iterator.rows != nil {
		iterator.rows.Close()
		iterator.rows = nil
	}
}
