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
