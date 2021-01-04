// Copyright (C) 2019-2021 Algorand, Inc.
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

package db

import (
	"database/sql"
)

// Queryable is meant to represent the union of a transaction (sql.Tx)
// and the underlying database (sql.DB), so that code issuing a single
// read-only query can be run directly on the sql.DB object without
// creating a short-lived transaction for a single SELECT query.
//
// Queryable captures only a subset of Go's SQL API for issuing reads;
// if new code needs additional methods to query a SQL DB, they should
// be added here as needed.
type Queryable interface {
	Prepare(query string) (*sql.Stmt, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}
