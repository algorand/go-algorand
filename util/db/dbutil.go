// Copyright (C) 2019 Algorand, Inc.
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

// Package db defines database utility functions.
//
// These functions currently work on a sqlite database.
// Other databases may not work with functions in this package.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/mattn/go-sqlite3"

	"github.com/algorand/go-algorand/logging"
)

/* database utils */

// busy is the time to wait for a sqlite lock from another process, in ms.
// This causes sqlite to wait before returning SQLITE_BUSY.  On the other
// hand, conflicts with other connections from the same process (e.g., algod)
// might contend on the shared cache, which corresponds to SQLITE_LOCKED and
// is not covered by the busy timeout.  We rely on sqlite_unlock_notify()
// to wait for the shared cache lock to be released.  This is enabled in
// go-sqlite3 with the "sqlite_unlock_notify" Go build tag.
const busy = 1000

// initStatements is a list of statements we execute after opening a database
// connection.  For now, it's just an optional "PRAGMA fullfsync=true" on
// MacOSX.
var initStatements []string

// An Accessor manages a sqlite database handle and any outstanding batching operations.
type Accessor struct {
	Handle   *sql.DB
	readOnly bool
}

// MakeAccessor creates a new Accessor.
func MakeAccessor(dbfilename string, readOnly bool, inMemory bool) (Accessor, error) {
	var db Accessor
	db.readOnly = readOnly

	var err error
	db.Handle, err = sql.Open("sqlite3", URI(dbfilename, readOnly, inMemory)+"&_journal_mode=wal")

	if err == nil {
		err = db.runInitStatements()
	}

	return db, err
}

// MakeErasableAccessor creates a new Accessor with the secure_delete pragma set;
// see https://www.sqlite.org/pragma.html#pragma_secure_delete
// It is not read-only and not in-memory (otherwise, erasability doesn't matter)
func MakeErasableAccessor(dbfilename string) (Accessor, error) {
	var db Accessor
	db.readOnly = false

	var err error
	db.Handle, err = sql.Open("sqlite3", URI(dbfilename, false, false)+"&_secure_delete=on")

	if err == nil {
		err = db.runInitStatements()
	}

	return db, err
}

// runInitStatements executes initialization statements.
func (db Accessor) runInitStatements() error {
	for _, stmt := range initStatements {
		_, err := db.Handle.Exec(stmt)
		if err != nil {
			db.Handle.Close()
			return err
		}
	}

	return nil
}

// Close closes the connection.
func (db Accessor) Close() {
	db.Handle.Close()
	db.Handle = nil
}

// Retry executes a function repeatedly as long as it returns an error
// that indicates database contention that warrants a retry.
func Retry(fn func() error) (err error) {
	for i := 0; ; i++ {
		if i > 0 && i%warnTxRetries == 0 {
			if i >= 1000 {
				logging.Base().Errorf("db.Retry: %d retries (last err: %v)", i, err)
				return
			}
			logging.Base().Warnf("db.Retry: %d retries (last err: %v)", i, err)
		}

		err = fn()
		if dbretry(err) {
			continue
		}

		return
	}
}

// Atomic executes a piece of code with respect to the database atomically.
// For transactions where readOnly is false, sync determines whether or not to wait for the result.
func (db Accessor) Atomic(fnDescription string, fn idemFn) (err error) {
	descr := "w"
	if db.readOnly {
		descr = "r"
	}

	start := time.Now()
	defer func() {
		end := time.Now()
		delta := end.Sub(start)
		if delta > time.Second {
			logging.Base().With("description", fnDescription).Warnf("dbatomic(%v): tx took %v", descr, delta)
		} else if delta > time.Millisecond {
			logging.Base().With("description", fnDescription).Debugf("dbatomic(%v): tx took %v", descr, delta)
		}
	}()

	// note that the sql library will drop panics inside an active transaction
	guardedFn := func(tx *sql.Tx) (err error) {
		defer func() {
			if r := recover(); r != nil {
				var ok bool
				err, ok = r.(error)
				if !ok {
					err = fmt.Errorf("%v", r)
				}
			}
		}()

		err = fn(tx)
		return
	}

	var tx *sql.Tx
	ctx := context.Background()
	var conn *sql.Conn
	conn, err = db.Handle.Conn(ctx)
	if err != nil {
		return
	}
	defer conn.Close()

	for i := 0; ; i++ {
		if i > 0 && i%warnTxRetries == 0 {
			if i >= 1000 {
				logging.Base().Errorf("dbatomic(%v): %d retries (last err: %v)", descr, i, err)
				return
			}
			logging.Base().With("description", fnDescription).Warnf("dbatomic(%v): %d retries (last err: %v)", descr, i, err)
		}

		tx, err = conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: db.readOnly})
		if dbretry(err) {
			continue
		} else if err != nil {
			return
		}

		err = guardedFn(tx)
		if err != nil {
			tx.Rollback()
			if dbretry(err) {
				continue
			} else {
				return
			}
		}

		err = tx.Commit()
		if err == nil {
			return
		} else if !dbretry(err) {
			return
		}
	}
}

// URI returns the sqlite URI given a db filename as an input.
func URI(filename string, readOnly bool, memory bool) string {
	uri := fmt.Sprintf("file:%s?_busy_timeout=%d&_synchronous=full", filename, busy)
	if !readOnly {
		uri += "&_txlock=immediate"
	}
	if memory {
		uri += "&mode=memory"
		uri += "&cache=shared"
	}
	return uri
}

// dbretry returns true if the error might be temporary
func dbretry(obj error) bool {
	err, ok := obj.(sqlite3.Error)
	return ok && (err.Code == sqlite3.ErrLocked || err.Code == sqlite3.ErrBusy)
}

type idemFn func(tx *sql.Tx) error

const warnTxRetries = 1
