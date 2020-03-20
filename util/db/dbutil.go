// Copyright (C) 2019-2020 Algorand, Inc.
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
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
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
var sqliteInitOnce sync.Once

// An Accessor manages a sqlite database handle and any outstanding batching operations.
type Accessor struct {
	Handle   *sql.DB
	readOnly bool
	log      logging.Logger
}

type sqliteDriverConnections struct {
	initilizationError error
}

var sqliteConnections sqliteDriverConnections

// MakeAccessor creates a new Accessor.
func MakeAccessor(dbfilename string, readOnly bool, inMemory bool) (Accessor, error) {
	return makeAccessorImpl(dbfilename, readOnly, inMemory, []string{"_journal_mode=wal"})
}

// MakeErasableAccessor creates a new Accessor with the secure_delete pragma set;
// see https://www.sqlite.org/pragma.html#pragma_secure_delete
// It is not read-only and not in-memory (otherwise, erasability doesn't matter)
func MakeErasableAccessor(dbfilename string) (Accessor, error) {
	return makeAccessorImpl(dbfilename, false, false, []string{"_secure_delete=on"})
}

func sqlite3Init() {
	// SQLite3 driver we use (mattn/go-sqlite3) does not implement driver.DriverContext interface
	// that forces sql.Open calling sql.OpenDB and return a struct without any touches to the underlying driver.
	// Because of that SQLite library is not initialized until the very first call of sqlite3_open_v2 that happens
	// in sql.DB.conn. SQLite initialization is not thread-safe on date of writing (2/27/2020) and
	// mattn/go-sqlite3 has no special code to handle this case.
	// Solution is to create a connection using a safe synchronization barrier right here.
	// The connection goes to a connection pool inside Go's sql package and will be re-used when needed.
	// See https://github.com/algorand/go-algorand/issues/846 for more details.

	// we create a dummy in-memory database and close it right after. This would suffice to initialize the sqlite library threading logic.
	var dbHandler *sql.DB
	dbHandler, sqliteConnections.initilizationError = sql.Open("sqlite3", URI("algorand-sqlite3-database-initializer", false, true)+"&_journal_mode=wal")
	if sqliteConnections.initilizationError != nil {
		return
	}
	sqliteConnections.initilizationError = dbHandler.Ping()
	if sqliteConnections.initilizationError != nil {
		return
	}
	sqliteConnections.initilizationError = dbHandler.Close()
	if sqliteConnections.initilizationError != nil {
		return
	}
}

func makeAccessorImpl(dbfilename string, readOnly bool, inMemory bool, params []string) (db Accessor, err error) {
	sqliteInitOnce.Do(sqlite3Init)

	db.readOnly = readOnly

	parameters := ""
	if len(params) > 0 {
		parameters = "&" + strings.Join(params, "&")
	}
	db.Handle, err = sql.Open("sqlite3", URI(dbfilename, readOnly, inMemory)+parameters)
	if err != nil {
		return Accessor{}, err
	}

	err = db.runInitStatements()

	return db, err
}

// runInitStatements executes initialization statements.
func (db *Accessor) runInitStatements() error {
	for _, stmt := range initStatements {
		_, err := db.Handle.Exec(stmt)
		if err != nil {
			db.Close()
			return err
		}
	}

	return nil
}

// SetLogger sets the Logger, mainly for unit test quietness
func (db *Accessor) SetLogger(log logging.Logger) {
	db.log = log
}

func (db *Accessor) logger() logging.Logger {
	if db.log != nil {
		return db.log
	}
	return logging.Base()
}

// Close closes the connection.
func (db *Accessor) Close() {
	db.Handle.Close()
	db.Handle = nil
}

// LoggedRetry executes a function repeatedly as long as it returns an error
// that indicates database contention that warrants a retry.
// Sends warnings and errors to log.
func LoggedRetry(fn func() error, log logging.Logger) (err error) {
	for i := 0; (i == 0) || dbretry(err); i++ {
		if i > 0 {
			if i < infoTxRetries {
				log.Infof("db.LoggedRetry: %d retries (last err: %v)", i, err)
			} else if i >= 1000 {
				log.Errorf("db.LoggedRetry: %d retries (last err: %v)", i, err)
				return
			} else if i%warnTxRetriesInterval == 0 {
				log.Warnf("db.LoggedRetry: %d retries (last err: %v)", i, err)
			}
		}
		err = fn()
	}
	return
}

// Retry executes a function repeatedly as long as it returns an error
// that indicates database contention that warrants a retry.
// Sends warnings and errors to logging.Base()
func Retry(fn func() error) (err error) {
	return LoggedRetry(fn, logging.Base())
}

// getDecoratedLogger retruns a decorated logger that includes the readonly true/false, caller and extra fields.
func (db *Accessor) getDecoratedLogger(fn idemFn, extras ...interface{}) logging.Logger {
	log := db.logger().With("readonly", db.readOnly)
	_, file, line, ok := runtime.Caller(2)
	if ok {
		log = log.With("caller", fmt.Sprintf("%s:%d", file, line))
	}
	log = log.With("callee", runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name())
	for i, e := range extras {
		if e == nil || reflect.ValueOf(e).IsNil() {
			continue
		}
		log = log.With(fmt.Sprintf("extra(%d)", i), e)
	}

	return log
}

// Atomic executes a piece of code with respect to the database atomically.
// For transactions where readOnly is false, sync determines whether or not to wait for the result.
func (db *Accessor) Atomic(fn idemFn, extras ...interface{}) (err error) {
	start := time.Now()

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
	var conn *sql.Conn
	ctx := context.Background()

	for i := 0; (i == 0) || dbretry(err); i++ {
		if i > 0 {
			if i < infoTxRetries {
				db.getDecoratedLogger(fn, extras).Infof("db.atomic: %d connection retries (last err: %v)", i, err)
			} else if i >= 1000 {
				db.getDecoratedLogger(fn, extras).Errorf("db.atomic: %d connection retries (last err: %v)", i, err)
				break
			} else if i%warnTxRetriesInterval == 0 {
				db.getDecoratedLogger(fn, extras).Warnf("db.atomic: %d connection retries (last err: %v)", i, err)
			}
		}
		conn, err = db.Handle.Conn(ctx)
	}

	if err != nil {
		return
	}
	defer conn.Close()

	for i := 0; ; i++ {
		if i > 0 {
			if i < infoTxRetries {
				db.getDecoratedLogger(fn, extras).Infof("db.atomic: %d retries (last err: %v)", i, err)
			} else if i >= 1000 {
				db.getDecoratedLogger(fn, extras).Errorf("db.atomic: %d retries (last err: %v)", i, err)
				break
			} else if i%warnTxRetriesInterval == 0 {
				db.getDecoratedLogger(fn, extras).Warnf("db.atomic: %d retries (last err: %v)", i, err)
			}
		}

		tx, err = conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: db.readOnly})
		if dbretry(err) {
			continue
		} else if err != nil {
			break
		}

		err = guardedFn(tx)
		if err != nil {
			tx.Rollback()
			if dbretry(err) {
				continue
			} else {
				break
			}
		}

		err = tx.Commit()
		if err == nil {
			break
		} else if !dbretry(err) {
			break
		}
	}

	end := time.Now()
	delta := end.Sub(start)
	if delta > time.Second {
		db.getDecoratedLogger(fn, extras).Warnf("dbatomic: tx took %v", delta)
	} else if delta > time.Millisecond {
		db.getDecoratedLogger(fn, extras).Debugf("dbatomic: tx took %v", delta)
	}
	return
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

const infoTxRetries = 5
const warnTxRetriesInterval = 1

// BackupAccessor encapsulate the online backup API functionality
type BackupAccessor struct {
	backup         *sqlite3.SQLiteBackup
	backupFinished chan bool
	destAccessor   Accessor
}

// Checkpoint create a wal checkpoint, forcing the content of the WAL file to be flushed into the main database.
func (db *Accessor) Checkpoint(ctx context.Context) (err error) {
	var conn *sql.Conn
	conn, err = db.Handle.Conn(ctx)
	if err != nil {
		return
	}
	defer conn.Close()
	_, err = conn.ExecContext(ctx, "PRAGMA wal_checkpoint")
	return
}

var errUnexpectedDriverConnector = errors.New("unexpected driver connector")
var errNoBackupObjectExists = errors.New("no backup object")

// Backup starts a backup of the existing database onto the destination database.
func (db *Accessor) Backup(ctx context.Context, destDbFilename string, inMem bool) (backupAccessor *BackupAccessor, err error) {
	backupStarted := make(chan bool, 1)

	// we want to create the two connection and hold them open for a long time ( until the backup object is destroyed )
	go func() {
		var srcConn, dstConn *sql.Conn
		srcConn, err = db.Handle.Conn(ctx)
		if err != nil {
			close(backupStarted)
			return
		}

		err = srcConn.Raw(func(driverConn interface{}) error {
			srcDriverConnector := driverConn.(*sqlite3.SQLiteConn)
			if srcDriverConnector == nil {
				return errUnexpectedDriverConnector
			}
			// cool, we have a driver connector.
			destAccessor, err := makeAccessorImpl(destDbFilename, false, inMem, []string{})
			if err != nil {
				return err
			}

			dstConn, err = destAccessor.Handle.Conn(ctx)
			if err != nil {
				destAccessor.Close()
				return err
			}

			err = dstConn.Raw(func(driverConn interface{}) error {
				dstDriverConnector := driverConn.(*sqlite3.SQLiteConn)
				if dstDriverConnector == nil {
					return errUnexpectedDriverConnector
				}
				backup, err := dstDriverConnector.Backup("main", srcDriverConnector, "main")
				if err != nil {
					return err
				}
				backupAccessor = &BackupAccessor{
					backup:         backup,
					backupFinished: make(chan bool, 1),
					destAccessor:   destAccessor,
				}
				close(backupStarted)
				// wait for "finish" to be called.
				<-backupAccessor.backupFinished
				return nil
			})

			dstConn.Close()
			if err != nil {
				destAccessor.Close()
			}
			return err
		})
		srcConn.Close()
		if err != nil {
			close(backupStarted)
			return
		}
	}()
	// wait until the backup accessor is created, or fail to create ( where the err would be set )
	select {
	case <-backupStarted:
		return backupAccessor, err
	case <-ctx.Done():
		return backupAccessor, ctx.Err()
	}
}

// PageCount returns the page count needed for the backup.
func (ba *BackupAccessor) PageCount() int {
	if ba.backup != nil {
		return ba.backup.PageCount()
	}
	return -1
}

// Remaining returns the remaining page count for the backup to complete.
func (ba *BackupAccessor) Remaining() int {
	if ba.backup != nil {
		return ba.backup.Remaining()
	}
	return -1
}

// Step copy p number of pages
func (ba *BackupAccessor) Step(p int) (bool, error) {
	if ba.backup != nil {
		return ba.backup.Step(p)
	}
	return false, errNoBackupObjectExists
}

// Finish completes the backup process
func (ba *BackupAccessor) Finish() (Accessor, error) {
	if ba.backup != nil {
		err := ba.backup.Finish()
		close(ba.backupFinished)
		ba.destAccessor.Checkpoint(context.Background())
		ba.backup = nil
		destAccessor := ba.destAccessor
		ba.destAccessor = Accessor{}
		return destAccessor, err
	}
	return Accessor{}, errNoBackupObjectExists
}
