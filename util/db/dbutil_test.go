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

package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
)

func TestInMemoryDisposal(t *testing.T) {
	acc, err := MakeAccessor("fn.db", false, true)
	require.NoError(t, err)
	err = acc.Atomic(func(tx *sql.Tx) error {
		_, err := tx.Exec("create table Service (data blob)")
		return err
	})
	require.NoError(t, err)

	err = acc.Atomic(func(tx *sql.Tx) error {
		raw := []byte{0, 1, 2}
		_, err := tx.Exec("insert or replace into Service (rowid, data) values (1, ?)", raw)
		return err
	})
	require.NoError(t, err)

	anotherAcc, err := MakeAccessor("fn.db", false, true)
	require.NoError(t, err)
	err = anotherAcc.Atomic(func(tx *sql.Tx) error {
		var nrows int
		row := tx.QueryRow("select count(*) from Service")
		err := row.Scan(&nrows)
		return err
	})
	require.NoError(t, err)
	anotherAcc.Close()

	acc.Close()

	acc, err = MakeAccessor("fn.db", false, true)
	require.NoError(t, err)
	err = acc.Atomic(func(tx *sql.Tx) error {
		var nrows int
		row := tx.QueryRow("select count(*) from Service")
		err := row.Scan(&nrows)
		if err == nil {
			return errors.New("table `Service` presents while it should not")
		}
		return nil
	})
	require.NoError(t, err)

	acc.Close()
}

func TestInMemoryUniqueDB(t *testing.T) {
	acc, err := MakeAccessor("fn.db", false, true)
	require.NoError(t, err)
	defer acc.Close()
	err = acc.Atomic(func(tx *sql.Tx) error {
		_, err := tx.Exec("create table Service (data blob)")
		return err
	})
	require.NoError(t, err)

	err = acc.Atomic(func(tx *sql.Tx) error {
		raw := []byte{0, 1, 2}
		_, err := tx.Exec("insert or replace into Service (rowid, data) values (1, ?)", raw)
		return err
	})
	require.NoError(t, err)

	anotherAcc, err := MakeAccessor("fn2.db", false, true)
	require.NoError(t, err)
	defer anotherAcc.Close()
	err = anotherAcc.Atomic(func(tx *sql.Tx) error {
		var nrows int
		row := tx.QueryRow("select count(*) from Service")
		err := row.Scan(&nrows)
		if err == nil {
			return errors.New("table `Service` presents while it should not")
		}
		return nil
	})
	require.NoError(t, err)
}

func TestDBConcurrency(t *testing.T) {
	fn := fmt.Sprintf("/tmp/%s.%d.sqlite3", t.Name(), crypto.RandUint64())
	defer cleanupSqliteDb(t, fn)

	acc, err := MakeAccessor(fn, false, false)
	require.NoError(t, err)
	defer acc.Close()

	acc2, err := MakeAccessor(fn, true, false)
	require.NoError(t, err)
	defer acc2.Close()

	err = acc.Atomic(func(tx *sql.Tx) error {
		_, err := tx.Exec("CREATE TABLE foo (a INTEGER, b INTEGER)")
		return err
	})
	require.NoError(t, err)

	err = acc.Atomic(func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO foo (a, b) VALUES (?, ?)", 1, 1)
		return err
	})
	require.NoError(t, err)

	c1 := make(chan struct{})
	c2 := make(chan struct{})
	go func() {
		err := acc.Atomic(func(tx *sql.Tx) error {
			<-c2

			_, err := tx.Exec("INSERT INTO foo (a, b) VALUES (?, ?)", 2, 2)
			if err != nil {
				return err
			}

			c1 <- struct{}{}
			<-c2

			_, err = tx.Exec("INSERT INTO foo (a, b) VALUES (?, ?)", 3, 3)
			if err != nil {
				return err
			}

			return nil
		})

		require.NoError(t, err)
		c1 <- struct{}{}
	}()

	err = acc2.Atomic(func(tx *sql.Tx) error {
		var nrows int64
		err := tx.QueryRow("SELECT COUNT(*) FROM foo").Scan(&nrows)
		if err != nil {
			return err
		}

		if nrows != 1 {
			return fmt.Errorf("row count mismatch: %d != 1", nrows)
		}

		return nil
	})
	require.NoError(t, err)

	c2 <- struct{}{}
	<-c1

	err = acc2.Atomic(func(tx *sql.Tx) error {
		var nrows int64
		err := tx.QueryRow("SELECT COUNT(*) FROM foo").Scan(&nrows)
		if err != nil {
			return err
		}

		if nrows != 1 {
			return fmt.Errorf("row count mismatch: %d != 1", nrows)
		}

		return nil
	})
	require.NoError(t, err)

	c2 <- struct{}{}
	<-c1

	err = acc2.Atomic(func(tx *sql.Tx) error {
		var nrows int64
		err := tx.QueryRow("SELECT COUNT(*) FROM foo").Scan(&nrows)
		if err != nil {
			return err
		}

		if nrows != 3 {
			return fmt.Errorf("row count mismatch: %d != 3", nrows)
		}

		return nil
	})
	require.NoError(t, err)
}

func cleanupSqliteDb(t *testing.T, path string) {
	parts, err := filepath.Glob(path + "*")
	if err != nil {
		t.Errorf("%s*: could not glob, %s", path, err)
		return
	}
	for _, part := range parts {
		err = os.Remove(part)
		if err != nil {
			t.Errorf("%s: error cleaning up, %s", part, err)
		}
	}
}

func TestDBConcurrencyRW(t *testing.T) {
	dbFolder := "/dev/shm"
	os := runtime.GOOS
	if os == "darwin" {
		var err error
		dbFolder, err = ioutil.TempDir("", "TestDBConcurrencyRW")
		if err != nil {
			panic(err)
		}
	}

	fn := fmt.Sprintf("/%s.%d.sqlite3", t.Name(), crypto.RandUint64())
	fn = filepath.Join(dbFolder, fn)
	defer cleanupSqliteDb(t, fn)

	acc, err := MakeAccessor(fn, false, false)
	require.NoError(t, err)
	defer acc.Close()

	acc2, err := MakeAccessor(fn, true, false)
	require.NoError(t, err)
	defer acc2.Close()

	err = acc.Atomic(func(tx *sql.Tx) error {
		_, err := tx.Exec("CREATE TABLE t (a INTEGER PRIMARY KEY)")
		return err
	})
	require.NoError(t, err)

	started := make(chan struct{})
	var lastInsert int64
	testRoutineComplete := make(chan struct{}, 3)
	targetTestDurationTimer := time.After(15 * time.Second)
	go func() {
		defer func() {
			atomic.StoreInt64(&lastInsert, -1)
			testRoutineComplete <- struct{}{}
		}()
		var errw error
		for i, timedLoop := int64(1), true; timedLoop && errw == nil; i++ {
			errw = acc.Atomic(func(tx *sql.Tx) error {
				_, err := tx.Exec("INSERT INTO t (a) VALUES (?)", i)
				return err
			})
			if errw == nil {
				atomic.StoreInt64(&lastInsert, i)
			}
			if i == 1 {
				close(started)
			}
			select {
			case <-targetTestDurationTimer:
				// abort the for loop.
				timedLoop = false
			default:
				// keep going.
			}
		}
		require.NoError(t, errw)
	}()

	for i := 0; i < 2; i++ {
		go func() {
			defer func() {
				testRoutineComplete <- struct{}{}
			}()
			select {
			case <-started:
			case <-time.After(10 * time.Second):
				t.Error("timeout")
				return
			}
			for {
				id := atomic.LoadInt64(&lastInsert)
				if id == 0 {
					// we have yet to complete the first item insertion, yet,
					// the "started" channel is closed. This happen only in case of
					// an error during the insert ( which is reported above)
					break
				} else if id < 0 {
					break
				}
				var x int64
				errsel := acc2.Atomic(func(tx *sql.Tx) error {
					return tx.QueryRow("SELECT a FROM t WHERE a=?", id).Scan(&x)
				})
				if errsel != nil {
					t.Errorf("selecting %d: %v", id, errsel)
				}
				require.Equal(t, x, id)
			}
		}()
	}

	testTimeout := time.After(3 * time.Minute)
	for i := 0; i < 3; i++ {
		select {
		case <-testRoutineComplete:
			// good. keep going.
		case <-testTimeout:
			// the test has timed out. we want to abort now with a failuire since we might be stuck in one of the goroutines above.
			lastID := atomic.LoadInt64(&lastInsert)
			t.Errorf("Test has timed out. Last id is %d.\n", lastID)
		}
	}

}

func TestDBBackup(t *testing.T) {
	os.Remove("fn.db")
	os.Remove("fn.db-shm")
	os.Remove("fn.db-wal")
	os.Remove("fn-copy.db")
	os.Remove("fn-copy.db-shm")
	os.Remove("fn-copy.db-wal")
	acc, err := MakeAccessor("fn.db", false, false)
	require.NoError(t, err)
	err = acc.Atomic(func(tx *sql.Tx) error {
		_, err := tx.Exec("create table Service (id int, data blob)")
		return err
	})
	require.NoError(t, err)
	const entriesCount = 100

	blob := []byte(fmt.Sprintf("%v", rand.Perm(1024)))
	for i := 0; i < entriesCount; i++ {
		err = acc.Atomic(func(tx *sql.Tx) error {
			_, err := tx.Exec("insert into Service (id, data) values (?, ?)", i, blob)
			return err
		})
		require.NoError(t, err)
	}
	err = acc.Checkpoint(context.Background())
	require.NoError(t, err)
	var nrows int
	err = acc.Atomic(func(tx *sql.Tx) error {
		row := tx.QueryRow("select count(*) from Service")
		err := row.Scan(&nrows)
		return err
	})
	require.NoError(t, err)
	require.Equal(t, entriesCount, nrows)

	backupAccessor, err := acc.Backup(context.Background(), "fn-copy.db")
	require.NoError(t, err)
	require.NotNil(t, backupAccessor)

	// call Step just to iniialize the remaining and page count.
	var complete bool
	complete, err = backupAccessor.Step(0)
	require.NoError(t, err)
	require.False(t, complete)
	remaining, total := 0, 0
	for {
		remaining = backupAccessor.Remaining()
		total = backupAccessor.PageCount()
		if remaining == 0 {
			break
		}
		if remaining-((remaining+1)/2) == 0 {
			// make sure to avoid completing the copy.
			break
		}
		complete, err = backupAccessor.Step((remaining + 1) / 2)
		if complete {
			break
		}
		require.NoError(t, err)
	}
	require.NotEqual(t, 0, total)

	// add one more entry to the source database before Finish is called.
	err = acc.Atomic(func(tx *sql.Tx) error {
		_, err := tx.Exec("insert into Service (id, data) values (?, ?)", entriesCount+1, blob)
		return err
	})
	require.NoError(t, err)
	backupAccessor.Step(-1)

	acc.Close()

	acc, err = backupAccessor.Finish()
	require.NoError(t, err)

	nrows = 0
	err = acc.Atomic(func(tx *sql.Tx) error {
		row := tx.QueryRow("select count(*) from Service")
		err := row.Scan(&nrows)
		return err
	})
	require.NoError(t, err)
	require.Equal(t, entriesCount+1, nrows)
	acc.Close()
	os.Remove("fn.db")
	os.Remove("fn.db-shm")
	os.Remove("fn.db-wal")
	os.Remove("fn-copy.db")
	os.Remove("fn-copy.db-shm")
	os.Remove("fn-copy.db-wal")
}

// TestDBWritingWhileReading
// this test demonstate what happens when trying to start a writing operarion while
// a long-running reading opeartion is taking place when the two accessors are opened in a read-write mode.
func TestDBWritingWhileReading(t *testing.T) {
	dbname := "fn.db"
	os.Remove(dbname)
	os.Remove(dbname + "-shm")
	os.Remove(dbname + "-wal")
	const entriesCount = 200

	createDatabaseWithEntries := func() {
		acc, err := MakeAccessor(dbname, false, false)
		require.NoError(t, err)
		defer acc.Close()
		err = acc.Atomic(func(tx *sql.Tx) error {
			_, err := tx.Exec("create table Service (id int, data blob)")
			return err
		})
		require.NoError(t, err)

		blob := []byte(fmt.Sprintf("%v", rand.Perm(1024)))
		for i := 0; i < entriesCount; i++ {
			err = acc.Atomic(func(tx *sql.Tx) error {
				_, err := tx.Exec("insert into Service (id, data) values (?, ?)", i, blob)
				return err
			})
			require.NoError(t, err)
		}
		err = acc.Checkpoint(context.Background())
		require.NoError(t, err)

	}
	readingInProgress := make(chan bool, 1)
	readingComplete := make(chan bool, 1)
	var readingCompletedTime time.Time
	readDatabaseWithEntries := func() {
		acc, err := MakeAccessor(dbname, true, false)
		require.NoError(t, err)
		defer func() {
			acc.Close()
			readingCompletedTime = time.Now()
			close(readingComplete)
		}()
		err = acc.Atomic(func(tx *sql.Tx) error {
			rows, err := tx.Query("select id, data from Service")
			require.NoError(t, err)
			defer rows.Close()
			var rowid int
			var data []byte
			firstRead := true
			for rows.Next() {
				err := rows.Scan(&rowid, &data)
				if err != nil {
					return err
				}
				require.True(t, rowid < entriesCount)
				if firstRead {
					firstRead = false
					close(readingInProgress)
				}
				time.Sleep(10 * time.Millisecond)
			}
			return err
		})
	}

	writeComplete := make(chan bool, 1)
	var firstItemWriteTime time.Time
	writeDatabaseWithEntries := func() {
		acc, err := MakeAccessor(dbname, false, false)
		require.NoError(t, err)
		defer func() {
			acc.Close()
			close(writeComplete)
		}()
		blob := []byte(fmt.Sprintf("%v", rand.Perm(1024)))
		for i := entriesCount; i < entriesCount+1; i++ {
			err = acc.Atomic(func(tx *sql.Tx) error {
				_, err := tx.Exec("insert into Service (id, data) values (?, ?)", i, blob)
				return err
			})
			require.NoError(t, err)
			if i == entriesCount {
				firstItemWriteTime = time.Now()
			}
		}
	}

	createDatabaseWithEntries()
	go readDatabaseWithEntries()
	<-readingInProgress           // wait until the first reading completed, so that we know the reading transaction was created
	go writeDatabaseWithEntries() // try to write. the expectancy is that this would get blocked until the reading for all the items is complete
	<-readingComplete
	<-writeComplete

	//require.True(t, firstItemWriteTime.After(readingCompletedTime))
	if firstItemWriteTime.After(readingCompletedTime) {
		os.Remove(dbname)
	}
	os.Remove(dbname)
	os.Remove(dbname + "-shm")
	os.Remove(dbname + "-wal")

}
