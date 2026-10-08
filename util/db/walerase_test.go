// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

// walEraseFixture is a file-backed erasable database with a table of random
// blobs, each large enough to be recognizable and small enough to stay in
// its leaf page.
type walEraseFixture struct {
	t     *testing.T
	acc   Accessor
	path  string
	blobs [][]byte
}

func newWALEraseFixture(t *testing.T) *walEraseFixture {
	path := filepath.Join(t.TempDir(), "erase.sqlite")
	acc, err := MakeErasableAccessor(path)
	require.NoError(t, err)
	t.Cleanup(acc.Close)
	f := &walEraseFixture{t: t, acc: acc, path: path}
	require.NoError(t, acc.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB)")
		return err
	}))
	// start each test with an empty log
	require.NoError(t, acc.EraseWAL(context.Background(), true))
	require.Zero(t, f.walSize())
	return f
}

// insert adds n random rows in one transaction and returns their blobs.
func (f *walEraseFixture) insert(n int) [][]byte {
	var added [][]byte
	require.NoError(f.t, f.acc.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		for i := 0; i < n; i++ {
			blob := make([]byte, 300)
			_, err := rand.Read(blob)
			require.NoError(f.t, err)
			if _, err := tx.Exec("INSERT INTO t (v) VALUES (?)", blob); err != nil {
				return err
			}
			added = append(added, blob)
		}
		return nil
	}))
	f.blobs = append(f.blobs, added...)
	return added
}

func (f *walEraseFixture) exec(query string, args ...any) {
	require.NoError(f.t, f.acc.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec(query, args...)
		return err
	}))
}

func (f *walEraseFixture) queryInt(query string) (n int64) {
	require.NoError(f.t, f.acc.Handle.QueryRow(query).Scan(&n))
	return n
}

func (f *walEraseFixture) file(suffix string) []byte {
	data, err := os.ReadFile(f.path + suffix)
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(f.t, err)
	return data
}

func (f *walEraseFixture) walSize() int64 {
	return int64(len(f.file("-wal")))
}

func TestEraseWAL(t *testing.T) {
	partitiontest.PartitionTest(t)
	ctx := context.Background()
	f := newWALEraseFixture(t)

	// one transaction in the log: its frames are the current page images,
	// so a routine erase leaves them alone
	first := f.insert(40)
	require.True(t, bytes.Contains(f.file("-wal"), first[0]), "the log does not hold the written rows; the test proves nothing")
	sizeBefore := f.walSize()
	require.NoError(t, f.acc.EraseWAL(ctx, false))
	require.Equal(t, sizeBefore, f.walSize(), "a single-transaction log was rewritten")
	require.True(t, bytes.Contains(f.file("-wal"), first[0]))

	// a second transaction makes the first one's images stale: the delete's
	// new image of the leaf has the row zeroed (secure_delete), the insert's
	// image still holds it
	f.exec("DELETE FROM t WHERE id=1")
	require.True(t, bytes.Contains(f.file("-wal"), first[0]))
	require.NoError(t, f.acc.EraseWAL(ctx, false))
	require.Zero(t, f.walSize(), "the log was not truncated")
	require.False(t, bytes.Contains(f.file(""), first[0]), "deleted row survives in the database file")
	for _, blob := range first[1:] {
		require.True(t, bytes.Contains(f.file(""), blob), "live row missing from the database file")
	}

	// the log restarted at the next write, so a single transaction is all
	// it holds again; all=true erases it regardless
	second := f.insert(40)
	require.True(t, bytes.Contains(f.file("-wal"), second[0]))
	require.NoError(t, f.acc.EraseWAL(ctx, true))
	require.Zero(t, f.walSize())
	require.Equal(t, int64(79), f.queryInt("SELECT count(*) FROM t"))

	// the zero pages of an erase become free pages that the next erase
	// reuses: the database holds its data plus at most the largest log
	// erased, and a routine erase after a deletion does not grow it
	require.Positive(t, f.queryInt("PRAGMA freelist_count"))
	pages := f.queryInt("PRAGMA page_count")
	for id := 2; id <= 6; id += 2 {
		f.exec("DELETE FROM t WHERE id=?", id)
		f.exec("DELETE FROM t WHERE id=?", id+1)
		require.NoError(t, f.acc.EraseWAL(ctx, false))
		require.Zero(t, f.walSize())
		require.Equal(t, pages, f.queryInt("PRAGMA page_count"), "the database grew on a routine erase")
		require.False(t, bytes.Contains(f.file(""), first[id-1]))
	}

	// an empty log (nothing written since) is left alone
	require.NoError(t, f.acc.EraseWAL(ctx, true))
	require.Zero(t, f.walSize())
}

// TestEraseWALLargeLog checks a log larger than a chunk is erased and the
// database grows by at most a chunk of free pages.
func TestEraseWALLargeLog(t *testing.T) {
	partitiontest.PartitionTest(t)
	ctx := context.Background()
	f := newWALEraseFixture(t)

	// ~3 MB in one transaction, about three chunks of log
	var blobs [][]byte
	require.NoError(t, f.acc.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		for i := 0; i < 3000; i++ {
			blob := make([]byte, 1000)
			_, err := rand.Read(blob)
			require.NoError(t, err)
			if _, err := tx.Exec("INSERT INTO t (v) VALUES (?)", blob); err != nil {
				return err
			}
			blobs = append(blobs, blob)
		}
		return nil
	}))
	require.Greater(t, f.walSize(), int64(2*walEraseChunkBytes))
	pagesBefore := f.queryInt("PRAGMA page_count")
	require.NoError(t, f.acc.EraseWAL(ctx, true))
	require.Zero(t, f.walSize())
	growth := f.queryInt("PRAGMA page_count") - pagesBefore
	require.LessOrEqual(t, growth, int64(walEraseChunkBytes/4096+4), "the database grew by more than a chunk")
	require.Equal(t, growth, f.queryInt("PRAGMA freelist_count"))
	for _, blob := range blobs[:50] {
		require.True(t, bytes.Contains(f.file(""), blob))
	}
	require.Equal(t, int64(3000), f.queryInt("SELECT count(*) FROM t"))

	// automatic checkpoints are back on the connection the erase used
	var autoCheckpoint int64
	f.acc.Handle.SetMaxOpenConns(1)
	require.NoError(t, f.acc.Handle.QueryRow("PRAGMA wal_autocheckpoint").Scan(&autoCheckpoint))
	require.Equal(t, int64(1000), autoCheckpoint)
}

// TestEraseWALLogAccounting checks the log inspection that decides whether a
// routine erase has anything to do.
func TestEraseWALLogAccounting(t *testing.T) {
	partitiontest.PartitionTest(t)
	ctx := context.Background()
	f := newWALEraseFixture(t)
	walPath := f.path + "-wal"

	// two transactions since the log was last restarted
	f.insert(40)
	f.exec("DELETE FROM t WHERE id=1")
	_, logFrames, _, err := f.acc.walCheckpoint(ctx, "PASSIVE")
	require.NoError(t, err)
	info, err := readWALFileInfo(walPath, logFrames, walMaxParsedFrames)
	require.NoError(t, err)
	require.Equal(t, int64(4096), info.pageSize)
	require.Equal(t, logFrames, info.frames)
	require.True(t, info.parsed && info.current)
	require.Equal(t, int64(2), info.commits)
	require.False(t, info.allCurrent())

	// after a restart the log holds one transaction but the file still
	// extends to the previous generation's frames
	require.NoError(t, f.acc.EraseWAL(ctx, false)) // truncates
	f.insert(40)
	f.exec("DELETE FROM t WHERE id=2")
	_, _, _, err = f.acc.walCheckpoint(ctx, "RESTART")
	require.NoError(t, err)
	f.exec("DELETE FROM t WHERE id=3") // restarts the log
	_, logFrames, _, err = f.acc.walCheckpoint(ctx, "PASSIVE")
	require.NoError(t, err)
	info, err = readWALFileInfo(walPath, logFrames, walMaxParsedFrames)
	require.NoError(t, err)
	require.True(t, info.allCurrent())
	require.Greater(t, info.frames, logFrames, "older frames beyond the restarted log")

	// a log longer than the inspection limit is not inspected
	info, err = readWALFileInfo(walPath, logFrames, logFrames-1)
	require.NoError(t, err)
	require.False(t, info.parsed)
	require.False(t, info.allCurrent())

	// a missing log
	info, err = readWALFileInfo(filepath.Join(t.TempDir(), "none-wal"), 0, walMaxParsedFrames)
	require.NoError(t, err)
	require.Zero(t, info.frames)
}

// walPageImages returns the page image of every frame of the log.
func (f *walEraseFixture) walPageImages() [][]byte {
	data := f.file("-wal")
	var images [][]byte
	for off := int64(walHeaderSize); off+walFrameHeaderSize+4096 <= int64(len(data)); off += walFrameHeaderSize + 4096 {
		images = append(images, data[off+walFrameHeaderSize:off+walFrameHeaderSize+4096])
	}
	return images
}

// TestEraseWALOverwritesBeforeTruncate looks at the log after the zero pages
// were written and before it is truncated: every frame of the old extent is
// overwritten (truncation alone would only release the bytes), and the only
// page images that are not all zeros are the few structural pages a chunk
// touches (the first page, the scratch table's root, the free-list trunk).
func TestEraseWALOverwritesBeforeTruncate(t *testing.T) {
	partitiontest.PartitionTest(t)
	ctx := context.Background()
	f := newWALEraseFixture(t)
	first := f.insert(40)
	f.exec("DELETE FROM t WHERE id=1")
	require.True(t, bytes.Contains(f.file("-wal"), first[0]))
	sizeBefore := f.walSize()

	inspected := false
	f.acc.eraseWALAfterOverwrite = func() {
		inspected = true
		require.GreaterOrEqual(t, f.walSize(), sizeBefore, "the log was truncated before being overwritten")
		require.False(t, bytes.Contains(f.file("-wal"), first[0]), "the deleted row's image survived the overwrite")
		nonZero := 0
		for _, image := range f.walPageImages() {
			if bytes.ContainsFunc(image, func(r rune) bool { return r != 0 }) {
				nonZero++
			}
		}
		require.LessOrEqual(t, nonZero, 3, "more than the structural pages are not zero")
	}
	require.NoError(t, f.acc.EraseWAL(ctx, false))
	require.True(t, inspected)
	require.Zero(t, f.walSize())
}

// TestEraseWALRefusesToTruncateAfterConcurrentWrite checks a transaction
// another connection commits while the log is being erased is detected: the
// erase fails instead of truncating, so the frames are not released
// unerased, and the next erase covers them.
func TestEraseWALRefusesToTruncateAfterConcurrentWrite(t *testing.T) {
	partitiontest.PartitionTest(t)
	ctx := context.Background()
	f := newWALEraseFixture(t)
	f.insert(40)
	f.exec("DELETE FROM t WHERE id=1")

	other, err := MakeErasableAccessor(f.path)
	require.NoError(t, err)
	defer other.Close()
	marker := make([]byte, 300)
	_, err = rand.Read(marker)
	require.NoError(t, err)
	f.acc.eraseWALAfterOverwrite = func() {
		require.NoError(t, other.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.Exec("INSERT INTO t (v) VALUES (?)", marker)
			return err
		}))
		require.True(t, bytes.Contains(f.file("-wal"), marker))
	}
	err = f.acc.EraseWAL(ctx, false)
	require.ErrorContains(t, err, "another writer")
	require.True(t, bytes.Contains(f.file("-wal"), marker), "the concurrent transaction's frames were released")

	// without interference the next erase covers the leftover frames; the
	// row itself is data, still in the database
	f.acc.eraseWALAfterOverwrite = nil
	require.NoError(t, f.acc.EraseWAL(ctx, false))
	require.Zero(t, f.walSize())
	require.True(t, bytes.Contains(f.file(""), marker))
}

// TestEraseWALSpilledFrames checks a single transaction whose pages were
// spilled from the cache and written again at commit is not taken for a log
// of current images: the spilled image of a page still holds a row the
// transaction deleted afterwards.
func TestEraseWALSpilledFrames(t *testing.T) {
	partitiontest.PartitionTest(t)
	ctx := context.Background()
	f := newWALEraseFixture(t)
	first := f.insert(200) // ~15 leaf pages
	require.NoError(t, f.acc.EraseWAL(ctx, true))

	// a cache of two pages on the one connection the fixture uses, so the
	// transaction below spills as it goes
	f.acc.Handle.SetMaxOpenConns(1)
	_, err := f.acc.Handle.Exec("PRAGMA cache_size=2")
	require.NoError(t, err)
	require.NoError(t, f.acc.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// dirty the first leaf, then every other leaf (spilling the first),
		// then the first leaf again: its first image still holds row 2
		if _, err := tx.Exec("DELETE FROM t WHERE id=1"); err != nil {
			return err
		}
		if _, err := tx.Exec("UPDATE t SET v=v WHERE id>20"); err != nil {
			return err
		}
		_, err := tx.Exec("DELETE FROM t WHERE id=2")
		return err
	}))
	_, logFrames, _, err := f.acc.walCheckpoint(ctx, "PASSIVE")
	require.NoError(t, err)
	info, err := readWALFileInfo(f.path+"-wal", logFrames, walMaxParsedFrames)
	require.NoError(t, err)
	require.Equal(t, logFrames, info.frames)
	require.True(t, info.repeated)
	require.False(t, info.allCurrent(), "spilled images went unnoticed")
	require.True(t, bytes.Contains(f.file("-wal"), first[1]), "no spilled image of the deleted row; the test proves nothing")
	require.False(t, bytes.Contains(f.file(""), first[1]))

	require.NoError(t, f.acc.EraseWAL(ctx, false))
	require.Zero(t, f.walSize())
	require.False(t, bytes.Contains(f.file(""), first[1]))
}

// TestEraseWALDeferredUnderReader checks a reader that keeps the checkpoint
// from completing makes the erase wait for the next call rather than fail.
func TestEraseWALDeferredUnderReader(t *testing.T) {
	partitiontest.PartitionTest(t)
	ctx := context.Background()
	f := newWALEraseFixture(t)
	first := f.insert(40)
	f.exec("DELETE FROM t WHERE id=1")

	// a short busy timeout on the erasing connection so the test does not
	// wait out the default 5s
	f.acc.Handle.SetMaxOpenConns(1)
	_, err := f.acc.Handle.Exec("PRAGMA busy_timeout=50")
	require.NoError(t, err)

	reader, err := MakeAccessor(f.path, true, false)
	require.NoError(t, err)
	defer reader.Close()
	holding := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = reader.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			var n int
			if err := tx.QueryRow("SELECT count(*) FROM t").Scan(&n); err != nil {
				return err
			}
			close(holding)
			<-release
			return nil
		})
	}()
	<-holding

	sizeBefore := f.walSize()
	require.NoError(t, f.acc.EraseWAL(ctx, false))
	require.Equal(t, sizeBefore, f.walSize(), "the log changed while a reader held it")
	require.True(t, bytes.Contains(f.file("-wal"), first[0]))

	close(release)
	require.Eventually(t, func() bool { return f.acc.EraseWAL(ctx, false) == nil && f.walSize() == 0 }, 5e9, 1e7)
	require.False(t, bytes.Contains(f.file(""), first[0]))
}
