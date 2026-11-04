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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// Write-ahead log file layout (https://www.sqlite.org/walformat.html): a
// 32-byte header, then one frame per written page, each a 24-byte frame
// header followed by the page image.  Frames of the current generation of
// the log carry the salts of the file header; a nonzero "database size"
// field marks the last frame of a transaction.
const (
	walHeaderSize      = 32
	walFrameHeaderSize = 24

	// walMaxParsedFrames bounds how much of the log EraseWAL reads to decide
	// whether it is stale; a longer log is erased without looking.
	walMaxParsedFrames = 64

	// walEraseTable is the scratch table EraseWAL writes zero pages through.
	walEraseTable = "walErase"

	// walEraseChunkBytes is the size of the blob of zeros each transaction
	// of overwriteWAL writes; the database grows by at most this much.
	walEraseChunkBytes = 1 << 20
)

// EraseWAL overwrites the page images in the database's write-ahead log with
// zeros and truncates the log, unless the log holds nothing but the last
// transaction.
//
// SQLite appends the new image of every page a transaction modifies to the
// log and, once a checkpoint has copied the images into the database file
// and no reader needs them, restarts the log from the beginning at the next
// transaction.  A frame is only ever overwritten by a later frame landing on
// the same offset, so the image of a page as it was before a row was deleted
// (the row is zeroed by secure_delete in the new image) stays readable in the
// file until the log is refilled that far or truncated, and truncation only
// unlinks the blocks.  For a store whose deletions are the point, such as
// retired signing keys, that keeps deleted content around long after the
// delete.
//
// EraseWAL is meant to run after every write transaction.  It checkpoints in
// RESTART mode, which copies every frame into the database and makes the
// next writer restart the log, then inspects the log: if its frames are
// exactly the final page images of one transaction and nothing lies beyond
// them, nothing is stale and there is nothing to do; otherwise, or with all
// set, it writes zero-filled pages at least as far as the file extends, which
// overwrites every frame in place, and checkpoints in TRUNCATE mode to drop
// the file to zero bytes.  all is for bulk writes whose rows are going to be
// deleted one at a time (a key installed with all its subkeys): their images
// would otherwise be the first stale content of every later transaction.  A
// call that finds readers holding the log (a checkpoint cannot complete)
// leaves it for the next call.  The zero pages become free pages of the
// database, at most walEraseChunkBytes of them, which later writes reuse.
//
// The caller must be the only writer to the database, in this and any other
// process, from its last write transaction until EraseWAL returns.  The
// sequence spans several transactions and checkpoints, and SQLite has no lock
// that covers all of them; a transaction another connection commits meanwhile
// is either not overwritten or, once the log is truncated, released unerased.
// Before truncating, EraseWAL checks that the log holds exactly the zero
// pages it wrote and refuses to truncate otherwise, which catches a
// concurrent writer everywhere but in the moment between that check and the
// truncating checkpoint taking the write lock.  Readers need no coordination:
// checkpoints wait for them, or give up and leave the log for the next call.
//
// Overwriting in place erases the previous content on file systems that
// write in place; copy-on-write file systems and flash translation layers
// may keep the old blocks, the same limit secure_delete has.
func (db *Accessor) EraseWAL(ctx context.Context, all bool) error {
	if db.inMemory || db.readOnly {
		return nil
	}
	walPath := db.filename + "-wal"
	busy, logFrames, checkpointed, err := db.walCheckpoint(ctx, "RESTART")
	if err != nil {
		return err
	}
	if logFrames < 0 {
		return nil // not in WAL mode
	}
	if busy != 0 || checkpointed != logFrames {
		db.logger().Warnf("EraseWAL: readers hold the write-ahead log of %s (%d of %d frames checkpointed); deferred to the next write", db.filename, checkpointed, logFrames)
		return nil
	}

	info, err := readWALFileInfo(walPath, logFrames, walMaxParsedFrames)
	if err != nil {
		return fmt.Errorf("EraseWAL: %w", err)
	}
	if info.frames == 0 {
		return nil
	}
	if !all && info.frames == logFrames && info.allCurrent() {
		return nil // only the last transaction's final images: nothing is stale
	}

	chunks, err := db.overwriteWAL(ctx, info)
	if err != nil {
		return fmt.Errorf("EraseWAL: writing zero pages: %w", err)
	}
	if db.eraseWALAfterOverwrite != nil {
		db.eraseWALAfterOverwrite() // tests: inspect the log before it is truncated
	}

	// Truncating releases whatever the file holds, so first make sure that
	// is exactly the zero pages just written: a PASSIVE checkpoint (the
	// TRUNCATE one reports an empty log once it has reset it) gives the
	// frames of the log, which must be at least as many as were to be
	// covered, all of the current generation, committed by exactly the cover
	// transactions, and end at the end of the file.
	_, logFrames, _, err = db.walCheckpoint(ctx, "PASSIVE")
	if err != nil {
		return err
	}
	after, err := readWALFileInfo(walPath, logFrames, logFrames)
	if err != nil {
		return fmt.Errorf("EraseWAL: %w", err)
	}
	switch {
	case logFrames < info.frames:
		return fmt.Errorf("EraseWAL: wrote %d frames of zeros, fewer than the %d frames of the log", logFrames, info.frames)
	case !after.current || after.commits != chunks || after.size != walHeaderSize+logFrames*(walFrameHeaderSize+info.pageSize):
		return fmt.Errorf("EraseWAL: another writer used the write-ahead log of %s while it was being erased (%d transactions in %d frames, %d bytes); not truncated", db.filename, after.commits, logFrames, after.size)
	}
	busy, _, _, err = db.walCheckpoint(ctx, "TRUNCATE")
	if err != nil {
		return err
	}
	if busy != 0 {
		db.logger().Warnf("EraseWAL: readers hold the write-ahead log of %s; it is overwritten but not truncated", db.filename)
	}
	return nil
}

// overwriteWAL writes at least info.frames frames of zero pages to the log,
// in transactions of walEraseChunkBytes each, and returns how many
// transactions it committed.  A transaction inserts and deletes a blob of
// zeros: the insert dirties one overflow page per page of the blob and the
// delete leaves them as zeroed free pages (secure_delete), each written once,
// so the commit is at least that many frames of zeros.  The transactions
// append to one another, since automatic checkpoints are off on the
// connection (the only reason for a dedicated one), starting from the first
// frame, since the caller's checkpoint made the log restart; each reuses the
// free pages of the previous one, so the database grows by at most one
// chunk.
func (db *Accessor) overwriteWAL(ctx context.Context, info walFileInfo) (chunks int64, err error) {
	conn, err := db.Handle.Conn(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	var autoCheckpoint int64
	if err = conn.QueryRowContext(ctx, "PRAGMA wal_autocheckpoint").Scan(&autoCheckpoint); err != nil {
		return 0, err
	}
	if _, err = conn.ExecContext(ctx, "PRAGMA wal_autocheckpoint=0"); err != nil {
		return 0, err
	}
	defer func() {
		_, _ = conn.ExecContext(ctx, fmt.Sprintf("PRAGMA wal_autocheckpoint=%d", autoCheckpoint))
	}()
	if _, err = conn.ExecContext(ctx, "PRAGMA secure_delete=ON"); err != nil {
		return 0, err
	}

	chunk := max(walEraseChunkBytes/info.pageSize, 1)
	for remaining := info.frames; remaining > 0; remaining -= chunk {
		n := min(remaining, chunk)
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return chunks, err
		}
		// the scratch table is created within the first transaction rather
		// than in one of its own, so the log's transactions are exactly the
		// chunks
		for _, query := range []string{
			"CREATE TABLE IF NOT EXISTS " + walEraseTable + " (zeros BLOB)",
			"INSERT INTO " + walEraseTable + " VALUES (zeroblob(" + fmt.Sprint(n*info.pageSize) + "))",
			"DELETE FROM " + walEraseTable,
		} {
			if _, err = tx.ExecContext(ctx, query); err != nil {
				_ = tx.Rollback()
				return chunks, err
			}
		}
		if err = tx.Commit(); err != nil {
			return chunks, err
		}
		chunks++
	}
	return chunks, nil
}

// SetEraseWALHook installs a function EraseWAL runs once it has overwritten
// the log and before it truncates it, so tests can inspect the overwritten
// log (afterwards, truncation leaves nothing to tell overwriting from).  nil
// removes it.  The hook runs on the goroutine that erases.
func (db *Accessor) SetEraseWALHook(hook func()) {
	db.eraseWALAfterOverwrite = hook
}

// walCheckpoint runs PRAGMA wal_checkpoint in the given mode and returns its
// result: whether it could not complete, the frames in the log (-1 when not
// in WAL mode), and how many of them are in the database file.
func (db *Accessor) walCheckpoint(ctx context.Context, mode string) (busy, logFrames, checkpointed int64, err error) {
	err = db.Handle.QueryRowContext(ctx, "PRAGMA wal_checkpoint("+mode+")").Scan(&busy, &logFrames, &checkpointed)
	return
}

type walFileInfo struct {
	size     int64 // bytes
	frames   int64 // frames the file extends to, a partial trailing one included
	pageSize int64

	// The first logFrames frames, inspected when there are at most maxParse
	// of them.
	parsed   bool
	current  bool  // all carry the salts of the file header, i.e. belong to the current generation of the log
	commits  int64 // commit markers among them, one per transaction
	repeated bool  // a page appears more than once
}

// allCurrent reports whether the inspected frames are exactly the final page
// images of one committed transaction: all of the current generation, one
// commit marker, and no page written twice (a page spilled from the cache
// mid-transaction and written again at commit leaves an earlier image, which
// may hold content the transaction went on to delete).  A log that was not
// inspected is not current.
func (info walFileInfo) allCurrent() bool {
	return info.parsed && info.current && info.commits == 1 && !info.repeated
}

// readWALFileInfo reads the write-ahead log's header and, if there are at
// most maxParse of them, the headers of its first logFrames frames.
func readWALFileInfo(path string, logFrames, maxParse int64) (info walFileInfo, err error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return info, nil
	}
	if err != nil {
		return info, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return info, err
	}
	info.size = stat.Size()
	if info.size <= walHeaderSize {
		return info, nil
	}

	var header [walHeaderSize]byte
	if _, err = io.ReadFull(f, header[:]); err != nil {
		return info, err
	}
	info.pageSize = int64(binary.BigEndian.Uint32(header[8:12]))
	if info.pageSize < 512 {
		return info, fmt.Errorf("write-ahead log %s has an invalid page size %d", path, info.pageSize)
	}
	frameSize := walFrameHeaderSize + info.pageSize
	info.frames = (info.size - walHeaderSize + frameSize - 1) / frameSize

	if logFrames > maxParse || logFrames > info.frames {
		return info, nil
	}
	info.parsed = true
	info.current = true
	salt := header[16:24]
	pages := make(map[uint32]struct{}, logFrames)
	for i := int64(0); i < logFrames; i++ {
		var frame [walFrameHeaderSize]byte
		if _, err = f.ReadAt(frame[:], walHeaderSize+i*frameSize); err != nil {
			return info, err
		}
		if string(frame[8:16]) != string(salt) {
			info.current = false
			return info, nil
		}
		page := binary.BigEndian.Uint32(frame[0:4])
		if _, dup := pages[page]; dup {
			info.repeated = true
		}
		pages[page] = struct{}{}
		if binary.BigEndian.Uint32(frame[4:8]) != 0 {
			info.commits++
		}
	}
	return info, nil
}
