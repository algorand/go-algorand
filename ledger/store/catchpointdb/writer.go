// Copyright (C) 2019-2023 Algorand, Inc.
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

package catchpointdb

import (
	"context"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

type writer struct {
	e db.Executable
}

func makeWriter(e db.Executable) Writer {
	return &writer{e}
}

// StoreCatchpoint implements Writer
func (w *writer) StoreCatchpoint(ctx context.Context, round basics.Round, fileName string, catchpoint string, fileSize int64) (err error) {
	err = db.Retry(func() (err error) {
		query := "DELETE FROM storedcatchpoints WHERE round=?"
		_, err = w.e.ExecContext(ctx, query, round)
		if err != nil || (fileName == "" && catchpoint == "" && fileSize == 0) {
			return err
		}

		query = "INSERT INTO storedcatchpoints(round, filename, catchpoint, filesize, pinned) VALUES(?, ?, ?, ?, 0)"
		_, err = w.e.ExecContext(ctx, query, round, fileName, catchpoint, fileSize)
		return err
	})
	return
}

// WriteCatchpointStateString implements Writer
func (w *writer) WriteCatchpointStateString(ctx context.Context, stateName CatchpointState, setValue string) (err error) {
	err = db.Retry(func() (err error) {
		if setValue == "" {
			return deleteCatchpointStateImpl(ctx, w.e, stateName)
		}

		// we don't know if there is an entry in the table for this state, so we'll insert/replace it just in case.
		query := "INSERT OR REPLACE INTO catchpointstate(id, strval) VALUES(?, ?)"
		_, err = w.e.ExecContext(ctx, query, stateName, setValue)
		return err
	})
	return err
}

// WriteCatchpointStateUint64 implements Writer
func (w *writer) WriteCatchpointStateUint64(ctx context.Context, stateName CatchpointState, setValue uint64) (err error) {
	err = db.Retry(func() (err error) {
		if setValue == 0 {
			return deleteCatchpointStateImpl(ctx, w.e, stateName)
		}

		// we don't know if there is an entry in the table for this state, so we'll insert/replace it just in case.
		query := "INSERT OR REPLACE INTO catchpointstate(id, intval) VALUES(?, ?)"
		_, err = w.e.ExecContext(ctx, query, stateName, setValue)
		return err
	})
	return err
}

// DeleteUnfinishedCatchpoint implements Writer
func (w *writer) DeleteUnfinishedCatchpoint(ctx context.Context, round basics.Round) error {
	f := func() error {
		query := "DELETE FROM unfinishedcatchpoints WHERE round = ?"
		_, err := w.e.ExecContext(ctx, query, round)
		return err
	}
	return db.Retry(f)
}

// InsertUnfinishedCatchpoint implements Writer
func (w *writer) InsertUnfinishedCatchpoint(ctx context.Context, round basics.Round, blockHash crypto.Digest) error {
	f := func() error {
		query := "INSERT INTO unfinishedcatchpoints(round, blockhash) VALUES(?, ?)"
		_, err := w.e.ExecContext(ctx, query, round, blockHash[:])
		return err
	}
	return db.Retry(f)
}

// DeleteOldCatchpointFirstStageInfo implements Writer
func (w *writer) DeleteOldCatchpointFirstStageInfo(ctx context.Context, maxRoundToDelete basics.Round) error {
	f := func() error {
		query := "DELETE FROM catchpointfirststageinfo WHERE round <= ?"
		_, err := w.e.ExecContext(ctx, query, maxRoundToDelete)
		return err
	}
	return db.Retry(f)
}

// InsertOrReplaceCatchpointFirstStageInfo implements Writer
func (w *writer) InsertOrReplaceCatchpointFirstStageInfo(ctx context.Context, round basics.Round, info *CatchpointFirstStageInfo) error {
	infoSerialized := protocol.Encode(info)
	f := func() error {
		query := "INSERT OR REPLACE INTO catchpointfirststageinfo(round, info) VALUES(?, ?)"
		_, err := w.e.ExecContext(ctx, query, round, infoSerialized)
		return err
	}
	return db.Retry(f)
}

func deleteCatchpointStateImpl(ctx context.Context, e db.Executable, stateName CatchpointState) error {
	query := "DELETE FROM catchpointstate WHERE id=?"
	_, err := e.ExecContext(ctx, query, stateName)
	return err
}
