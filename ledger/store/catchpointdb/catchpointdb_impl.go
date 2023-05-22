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
	"database/sql"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
)

var LatestSchemaVersion int32 = 1

type catchpointStore struct {
	pair db.Pair
	Reader
	Writer
}

func Open(dbFilename string, dbMem bool, log logging.Logger) (Store, error) {
	pair, err := db.OpenPair(dbFilename, dbMem)
	if err != nil {
		return nil, err
	}
	pair.Rdb.SetLogger(log)
	pair.Wdb.SetLogger(log)
	return MakeStore(pair), nil
}

func MakeStore(pair db.Pair) Store {
	return &catchpointStore{pair, makeReader(pair.Rdb.Handle), makeWriter(pair.Wdb.Handle)}
}

// RunMigrations implements Store
func (*catchpointStore) RunMigrations(ctx context.Context, targetVersion int32) (err error) {
	panic("unimplemented")
}

// Batch implements Store
func (store *catchpointStore) Batch(fn BatchFn) (err error) {
	return store.BatchContext(context.Background(), fn)
}

// BatchContext implements Store
func (store *catchpointStore) BatchContext(ctx context.Context, fn BatchFn) (err error) {
	return store.pair.Wdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return fn(ctx, &batchScope{makeWriter(tx)})
	})
}

// DeleteStoredCatchpoints iterates over the storedcatchpoints table and deletes all the files stored on disk.
// once all the files have been deleted, it would go ahead and remove the entries from the table.
func (store *catchpointStore) DeleteStoredCatchpoints(ctx context.Context, dbDirectory string) (err error) {
	catchpointsFilesChunkSize := 50
	for {
		fileNames, err := store.GetOldestCatchpointFiles(ctx, catchpointsFilesChunkSize, 0)
		if err != nil {
			return err
		}
		if len(fileNames) == 0 {
			break
		}

		for round, fileName := range fileNames {
			err = RemoveSingleCatchpointFileFromDisk(dbDirectory, fileName)
			if err != nil {
				return err
			}
			// clear the entry from the database
			err = store.StoreCatchpoint(ctx, round, "", "", 0)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Close implements Store
func (store *catchpointStore) Close() {
	store.pair.Close()
}

type batchScope struct {
	Writer
}
