// Copyright (C) 2019-2025 Algorand, Inc.
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

package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

type dbOp interface {
	apply(d *participationDB) error
}

type opRequest struct {
	operation  dbOp
	errChannel chan error
}

type flushOp struct{} // does nothing but flushes the latest error.

type registerOp struct {
	updated map[ParticipationID]updatingParticipationRecord
}

type deleteOp struct {
	id ParticipationID
}

type insertOp struct {
	id     ParticipationID
	record Participation
}

type appendKeysOp struct {
	id   ParticipationID
	keys StateProofKeys
}
type deleteStateProofKeysOp struct {
	ParticipationID ParticipationID
	round           basics.Round
}

func (d deleteStateProofKeysOp) apply(db *participationDB) error {
	err := db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {

		// Fetch primary key
		var pk int
		row := tx.QueryRow(selectPK, d.ParticipationID[:])
		err := row.Scan(&pk)
		if err != nil {
			return fmt.Errorf("unable to scan pk: %w", err)
		}

		stmt, err := tx.Prepare(deleteStateProofKeysQuery)
		if err != nil {
			return fmt.Errorf("unable to prepare state proof delete: %w", err)
		}
		defer stmt.Close()

		_, err = stmt.Exec(pk, d.round)
		if err != nil {
			return fmt.Errorf("unable to exec state proof delete (pk,rnd) == (%d,%d): %w", pk, d.round, err)
		}
		return nil
	})

	if err != nil {
		db.log.Warnf("participationDB unable to delete stateProof key: %v", err)
	}
	return err
}

func makeOpRequest(operation dbOp) opRequest {
	return opRequest{operation: operation}
}

func makeOpRequestWithError(operation dbOp, errChan chan error) opRequest {
	return opRequest{operation: operation, errChannel: errChan}
}

func (r *registerOp) apply(db *participationDB) error {
	var cacheDeletes []ParticipationID
	err := db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// Disable active key if there is one
		for id, record := range r.updated {
			err := updateRollingFields(ctx, tx, record.ParticipationRecord)
			// Repair the case when no keys were updated
			if err == ErrNoKeyForID {
				db.log.Warn("participationDB unable to update key in cache. Removing from cache.")
				cacheDeletes = append(cacheDeletes, id)
				if !record.required {
					err = nil
				}
			}
			if err != nil {
				return fmt.Errorf("unable to disable old key when registering %s: %w", id, err)
			}
		}
		return nil
	})

	// Update cache
	if err == nil && len(cacheDeletes) != 0 {
		db.mutex.Lock()
		defer db.mutex.Unlock()
		for _, id := range cacheDeletes {
			delete(db.cache, id)
			delete(db.dirty, id)
		}
	}
	return err
}

func (i *insertOp) apply(db *participationDB) (err error) {
	var rawVRF []byte
	var rawVoting []byte
	var rawStateProofContext []byte

	if i.record.VRF != nil {
		rawVRF = protocol.Encode(i.record.VRF)
	}
	if i.record.Voting != nil {
		voting := i.record.Voting.Snapshot()
		rawVoting = protocol.Encode(&voting)
	}

	// This contains all the state proof data except for the actual secret keys (stored in a different table)
	if i.record.StateProofSecrets != nil {
		rawStateProofContext = protocol.Encode(&i.record.StateProofSecrets.SignerContext)
	}

	err = db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		result, err2 := tx.Exec(
			insertKeysetQuery,
			i.id[:],
			i.record.Parent[:],
			i.record.FirstValid,
			i.record.LastValid,
			i.record.KeyDilution,
			rawVRF,
			rawStateProofContext)
		if err2 = verifyExecWithOneRowEffected(err2, result, "insert keyset"); err2 != nil {
			return err2
		}
		pk, err2 := result.LastInsertId()
		if err2 != nil {
			return fmt.Errorf("unable to get pk from keyset: %w", err2)
		}

		// Create Rolling entry
		result, err2 = tx.Exec(insertRollingQuery, pk, rawVoting)
		return verifyExecWithOneRowEffected(err2, result, "insert rolling")
	})
	return err
}

func (d *deleteOp) apply(db *participationDB) error {
	err := db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// Fetch primary key
		var pk int
		row := tx.QueryRow(selectPK, d.id[:])
		err := row.Scan(&pk)
		if err == sql.ErrNoRows {
			// nothing to do.
			return nil
		}
		if err != nil {
			return fmt.Errorf("unable to scan pk: %w", err)
		}

		// Delete rows
		result, err := tx.Exec(deleteKeysets, pk)
		if err = verifyExecWithOneRowEffected(err, result, "delete keyset"); err != nil {
			return err
		}

		result, err = tx.Exec(deleteRolling, pk)
		if err = verifyExecWithOneRowEffected(err, result, "delete rolling"); err != nil {
			return err
		}

		_, err = tx.Exec(deleteStateProofByPK, pk)
		if err != nil {
			return err
		}

		return nil
	})
	return err
}

// flush does nothing, but is called specifically to flush errors from the db
func (f *flushOp) apply(db *participationDB) error {
	var dirty map[ParticipationID]struct{}
	db.mutex.Lock()
	if len(db.dirty) != 0 {
		dirty = db.dirty
		db.dirty = make(map[ParticipationID]struct{})
	} else {
		dirty = nil
	}

	var needsUpdate []ParticipationRecord
	// Verify that the dirty flag has not desynchronized from the cache.
	for id := range dirty {
		if rec, ok := db.cache[id]; !ok {
			db.log.Warnf("participationDB fixing dirty flag de-synchronization for %s", id)
			delete(db.cache, id)
		} else {
			needsUpdate = append(needsUpdate, rec)
		}
	}
	db.mutex.Unlock()

	if dirty == nil {
		return nil
	}

	err := db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var errorStr strings.Builder
		for _, record := range needsUpdate {
			err := updateRollingFields(ctx, tx, record)
			// This should only be updating key usage so ignoring missing keys is not a problem.
			if err != nil && err != ErrNoKeyForID {
				if errorStr.Len() > 0 {
					errorStr.WriteString(", ")
				}
				errorStr.WriteString(err.Error())
			}
		}
		if errorStr.Len() > 0 {
			return errors.New(errorStr.String())
		}
		return nil
	})

	if err != nil {
		// put back what we didn't finish with
		db.mutex.Lock()
		maps.Copy(db.dirty, dirty)
		db.mutex.Unlock()
	}

	return err
}

func (a *appendKeysOp) apply(db *participationDB) error {
	err := db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// Fetch primary key
		var pk int
		row := tx.QueryRow(selectPK, a.id[:])
		err := row.Scan(&pk)
		if err == sql.ErrNoRows {
			// nothing to do.
			return nil
		}
		if err != nil {
			return fmt.Errorf("unable to scan pk: %w", err)
		}

		stmt, err := tx.Prepare(appendStateProofKeysQuery)
		if err != nil {
			return fmt.Errorf("unable to prepare state proof insert: %w", err)
		}

		for _, key := range a.keys {
			result, err := stmt.Exec(pk, key.Round, protocol.Encode(key.Key))
			if err = verifyExecWithOneRowEffected(err, result, "append keys"); err != nil {
				return err
			}
		}

		return nil
	})
	return err
}
