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

package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
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
			err := updateRegistrationFields(ctx, tx, record.ParticipationRecord)
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

// fastForwardToStoredCursor advances secrets to the most advanced deletion
// cursor already persisted for id, so an insert can never rewind the cursor
// and resurrect retired keys on disk.  Fast-forwarding is exact because the
// participation ID commits to the key material: a stored cursor ahead of the
// inserted copy means those rounds were already voted and retired.
//
// It fails closed when a stored header for the id cannot be used (it is
// undecodable, or carries a different verifier than the key the ID commits
// to): the registry may be ahead of the supplied copy (a key file restored
// from a backup, or one that missed the last round's deletion), and a copy
// whose relation to the stored cursor cannot be established must not replace
// it.  The record stays excluded from the cache until the operator rebuilds
// the registry.
func fastForwardToStoredCursor(tx *sql.Tx, log logging.Logger, id ParticipationID, secrets *crypto.OneTimeSignatureSecrets, dilution uint64) error {
	rows, err := tx.Query(selectRollingVotingByID, id[:])
	if err != nil {
		return fmt.Errorf("unable to read the stored voting header for %s: %w", id, err)
	}
	defer rows.Close()

	current := votingSnapshot(secrets).Header()
	var stored *crypto.OneTimeSignatureSecretsHeader
	for rows.Next() {
		var pk int64
		var rawHeader []byte
		if err := rows.Scan(&pk, &rawHeader); err != nil {
			return err
		}
		// an existing row without a usable header (empty or undecodable)
		// cannot establish the stored deletion state: fail closed
		hdr, err := decodeVotingHeader(rawHeader)
		if err != nil {
			return fmt.Errorf("stored voting header for key %s is undecodable; refusing to replace it from the inserted copy (delete %s and restart to rebuild the registry): %v",
				id, config.ParticipationRegistryFilename, err)
		}
		if hdr.Verifier != current.Verifier {
			return fmt.Errorf("stored voting header for key %s belongs to a different voting key; refusing to replace it from the inserted copy (delete %s and restart to rebuild the registry)",
				id, config.ParticipationRegistryFilename)
		}
		if stored == nil || storedHeaderAhead(hdr, *stored) {
			stored = &hdr
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	if stored == nil {
		return nil // known-new: nothing stored for this key
	}
	if !storedHeaderAhead(*stored, current) {
		return nil
	}
	if stored.Exhausted() {
		// every subkey was retired: moving past the inserted copy's last
		// batch consumes them all without expanding anything, so the key
		// dilution is not needed
		log.Warnf("participationDB: inserted copy of key %s (batch %d, offset %d) lags the stored deletion cursor, which is exhausted; retiring every subkey",
			id, current.FirstBatch, current.FirstOffset)
		secrets.DeleteBeforeFineGrained(crypto.OneTimeSignatureIdentifier{Batch: current.FirstBatch + current.BatchCount}, dilution)
		return nil
	}
	// a cursor can only be ahead after a batch expansion, so FirstBatch >= 1
	if stored.FirstBatch == 0 {
		return nil
	}
	if dilution == 0 {
		return fmt.Errorf("stored voting state for %s (batch %d, offset %d) is ahead of the inserted copy (batch %d, offset %d) and its key dilution is unknown; refusing to rewind the deletion cursor",
			id, stored.FirstBatch, stored.FirstOffset, current.FirstBatch, current.FirstOffset)
	}
	log.Warnf("participationDB: inserted copy of key %s lags the stored deletion cursor; fast-forwarding from (batch %d, offset %d) to (batch %d, offset %d)",
		id, current.FirstBatch, current.FirstOffset, stored.FirstBatch, stored.FirstOffset)
	secrets.DeleteBeforeFineGrained(crypto.OneTimeSignatureIdentifier{Batch: stored.FirstBatch - 1, Offset: stored.FirstOffset}, dilution)
	return nil
}

func (i *insertOp) apply(db *participationDB) (err error) {
	var rawVRF []byte
	var rawStateProofContext []byte

	if i.record.VRF != nil {
		rawVRF = protocol.Encode(i.record.VRF)
	}
	// This contains all the state proof data except for the actual secret keys (stored in a different table)
	if i.record.StateProofSecrets != nil {
		rawStateProofContext = protocol.Encode(&i.record.StateProofSecrets.SignerContext)
	}

	err = db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// Replacing pre-existing rows must never rewind the persisted
		// deletion cursor: the .partkey file and the registry are
		// independent stores, so an inserted copy can lag what the registry
		// already retired (e.g. a key file restored from a backup).  The
		// participation ID commits to the key material, so the stored and
		// inserted secrets are the same key — fast-forward the inserted copy
		// to the most advanced stored cursor before persisting it.
		if i.record.Voting != nil {
			if err2 := fastForwardToStoredCursor(tx, db.log, i.id, i.record.Voting, i.record.KeyDilution); err2 != nil {
				return err2
			}
		}

		// snapshot the voting secrets only after the potential fast-forward
		var rawVotingHeader []byte
		var voting crypto.OneTimeSignatureSecretsPersistent
		if i.record.Voting != nil {
			voting = votingSnapshot(i.record.Voting)
			votingHeader := voting.Header()
			rawVotingHeader = protocol.Encode(&votingHeader)
		}

		// Clear any pre-existing rows for this participation ID.  A corrupt
		// record excluded from the cache at load leaves its rows behind, and
		// the caller (e.g. loadParticipationKeys in the same startup) then
		// legitimately re-inserts the key: dedup happens against the cache
		// only, and a duplicate Keysets row would make every subsequent
		// flush fail with ErrMultipleKeysForID.
		var cleared int64
		for _, query := range []string{clearRollingByID, clearStateProofByID, clearVotingBatchesByID, clearVotingOffsetsByID, clearKeysetsByID} {
			result, err2 := tx.Exec(query, i.id[:])
			if err2 != nil {
				return fmt.Errorf("unable to clear pre-existing rows for %s: %w", i.id, err2)
			}
			if n, err2 := result.RowsAffected(); err2 == nil {
				cleared += n
			}
		}
		if cleared > 0 {
			db.log.Warnf("participationDB: insert of key %s replaced %d pre-existing rows", i.id, cleared)
		}

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
		result, err2 = tx.Exec(insertRollingQuery, pk, rawVotingHeader)
		if err2 = verifyExecWithOneRowEffected(err2, result, "insert rolling"); err2 != nil {
			return err2
		}

		if i.record.Voting != nil {
			// per-subkey voting rows (a mid-life key carries offsets too)
			if err2 = insertVotingRows(tx, registryVotingTarget(pk), voting); err2 != nil {
				return fmt.Errorf("unable to insert voting subkeys: %w", err2)
			}
		}
		return nil
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

		_, err = tx.Exec(deleteVotingBatchesPK, pk)
		if err != nil {
			return err
		}

		_, err = tx.Exec(deleteVotingOffsetsPK, pk)
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

	// Each record is written under its own savepoint so one record that
	// cannot be persisted (e.g. an undecodable stored header, which fails
	// closed) does not roll back the others and stall on-disk key deletion
	// for every key; only the failed records are retried at the next flush.
	var failed []ParticipationID
	var errorStr strings.Builder
	err := db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		failed = failed[:0]
		errorStr.Reset()
		for _, record := range needsUpdate {
			if _, serr := tx.ExecContext(ctx, "SAVEPOINT flush_record"); serr != nil {
				return serr
			}
			err := updateRollingFields(ctx, tx, record)
			// This should only be updating key usage so ignoring missing keys is not a problem.
			if err != nil && err != ErrNoKeyForID {
				if _, rerr := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT flush_record"); rerr != nil {
					return rerr
				}
				failed = append(failed, record.ParticipationID)
				if errorStr.Len() > 0 {
					errorStr.WriteString(", ")
				}
				errorStr.WriteString(err.Error())
			}
			if _, serr := tx.ExecContext(ctx, "RELEASE SAVEPOINT flush_record"); serr != nil {
				return serr
			}
		}
		return nil
	})

	if err != nil {
		// the whole transaction failed: put back everything
		db.mutex.Lock()
		maps.Copy(db.dirty, dirty)
		db.mutex.Unlock()
		return err
	}
	if len(failed) != 0 {
		// the others committed; retry only the failed records
		db.mutex.Lock()
		for _, id := range failed {
			db.dirty[id] = struct{}{}
		}
		db.mutex.Unlock()
		return errors.New(errorStr.String())
	}
	return nil
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
