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
	"database/sql"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// errInconsistentVotingRows signals that the stored subkey rows disagree with
// the stored scalars (a trim removed an unexpected number of rows).  The
// appliers recover from it by rebuilding the rows from memory.
var errInconsistentVotingRows = errors.New("stored voting rows are inconsistent with the stored scalars")

// votingDelta describes the row operations needed to bring row-oriented
// persisted voting secrets (whose last-persisted scalars are known) up to the
// current in-memory state.  Voting subkeys advance monotonically: batch rows
// are written once when a key is stored and only ever deleted afterwards;
// offset rows are replaced wholesale on a batch rollover and deleted from the
// front as rounds pass.
type votingDelta struct {
	// noop means the persisted state already matches; skip all writes.
	noop bool

	// fullRewrite means the persisted state cannot be diffed (missing,
	// undecodable, or a legacy whole-blob): delete every row and re-insert
	// insertBatches+insertOffsets.
	fullRewrite bool

	// clearAllRows means the in-memory secrets carry no subkeys at all while
	// the scalars are unchanged (the end-of-key-life transition): delete
	// every row, keep the stored scalars.  Idempotent, and once the tables
	// are empty it writes nothing.
	clearAllRows bool

	// deleteBatchesBelow deletes batch rows with index < this value
	// (rollover path; 0 means no batch deletion).
	deleteBatchesBelow uint64

	// expectedBatchDeletes is the exact number of rows deleteBatchesBelow
	// must remove; a mismatch means the stored rows are inconsistent with
	// the stored scalars.  -1 skips the check.
	expectedBatchDeletes int64

	// deleteOffsetsBelow deletes offset rows with index < this value
	// (same-batch path; 0 means no offset range-deletion).
	deleteOffsetsBelow uint64

	// expectedOffsetDeletes is the exact number of rows deleteOffsetsBelow
	// must remove.  -1 skips the check.
	expectedOffsetDeletes int64

	// replaceAllOffsets clears the offsets table before inserting
	// insertOffsets.  Offsets restart at 0 in every batch, so a rollover must
	// clear rather than range-delete.
	replaceAllOffsets bool

	insertBatches []crypto.KeyedSubkey
	insertOffsets []crypto.KeyedSubkey

	// offsetsBatch is the batch the insertOffsets subkeys belong to
	// (FirstBatch-1 of the scalars they were captured with); meaningful only
	// when insertOffsets is non-empty.
	offsetsBatch uint64

	// newScalars is the encoded scalar state to store; nil when the stored
	// scalars need no update (noop and clearAllRows).
	newScalars []byte
}

// cursorAhead reports whether a's deletion cursor is strictly ahead of b's.
func cursorAhead(a, b *crypto.OneTimeSignatureSecretsPersistent) bool {
	return a.FirstBatch > b.FirstBatch ||
		(a.FirstBatch == b.FirstBatch && a.FirstOffset > b.FirstOffset)
}

// computeVotingDelta compares the last-persisted scalars against the current
// in-memory secrets and returns the row operations to persist the difference.
// old == nil requests an unconditional full rewrite and is only legitimate for
// known-new state (nothing persisted yet) and explicit format migration; an
// undecodable persisted state must fail closed at the caller instead, since
// it cannot rule out that memory lags storage.
//
// Forward security requires the persisted deletion cursor to be monotonic:
// if storage is ahead of memory, rewriting from memory would resurrect keys
// that were already deleted on disk, so that state is an error rather than a
// self-heal.
func computeVotingDelta(old *crypto.OneTimeSignatureSecretsPersistent, secrets *crypto.OneTimeSignatureSecrets) (votingDelta, error) {
	fullRewrite := func() (votingDelta, error) {
		scalars, batches, offsets := secrets.PersistentParts()
		d := votingDelta{
			fullRewrite:           true,
			expectedBatchDeletes:  -1,
			expectedOffsetDeletes: -1,
			insertBatches:         batches,
			insertOffsets:         offsets,
			newScalars:            protocol.Encode(&scalars),
		}
		if len(offsets) > 0 {
			var err error
			d.offsetsBatch, err = offsetsOwningBatch(scalars.FirstBatch)
			if err != nil {
				return votingDelta{}, err
			}
		}
		return d, nil
	}

	if old == nil {
		return fullRewrite()
	}

	scalars, numBatches, numOffsets := secrets.PersistentState()

	if cursorAhead(old, &scalars) {
		return votingDelta{}, fmt.Errorf("computeVotingDelta: persisted voting state (batch %d, offset %d) is ahead of memory (batch %d, offset %d): stale or corrupt store; refusing to resurrect deleted keys",
			old.FirstBatch, old.FirstOffset, scalars.FirstBatch, scalars.FirstOffset)
	}

	// Legacy whole-blob persisted state: convert in place.  The cursor check
	// above guarantees memory holds no more keys than the blob did.
	if len(old.Batches) != 0 || len(old.Offsets) != 0 {
		return fullRewrite()
	}

	switch {
	case scalars.FirstBatch == old.FirstBatch && scalars.FirstOffset == old.FirstOffset:
		if numBatches == 0 && numOffsets == 0 {
			// Exhausted key whose stored cursor did not move when its rows
			// were erased (state written before exhaustion advanced
			// FirstOffset to the batch end): scalar equality does not imply
			// the stored rows are current, and a key with no subkeys in
			// memory must have no rows on disk (forward security).
			return votingDelta{clearAllRows: true, expectedBatchDeletes: -1, expectedOffsetDeletes: -1}, nil
		}
		return votingDelta{noop: true}, nil

	case scalars.FirstBatch == old.FirstBatch:
		// Common per-round path: offsets consumed from the front.  Storage
		// held rows from old.FirstOffset, so the trim size is exact.
		return votingDelta{
			deleteOffsetsBelow:    scalars.FirstOffset,
			expectedOffsetDeletes: int64(scalars.FirstOffset - old.FirstOffset),
			expectedBatchDeletes:  -1,
			newScalars:            protocol.Encode(&scalars),
		}, nil

	default:
		// Batch rollover: batch rows consumed, offset rows regenerated.
		// Re-capture scalars and offset rows in one consistent snapshot;
		// batch rows are already present in storage and never re-inserted.
		partScalars, offsets := secrets.PersistentScalarsAndOffsets()
		d := votingDelta{
			deleteBatchesBelow:    partScalars.FirstBatch,
			expectedBatchDeletes:  -1,
			expectedOffsetDeletes: -1,
			replaceAllOffsets:     true,
			insertOffsets:         offsets,
			newScalars:            protocol.Encode(&partScalars),
		}
		if len(offsets) > 0 {
			var err error
			d.offsetsBatch, err = offsetsOwningBatch(partScalars.FirstBatch)
			if err != nil {
				return votingDelta{}, err
			}
			// memory still holds the tail of the batch sequence, so storage
			// must have carried exactly the same tail and the trim size is
			// exact; when memory ran out of batches entirely the tail length
			// is unknown here, so the check is skipped
			d.expectedBatchDeletes = int64(partScalars.FirstBatch - old.FirstBatch)
		}
		return d, nil
	}
}

// votingDeltaTarget names the SQL statements for one of the two row-oriented
// voting key stores: the .partkey file tables, or the registry tables scoped
// by pk.  Statements taking a threshold or row values receive prefixArgs
// first; insertOffset additionally receives the owning batch number between
// the prefix and the row values.
type votingDeltaTarget struct {
	deleteAllBatches   string
	deleteBatchesBelow string // args: (prefixArgs..., threshold)
	deleteAllOffsets   string
	deleteOffsetsBelow string // args: (prefixArgs..., threshold)
	insertBatch        string // args: (prefixArgs..., index, data)
	insertOffset       string // args: (prefixArgs..., batch, index, data)
	updateScalars      string // args: (scalars, prefixArgs...)
	prefixArgs         []any
}

var partkeyFileVotingTarget = votingDeltaTarget{
	deleteAllBatches:   "DELETE FROM OtsBatches",
	deleteBatchesBelow: "DELETE FROM OtsBatches WHERE batch<?",
	deleteAllOffsets:   "DELETE FROM OtsOffsets",
	deleteOffsetsBelow: "DELETE FROM OtsOffsets WHERE off<?",
	insertBatch:        "INSERT INTO OtsBatches (batch, data) VALUES (?, ?)",
	insertOffset:       "INSERT INTO OtsOffsets (batch, off, data) VALUES (?, ?, ?)",
	updateScalars:      "UPDATE ParticipationAccount SET voting=?",
}

func registryVotingTarget(pk int64) votingDeltaTarget {
	return votingDeltaTarget{
		deleteAllBatches:   deleteVotingBatchesPK,
		deleteBatchesBelow: "DELETE FROM VotingBatches WHERE pk=? AND batch<?",
		deleteAllOffsets:   deleteVotingOffsetsPK,
		deleteOffsetsBelow: "DELETE FROM VotingOffsets WHERE pk=? AND off<?",
		insertBatch:        "INSERT INTO VotingBatches (pk, batch, data) VALUES (?, ?, ?)",
		insertOffset:       "INSERT INTO VotingOffsets (pk, batch, off, data) VALUES (?, ?, ?, ?)",
		updateScalars:      "UPDATE Rolling SET voting=? WHERE pk=?",
		prefixArgs:         []any{pk},
	}
}

// applyVotingDeltaToPartkeyFile applies a delta to a .partkey database,
// rebuilding the rows from secrets if they turn out inconsistent.
func applyVotingDeltaToPartkeyFile(tx *sql.Tx, d votingDelta, secrets *crypto.OneTimeSignatureSecrets) error {
	return applyVotingDeltaSelfHealing(tx, partkeyFileVotingTarget, d, secrets)
}

// applyVotingDeltaToRegistry applies a delta to the participation registry
// tables for one key, rebuilding the rows from secrets if they turn out
// inconsistent.
func applyVotingDeltaToRegistry(tx *sql.Tx, pk int64, d votingDelta, secrets *crypto.OneTimeSignatureSecrets) error {
	return applyVotingDeltaSelfHealing(tx, registryVotingTarget(pk), d, secrets)
}

// applyVotingDeltaSelfHealing applies a delta and, when the trim row counts
// reveal that the stored rows disagree with the stored scalars, falls back to
// rebuilding the rows from memory.  The fallback is safe: computeVotingDelta's
// monotonicity guard already established that storage is not ahead of memory,
// so a full rewrite can only remove or faithfully restore keys memory
// legitimately holds — never resurrect deleted ones.  Without it, one
// inconsistent key would fail every flush forever (blocking on-disk key
// deletion for all keys, since the registry flush is one transaction).
func applyVotingDeltaSelfHealing(tx *sql.Tx, target votingDeltaTarget, d votingDelta, secrets *crypto.OneTimeSignatureSecrets) error {
	err := applyVotingDelta(tx, target, d)
	if !errors.Is(err, errInconsistentVotingRows) || secrets == nil {
		return err
	}
	// reaching this path means a disk problem or a delta bug — repair it,
	// but never silently
	logging.Base().Warnf("participation voting rows were inconsistent and have been rebuilt from memory: %v", err)
	full, ferr := computeVotingDelta(nil, secrets)
	if ferr != nil {
		return ferr
	}
	return applyVotingDelta(tx, target, full)
}

// offsetsOwningBatch returns the batch that offset subkeys belong to.  Offset
// subkeys only exist after a batch expansion, which leaves FirstBatch >= 1;
// FirstBatch == 0 alongside offsets means corrupt in-memory state, which must
// fail at write time rather than persist a row every later load would reject.
func offsetsOwningBatch(firstBatch uint64) (uint64, error) {
	if firstBatch == 0 {
		return 0, errors.New("offset subkeys present but FirstBatch is 0: corrupt voting state")
	}
	return firstBatch - 1, nil
}

func applyVotingDelta(tx *sql.Tx, target votingDeltaTarget, d votingDelta) error {
	if d.noop {
		return nil
	}

	if d.fullRewrite || d.clearAllRows {
		if _, err := tx.Exec(target.deleteAllBatches, target.prefixArgs...); err != nil {
			return fmt.Errorf("applyVotingDelta: failed to clear batches: %w", err)
		}
	} else if d.deleteBatchesBelow > 0 {
		result, err := tx.Exec(target.deleteBatchesBelow, append(append([]any{}, target.prefixArgs...), d.deleteBatchesBelow)...)
		if err != nil {
			return fmt.Errorf("applyVotingDelta: failed to trim batches: %w", err)
		}
		if err := verifyRowsAffected(result, d.expectedBatchDeletes, "batch subkey trim"); err != nil {
			return fmt.Errorf("applyVotingDelta: %w", err)
		}
	}

	if d.fullRewrite || d.clearAllRows || d.replaceAllOffsets {
		if _, err := tx.Exec(target.deleteAllOffsets, target.prefixArgs...); err != nil {
			return fmt.Errorf("applyVotingDelta: failed to clear offsets: %w", err)
		}
	} else if d.deleteOffsetsBelow > 0 {
		result, err := tx.Exec(target.deleteOffsetsBelow, append(append([]any{}, target.prefixArgs...), d.deleteOffsetsBelow)...)
		if err != nil {
			return fmt.Errorf("applyVotingDelta: failed to trim offsets: %w", err)
		}
		if err := verifyRowsAffected(result, d.expectedOffsetDeletes, "offset subkey trim"); err != nil {
			return fmt.Errorf("applyVotingDelta: %w", err)
		}
	}

	if err := insertKeyedSubkeys(tx, target.insertBatch, target.prefixArgs, d.insertBatches); err != nil {
		return fmt.Errorf("applyVotingDelta: failed to insert batches: %w", err)
	}
	if len(d.insertOffsets) > 0 {
		offsetPrefix := append(append([]any{}, target.prefixArgs...), d.offsetsBatch)
		if err := insertKeyedSubkeys(tx, target.insertOffset, offsetPrefix, d.insertOffsets); err != nil {
			return fmt.Errorf("applyVotingDelta: failed to insert offsets: %w", err)
		}
	}

	if d.newScalars != nil {
		result, err := tx.Exec(target.updateScalars, append([]any{d.newScalars}, target.prefixArgs...)...)
		if err != nil {
			return fmt.Errorf("applyVotingDelta: failed to update scalars: %w", err)
		}
		// deliberately not the self-heal sentinel: a missing scalar row is
		// not repairable by rewriting the subkey rows
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("applyVotingDelta: scalar update affected %d rows, expected 1", n)
		}
	}
	return nil
}

// verifyRowsAffected checks a statement changed exactly the expected number
// of rows; expected < 0 skips the check.
func verifyRowsAffected(result sql.Result, expected int64, what string) error {
	if expected < 0 {
		return nil
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != expected {
		return fmt.Errorf("%s affected %d rows, expected %d: %w", what, n, expected, errInconsistentVotingRows)
	}
	return nil
}

// validateVotingRowCounts verifies the number of stored subkey rows matches
// what the scalars imply.  Batch rows are only ever trimmed from the front,
// so a key valid through lastValid must hold exactly the batches from
// FirstBatch through the last batch of its validity window.  Offset rows for
// the current batch (FirstBatch-1) must cover FirstOffset through
// dilution-1, except while the key is past its final batch where zero rows
// (erased at end of key life) are also legitimate.  dilution 0 (ancient keys
// deferring to consensus parameters) skips the checks.
func validateVotingRowCounts(scalars *crypto.OneTimeSignatureSecretsPersistent, lastValid basics.Round, dilution uint64, numBatchRows, numOffsetRows int) error {
	if dilution == 0 {
		return nil
	}
	lastBatch := basics.OneTimeIDForRound(lastValid, dilution).Batch

	expectedBatches := 0
	if scalars.FirstBatch <= lastBatch {
		expectedBatches = int(lastBatch - scalars.FirstBatch + 1)
	}
	if numBatchRows != expectedBatches {
		return fmt.Errorf("voting key has %d batch subkey rows, expected %d (first batch %d, last batch %d): missing or extra rows", numBatchRows, expectedBatches, scalars.FirstBatch, lastBatch)
	}

	expectedOffsets := 0
	if dilution > scalars.FirstOffset {
		expectedOffsets = int(dilution - scalars.FirstOffset)
	}
	switch {
	case !scalars.OffsetsExpanded():
		expectedOffsets = 0
	case scalars.FirstBatch == lastBatch+1:
		// final-batch phase: the rows are either still live or already
		// erased at the end of the key's life — both are legitimate
		if numOffsetRows == 0 {
			return nil
		}
	case scalars.FirstBatch > lastBatch+1:
		expectedOffsets = 0
	}
	if numOffsetRows != expectedOffsets {
		return fmt.Errorf("voting key has %d offset subkey rows, expected %d (first offset %d, dilution %d): missing or extra rows", numOffsetRows, expectedOffsets, scalars.FirstOffset, dilution)
	}
	return nil
}

// validateOffsetRowBatches verifies every stored offset row belongs to the
// batch the scalars say is expanded (FirstBatch-1), so a scalar/row mismatch
// cannot silently associate offsets with the wrong batch.
func validateOffsetRowBatches(scalars *crypto.OneTimeSignatureSecretsPersistent, offsetBatches []uint64) error {
	if len(offsetBatches) == 0 {
		return nil
	}
	if !scalars.OffsetsExpanded() || scalars.FirstBatch == 0 {
		return fmt.Errorf("offset subkey rows present but the key has no expanded batch")
	}
	want := scalars.FirstBatch - 1
	for _, b := range offsetBatches {
		if b != want {
			return fmt.Errorf("offset subkey row belongs to batch %d, expected batch %d", b, want)
		}
	}
	return nil
}

// insertKeyedSubkeys bulk-inserts rows with a single prepared statement.
// insertSQL must take (prefixArgs..., index, data).
func insertKeyedSubkeys(tx *sql.Tx, insertSQL string, prefixArgs []any, rows []crypto.KeyedSubkey) error {
	if len(rows) == 0 {
		return nil
	}
	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	args := make([]any, len(prefixArgs)+2)
	copy(args, prefixArgs)
	for _, row := range rows {
		args[len(prefixArgs)] = row.Index
		args[len(prefixArgs)+1] = row.Key
		if _, err := stmt.Exec(args...); err != nil {
			return err
		}
	}
	return nil
}

// readVotingRowsFromPartkeyFile loads the subkey rows from a v4 .partkey
// database, ordered by index, along with each offset row's owning batch.
func readVotingRowsFromPartkeyFile(tx *sql.Tx) (batches, offsets []crypto.KeyedSubkey, offsetBatches []uint64, err error) {
	batches, err = readKeyedSubkeys(tx, "SELECT batch, data FROM OtsBatches ORDER BY batch")
	if err != nil {
		return nil, nil, nil, err
	}
	offsets, offsetBatches, err = readOffsetSubkeys(tx, "SELECT batch, off, data FROM OtsOffsets ORDER BY off")
	if err != nil {
		return nil, nil, nil, err
	}
	return batches, offsets, offsetBatches, nil
}

func readKeyedSubkeys(tx *sql.Tx, query string, args ...any) ([]crypto.KeyedSubkey, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []crypto.KeyedSubkey
	for rows.Next() {
		var row crypto.KeyedSubkey
		if err := rows.Scan(&row.Index, &row.Key); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// groupedSubkeys carries the subkey rows of one pk; batches holds each row's
// owning batch for offset subkeys (nil for batch subkeys).
type groupedSubkeys struct {
	subkeys []crypto.KeyedSubkey
	batches []uint64
}

// readGroupedSubkeys loads subkey rows for every key at once, grouped by pk.
// The query must yield (pk, index, data) rows, or (pk, batch, index, data)
// when withBatch is set, ordered by (pk, index).
func readGroupedSubkeys(tx *sql.Tx, query string, withBatch bool) (map[int64]groupedSubkeys, error) {
	rows, err := tx.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int64]groupedSubkeys)
	for rows.Next() {
		var pk int64
		var batch uint64
		var row crypto.KeyedSubkey
		if withBatch {
			err = rows.Scan(&pk, &batch, &row.Index, &row.Key)
		} else {
			err = rows.Scan(&pk, &row.Index, &row.Key)
		}
		if err != nil {
			return nil, err
		}
		group := result[pk]
		group.subkeys = append(group.subkeys, row)
		if withBatch {
			group.batches = append(group.batches, batch)
		}
		result[pk] = group
	}
	return result, rows.Err()
}

func readOffsetSubkeys(tx *sql.Tx, query string, args ...any) ([]crypto.KeyedSubkey, []uint64, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var result []crypto.KeyedSubkey
	var batches []uint64
	for rows.Next() {
		var batch uint64
		var row crypto.KeyedSubkey
		if err := rows.Scan(&batch, &row.Index, &row.Key); err != nil {
			return nil, nil, err
		}
		result = append(result, row)
		batches = append(batches, batch)
	}
	return result, batches, rows.Err()
}
