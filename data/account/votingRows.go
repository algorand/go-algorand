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
	"bytes"
	"database/sql"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// Row-oriented storage of voting secrets, shared by the .partkey file and the
// participation registry.  Each store holds a crypto.OneTimeSignatureSecretsHeader
// in a votingHeader column and one row per ephemeral subkey in two tables, so
// the header alone says exactly which rows must exist.  Three operations are
// provided: insertVotingRows for a key that is stored for the first time,
// rewriteVotingRows for format migration and repair, and syncVotingRows for
// the per-round transition from the stored header to the in-memory state.

// errInconsistentVotingRows reports that the stored subkey rows disagree with
// the stored header (a trim removed an unexpected number of rows, or the two
// headers' counts cannot be reconciled).  syncVotingRows repairs it by
// rewriting the rows from memory.
var errInconsistentVotingRows = errors.New("stored voting subkey rows are inconsistent with the stored header")

// votingRowTarget names the SQL statements of one row-oriented voting key
// store: the .partkey file tables, or the registry tables scoped by pk.
// prefixArgs (the registry pk) lead every statement's arguments, except
// updateHeader where the header value comes first.
type votingRowTarget struct {
	selectHeader       string // args: (prefixArgs...) -> header blob
	selectBatches      string // args: (prefixArgs...) -> (batch, data) ordered by batch
	selectOffsets      string // args: (prefixArgs...) -> (batch, off, data) ordered by off
	deleteAllBatches   string // args: (prefixArgs...)
	deleteBatchesBelow string // args: (prefixArgs..., threshold)
	deleteAllOffsets   string // args: (prefixArgs...)
	deleteOffsetsBelow string // args: (prefixArgs..., threshold)
	insertBatch        string // args: (prefixArgs..., index, data)
	insertOffset       string // args: (prefixArgs..., batch, index, data)
	updateHeader       string // args: (header, prefixArgs...)
	prefixArgs         []any
}

var partkeyFileVotingTarget = votingRowTarget{
	selectHeader:       "SELECT votingHeader FROM ParticipationAccount",
	selectBatches:      "SELECT batch, data FROM VotingBatches ORDER BY batch",
	selectOffsets:      "SELECT batch, off, data FROM VotingOffsets ORDER BY off",
	deleteAllBatches:   "DELETE FROM VotingBatches",
	deleteBatchesBelow: "DELETE FROM VotingBatches WHERE batch<?",
	deleteAllOffsets:   "DELETE FROM VotingOffsets",
	deleteOffsetsBelow: "DELETE FROM VotingOffsets WHERE off<?",
	insertBatch:        "INSERT INTO VotingBatches (batch, data) VALUES (?, ?)",
	insertOffset:       "INSERT INTO VotingOffsets (batch, off, data) VALUES (?, ?, ?)",
	updateHeader:       "UPDATE ParticipationAccount SET votingHeader=?",
}

func registryVotingTarget(pk int64) votingRowTarget {
	return votingRowTarget{
		selectHeader:       "SELECT votingHeader FROM Rolling WHERE pk=?",
		selectBatches:      selectVotingBatches,
		selectOffsets:      selectVotingOffsets,
		deleteAllBatches:   deleteVotingBatchesPK,
		deleteBatchesBelow: "DELETE FROM VotingBatches WHERE pk=? AND batch<?",
		deleteAllOffsets:   deleteVotingOffsetsPK,
		deleteOffsetsBelow: "DELETE FROM VotingOffsets WHERE pk=? AND off<?",
		insertBatch:        "INSERT INTO VotingBatches (pk, batch, data) VALUES (?, ?, ?)",
		insertOffset:       "INSERT INTO VotingOffsets (pk, batch, off, data) VALUES (?, ?, ?, ?)",
		updateHeader:       "UPDATE Rolling SET votingHeader=? WHERE pk=?",
		prefixArgs:         []any{pk},
	}
}

// args returns the target's prefix arguments followed by extra.
func (t votingRowTarget) args(extra ...any) []any {
	return append(append(make([]any, 0, len(t.prefixArgs)+len(extra)), t.prefixArgs...), extra...)
}

// votingSnapshot captures the state of live voting secrets for persistence.
func votingSnapshot(secrets *crypto.OneTimeSignatureSecrets) crypto.OneTimeSignatureSecretsPersistent {
	return secrets.Snapshot().OneTimeSignatureSecretsPersistent
}

// decodeVotingHeader decodes a stored voting header; an empty value is an
// error, since every row-oriented store writes a header along with the key.
func decodeVotingHeader(raw []byte) (crypto.OneTimeSignatureSecretsHeader, error) {
	var hdr crypto.OneTimeSignatureSecretsHeader
	if len(raw) == 0 {
		return hdr, errors.New("no voting header stored")
	}
	if err := protocol.Decode(raw, &hdr); err != nil {
		return hdr, err
	}
	return hdr, nil
}

// offsetsBatch returns the batch the offset subkeys of hdr belong to.  Offset
// subkeys only exist after a batch expansion, which leaves FirstBatch >= 1.
func offsetsBatch(hdr crypto.OneTimeSignatureSecretsHeader) (uint64, error) {
	if hdr.FirstBatch == 0 {
		return 0, errors.New("offset subkeys present but no batch has been expanded (FirstBatch is 0)")
	}
	return hdr.FirstBatch - 1, nil
}

// storedHeaderAhead reports whether the stored deletion cursor is strictly
// ahead of memory's.  Exhaustion is terminal: an exhausted store is ahead of
// any live in-memory state, whatever its cursor says.
func storedHeaderAhead(stored, mem crypto.OneTimeSignatureSecretsHeader) bool {
	if stored.Exhausted() {
		return !mem.Exhausted()
	}
	if mem.Exhausted() {
		return false
	}
	return stored.FirstBatch > mem.FirstBatch ||
		(stored.FirstBatch == mem.FirstBatch && stored.FirstOffset > mem.FirstOffset)
}

// insertVotingRows inserts one row per subkey of snap.  It is the row half of
// storing a key for the first time; the caller stores the header with the
// key's own row.
func insertVotingRows(tx *sql.Tx, target votingRowTarget, snap crypto.OneTimeSignatureSecretsPersistent) error {
	if err := insertKeyedSubkeys(tx, target.insertBatch, target.prefixArgs, snap.EncodedBatches()); err != nil {
		return fmt.Errorf("failed to insert voting batch subkeys: %w", err)
	}
	if len(snap.Offsets) == 0 {
		return nil
	}
	batch, err := offsetsBatch(snap.Header())
	if err != nil {
		return err
	}
	if err := insertKeyedSubkeys(tx, target.insertOffset, target.args(batch), snap.EncodedOffsets()); err != nil {
		return fmt.Errorf("failed to insert voting offset subkeys: %w", err)
	}
	return nil
}

// rewriteVotingRows replaces everything the store holds for the key (rows and
// header) with snap.  Used by format migration and by repair.
func rewriteVotingRows(tx *sql.Tx, target votingRowTarget, snap crypto.OneTimeSignatureSecretsPersistent) error {
	if _, err := tx.Exec(target.deleteAllBatches, target.prefixArgs...); err != nil {
		return fmt.Errorf("failed to clear voting batch subkeys: %w", err)
	}
	if _, err := tx.Exec(target.deleteAllOffsets, target.prefixArgs...); err != nil {
		return fmt.Errorf("failed to clear voting offset subkeys: %w", err)
	}
	if err := insertVotingRows(tx, target, snap); err != nil {
		return err
	}
	return updateVotingHeader(tx, target, snap.Header())
}

func updateVotingHeader(tx *sql.Tx, target votingRowTarget, hdr crypto.OneTimeSignatureSecretsHeader) error {
	result, err := tx.Exec(target.updateHeader, append([]any{protocol.Encode(&hdr)}, target.prefixArgs...)...)
	if err != nil {
		return fmt.Errorf("failed to update the voting header: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("voting header update affected %d rows, expected 1", n)
	}
	return nil
}

// syncVotingRows brings the store from the stored header to the state of
// snap, writing only the transition: consumed subkey rows are deleted, a
// batch rollover additionally replaces the offset rows, and the header is
// updated.  Subkeys advance monotonically (batch rows are written once and
// only deleted afterwards; offset rows are consumed from the front and
// regenerated per batch), so every transition has an exact expected row
// count; a mismatch means the stored rows drifted from the header and the
// store is repaired by rewriting it from memory, which is safe because the
// monotonicity guard below has established that storage is not ahead.
//
// Forward security requires the stored deletion cursor to be monotonic: if
// storage is ahead of memory, writing memory would resurrect keys that were
// already deleted on disk, so that state is an error rather than a repair.
func syncVotingRows(tx *sql.Tx, target votingRowTarget, stored crypto.OneTimeSignatureSecretsHeader, snap crypto.OneTimeSignatureSecretsPersistent) error {
	mem := snap.Header()
	if storedHeaderAhead(stored, mem) {
		return fmt.Errorf("stored voting state (batch %d, offset %d, %d+%d subkeys) is ahead of memory (batch %d, offset %d, %d+%d subkeys): stale or corrupt store; refusing to resurrect deleted keys",
			stored.FirstBatch, stored.FirstOffset, stored.BatchCount, stored.OffsetCount,
			mem.FirstBatch, mem.FirstOffset, mem.BatchCount, mem.OffsetCount)
	}
	if stored == mem {
		return nil
	}

	err := applyVotingTransition(tx, target, stored, mem, snap)
	if errors.Is(err, errInconsistentVotingRows) {
		// reaching this path means a disk problem or a bug — repair it, but
		// never silently
		logging.Base().Warnf("participation voting subkey rows were inconsistent with the stored header and have been rebuilt from memory: %v", err)
		return rewriteVotingRows(tx, target, snap)
	}
	if err != nil {
		return err
	}
	return updateVotingHeader(tx, target, mem)
}

// applyVotingTransition deletes (and, on a batch rollover, re-inserts) the
// subkey rows that differ between the stored and in-memory headers.  It does
// not touch the header itself.
func applyVotingTransition(tx *sql.Tx, target votingRowTarget, stored, mem crypto.OneTimeSignatureSecretsHeader, snap crypto.OneTimeSignatureSecretsPersistent) error {
	switch {
	case mem.Exhausted():
		if err := deleteExpecting(tx, target.deleteAllBatches, target.prefixArgs, stored.BatchCount, "retiring batch subkeys"); err != nil {
			return err
		}
		return deleteExpecting(tx, target.deleteAllOffsets, target.prefixArgs, stored.OffsetCount, "retiring offset subkeys")

	case mem.FirstBatch == stored.FirstBatch:
		// common per-round path: offsets consumed from the front of the
		// current batch (the guard guarantees mem.FirstOffset >= stored.FirstOffset)
		consumed := mem.FirstOffset - stored.FirstOffset
		if mem.BatchCount != stored.BatchCount || mem.OffsetCount+consumed != stored.OffsetCount {
			return fmt.Errorf("%w: same-batch transition with batch count %d->%d, offset count %d->%d, first offset %d->%d",
				errInconsistentVotingRows, stored.BatchCount, mem.BatchCount, stored.OffsetCount, mem.OffsetCount, stored.FirstOffset, mem.FirstOffset)
		}
		return deleteExpecting(tx, target.deleteOffsetsBelow, target.args(int64(mem.FirstOffset)), consumed, "offset subkey trim")

	default:
		// batch rollover (mem.FirstBatch > stored.FirstBatch): batch rows
		// consumed from the front, offset rows regenerated for the new batch
		if mem.BatchCount > stored.BatchCount {
			return fmt.Errorf("%w: batch rollover with batch count %d->%d", errInconsistentVotingRows, stored.BatchCount, mem.BatchCount)
		}
		if err := deleteExpecting(tx, target.deleteBatchesBelow, target.args(int64(mem.FirstBatch)), stored.BatchCount-mem.BatchCount, "batch subkey trim"); err != nil {
			return err
		}
		if err := deleteExpecting(tx, target.deleteAllOffsets, target.prefixArgs, stored.OffsetCount, "offset subkey replacement"); err != nil {
			return err
		}
		if mem.OffsetCount == 0 {
			return nil
		}
		batch, err := offsetsBatch(mem)
		if err != nil {
			return err
		}
		if err := insertKeyedSubkeys(tx, target.insertOffset, target.args(batch), snap.EncodedOffsets()); err != nil {
			return fmt.Errorf("failed to insert voting offset subkeys: %w", err)
		}
		return nil
	}
}

// deleteExpecting runs a delete that must remove exactly expected rows.
func deleteExpecting(tx *sql.Tx, query string, args []any, expected uint64, what string) error {
	result, err := tx.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("%s failed: %w", what, err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != int64(expected) {
		return fmt.Errorf("%w: %s affected %d rows, expected %d", errInconsistentVotingRows, what, n, expected)
	}
	return nil
}

// readVotingHeader reads and decodes the stored header of a key.
func readVotingHeader(tx *sql.Tx, target votingRowTarget) (crypto.OneTimeSignatureSecretsHeader, error) {
	var raw []byte
	if err := tx.QueryRow(target.selectHeader, target.prefixArgs...).Scan(&raw); err != nil {
		return crypto.OneTimeSignatureSecretsHeader{}, fmt.Errorf("failed to read the stored voting header: %w", err)
	}
	hdr, err := decodeVotingHeader(raw)
	if err != nil {
		return hdr, fmt.Errorf("stored voting header is undecodable: %w", err)
	}
	return hdr, nil
}

// readVotingRows reads the subkey rows of a key: batches ordered by index,
// offsets ordered by index along with each offset row's batch column.
func readVotingRows(tx *sql.Tx, target votingRowTarget) (batches, offsets []crypto.KeyedSubkey, offsetBatches []uint64, err error) {
	batches, err = readKeyedSubkeys(tx, target.selectBatches, target.prefixArgs...)
	if err != nil {
		return nil, nil, nil, err
	}
	offsets, offsetBatches, err = readOffsetSubkeys(tx, target.selectOffsets, target.prefixArgs...)
	if err != nil {
		return nil, nil, nil, err
	}
	return batches, offsets, offsetBatches, nil
}

// votingFromRows reassembles voting secrets from a header and its rows,
// checking first that every offset row belongs to the batch the header says
// is expanded.  Errors are wrapped in ErrCorruptedVotingData.
func votingFromRows(hdr crypto.OneTimeSignatureSecretsHeader, batches, offsets []crypto.KeyedSubkey, offsetBatches []uint64) (*crypto.OneTimeSignatureSecrets, error) {
	if err := validateOffsetRowBatches(hdr, offsetBatches); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptedVotingData, err)
	}
	voting, err := crypto.OneTimeSignatureSecretsFromRows(hdr, batches, offsets)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptedVotingData, err)
	}
	return voting, nil
}

// validateOffsetRowBatches verifies every stored offset row belongs to batch
// FirstBatch-1, so a header/row mismatch cannot silently associate offsets
// with the wrong batch.
func validateOffsetRowBatches(hdr crypto.OneTimeSignatureSecretsHeader, offsetBatches []uint64) error {
	if len(offsetBatches) == 0 {
		return nil
	}
	want, err := offsetsBatch(hdr)
	if err != nil {
		return err
	}
	for _, b := range offsetBatches {
		if b != want {
			return fmt.Errorf("offset subkey row belongs to batch %d, expected batch %d", b, want)
		}
	}
	return nil
}

// verifyVotingRowsMatch reads back what a migration wrote and compares the
// reassembled secrets against the original key material.
func verifyVotingRowsMatch(tx *sql.Tx, target votingRowTarget, original *crypto.OneTimeSignatureSecrets) error {
	hdr, err := readVotingHeader(tx, target)
	if err != nil {
		return fmt.Errorf("reading back the converted voting state: %w", err)
	}
	batches, offsets, offsetBatches, err := readVotingRows(tx, target)
	if err != nil {
		return fmt.Errorf("reading back the converted voting subkey rows: %w", err)
	}
	reconstructed, err := votingFromRows(hdr, batches, offsets, offsetBatches)
	if err != nil {
		return fmt.Errorf("reconstruction of the converted voting state failed: %w", err)
	}
	origSnap := original.Snapshot()
	newSnap := reconstructed.Snapshot()
	if !bytes.Equal(protocol.Encode(&origSnap), protocol.Encode(&newSnap)) {
		return errors.New("converted voting state does not match the original key material")
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
