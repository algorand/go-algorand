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
	selectOffsets      string // args: (prefixArgs...) -> (off, data) ordered by off
	deleteAllBatches   string // args: (prefixArgs...)
	deleteBatchesBelow string // args: (prefixArgs..., threshold)
	deleteAllOffsets   string // args: (prefixArgs...)
	deleteOffsetsBelow string // args: (prefixArgs..., threshold)
	insertBatch        string // args: (prefixArgs..., index, data)
	insertOffset       string // args: (prefixArgs..., index, data)
	updateHeader       string // args: (header, prefixArgs...)
	prefixArgs         []any
}

var partkeyFileVotingTarget = votingRowTarget{
	selectHeader:       "SELECT votingHeader FROM ParticipationAccount",
	selectBatches:      "SELECT batch, data FROM VotingBatches ORDER BY batch",
	selectOffsets:      "SELECT off, data FROM VotingOffsets ORDER BY off",
	deleteAllBatches:   "DELETE FROM VotingBatches",
	deleteBatchesBelow: "DELETE FROM VotingBatches WHERE batch<?",
	deleteAllOffsets:   "DELETE FROM VotingOffsets",
	deleteOffsetsBelow: "DELETE FROM VotingOffsets WHERE off<?",
	insertBatch:        "INSERT INTO VotingBatches (batch, data) VALUES (?, ?)",
	insertOffset:       "INSERT INTO VotingOffsets (off, data) VALUES (?, ?)",
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
		insertOffset:       "INSERT INTO VotingOffsets (pk, off, data) VALUES (?, ?, ?)",
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
func decodeVotingHeader(raw []byte) (hdr crypto.OneTimeSignatureSecretsHeader, err error) {
	if len(raw) == 0 {
		return hdr, errors.New("no voting header stored")
	}
	err = protocol.Decode(raw, &hdr)
	return hdr, err
}

func encodeVotingHeader(hdr crypto.OneTimeSignatureSecretsHeader) []byte {
	return protocol.Encode(&hdr)
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
	if err := insertKeyedSubkeys(tx, target.insertOffset, target.prefixArgs, snap.EncodedOffsets()); err != nil {
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
	result, err := tx.Exec(target.updateHeader, append([]any{encodeVotingHeader(hdr)}, target.prefixArgs...)...)
	return verifyExecWithOneRowEffected(err, result, "update voting header")
}

// syncVotingRows brings the store's subkey rows from the stored header to
// the state of snap, writing only the transition: consumed subkey rows are
// deleted and a batch rollover additionally replaces the offset rows.
// Subkeys advance monotonically (batch rows are written once and only deleted
// afterwards; offset rows are consumed from the front and regenerated per
// batch), so every transition has an exact expected row count; a mismatch
// means the stored rows drifted from the header and the store is repaired by
// rewriting it from memory, which is safe because the monotonicity guard
// below has established that storage is not ahead.
//
// It returns the header the caller must store to complete the transition, so
// the caller can fold it into a row update of its own; nil means nothing is
// left to write (the store already matched, or the repair rewrote the header
// along with the rows).
//
// Forward security requires the stored deletion cursor to be monotonic: if
// storage is ahead of memory, writing memory would resurrect keys that were
// already deleted on disk, so that state is an error rather than a repair.
func syncVotingRows(tx *sql.Tx, target votingRowTarget, stored crypto.OneTimeSignatureSecretsHeader, snap crypto.OneTimeSignatureSecretsPersistent) (*crypto.OneTimeSignatureSecretsHeader, error) {
	mem := snap.Header()
	if storedHeaderAhead(stored, mem) {
		return nil, fmt.Errorf("stored voting state (batch %d, offset %d, %d+%d subkeys) is ahead of memory (batch %d, offset %d, %d+%d subkeys): stale or corrupt store; refusing to resurrect deleted keys",
			stored.FirstBatch, stored.FirstOffset, stored.BatchCount, stored.OffsetCount,
			mem.FirstBatch, mem.FirstOffset, mem.BatchCount, mem.OffsetCount)
	}
	if stored == mem {
		return nil, nil
	}

	err := applyVotingTransition(tx, target, stored, mem, snap)
	if errors.Is(err, errInconsistentVotingRows) {
		// reaching this path means a disk problem or a bug — repair it, but
		// never silently
		logging.Base().Warnf("participation voting subkey rows were inconsistent with the stored header and have been rebuilt from memory: %v", err)
		return nil, rewriteVotingRows(tx, target, snap)
	}
	if err != nil {
		return nil, err
	}
	return &mem, nil
}

// syncVotingRowsAndHeader reads the stored header, runs syncVotingRows, and
// writes the resulting header, for callers with no row update of their own to
// fold it into.  An unusable stored header fails closed: without the stored
// cursor there is no way to tell whether memory lags storage.
func syncVotingRowsAndHeader(tx *sql.Tx, target votingRowTarget, snap crypto.OneTimeSignatureSecretsPersistent) error {
	stored, err := readVotingHeader(tx, target)
	if err != nil {
		return fmt.Errorf("%w; refusing to rewrite voting rows from memory", err)
	}
	hdr, err := syncVotingRows(tx, target, stored, snap)
	if err != nil || hdr == nil {
		return err
	}
	return updateVotingHeader(tx, target, *hdr)
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
		if err := insertKeyedSubkeys(tx, target.insertOffset, target.prefixArgs, snap.EncodedOffsets()); err != nil {
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

// readVotingRows reads the subkey rows of a key, each ordered by index.
func readVotingRows(tx *sql.Tx, target votingRowTarget) (batches, offsets []crypto.KeyedSubkey, err error) {
	if batches, err = readKeyedSubkeys(tx, target.selectBatches, target.prefixArgs...); err != nil {
		return nil, nil, err
	}
	if offsets, err = readKeyedSubkeys(tx, target.selectOffsets, target.prefixArgs...); err != nil {
		return nil, nil, err
	}
	return batches, offsets, nil
}

// votingFromRows reassembles voting secrets from a header and its rows.
// Errors are wrapped in ErrCorruptedVotingData.
func votingFromRows(hdr crypto.OneTimeSignatureSecretsHeader, batches, offsets []crypto.KeyedSubkey) (*crypto.OneTimeSignatureSecrets, error) {
	voting, err := crypto.OneTimeSignatureSecretsFromRows(hdr, batches, offsets)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptedVotingData, err)
	}
	return voting, nil
}

// verifyVotingRowsMatch reads back what a migration wrote and compares the
// reassembled secrets against the original key material.
func verifyVotingRowsMatch(tx *sql.Tx, target votingRowTarget, original *crypto.OneTimeSignatureSecrets) error {
	hdr, err := readVotingHeader(tx, target)
	if err != nil {
		return fmt.Errorf("reading back the converted voting state: %w", err)
	}
	batches, offsets, err := readVotingRows(tx, target)
	if err != nil {
		return fmt.Errorf("reading back the converted voting subkey rows: %w", err)
	}
	reconstructed, err := votingFromRows(hdr, batches, offsets)
	if err != nil {
		return fmt.Errorf("reconstruction of the converted voting state failed: %w", err)
	}
	origSnap := original.Snapshot()
	newSnap := reconstructed.Snapshot()
	if !bytes.Equal(protocol.Encode(&origSnap), protocol.Encode(&newSnap)) {
		return fmt.Errorf("%w: converted voting state does not match the original key material", ErrCorruptedVotingData)
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

// readKeyedSubkeys reads (index, data) rows.
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
