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

// Row-oriented storage of the registry's voting secrets.  Rolling.votingHeader
// holds a crypto.OneTimeSignatureSecretsHeader and VotingBatches/VotingOffsets
// one row per ephemeral subkey, keyed by the record's pk, so the header alone
// says exactly which rows must exist.  Three operations are provided:
// insertVotingRows for a key that is stored for the first time,
// rewriteVotingRows for format migration and repair, and syncVotingRows for
// the per-round transition from the stored header to the in-memory state.

// errInconsistentVotingRows reports that the stored subkey rows disagree with
// the stored header (a trim removed an unexpected number of rows, or the two
// headers' counts cannot be reconciled).  syncVotingRows repairs it by
// rewriting the rows from memory.
var errInconsistentVotingRows = errors.New("stored voting subkey rows are inconsistent with the stored header")

// enableSecureDelete turns on SQLite's secure_delete for the transaction's
// connection, so content freed by the following statements is overwritten
// with zeros instead of lingering in free pages.  The setting is per
// connection and harmless to leave on.
func enableSecureDelete(tx *sql.Tx) error {
	if _, err := tx.Exec("PRAGMA secure_delete=ON"); err != nil {
		return fmt.Errorf("failed to enable secure_delete: %w", err)
	}
	return nil
}

// votingSnapshot captures the state of live voting secrets for persistence.
func votingSnapshot(secrets *crypto.OneTimeSignatureSecrets) crypto.OneTimeSignatureSecretsPersistent {
	return secrets.Snapshot().OneTimeSignatureSecretsPersistent
}

// decodeVotingHeader decodes a stored voting header; an empty value is an
// error, since every record with voting secrets stores a header with them.
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

// insertVotingRows inserts one row per subkey of snap for the record pk.  It
// is the row half of storing a key for the first time; the caller stores the
// header in the record's Rolling row.
func insertVotingRows(tx *sql.Tx, pk int64, snap crypto.OneTimeSignatureSecretsPersistent) error {
	if err := insertKeyedSubkeys(tx, insertVotingBatch, pk, snap.EncodedBatches()); err != nil {
		return fmt.Errorf("failed to insert voting batch subkeys: %w", err)
	}
	if err := insertKeyedSubkeys(tx, insertVotingOffset, pk, snap.EncodedOffsets()); err != nil {
		return fmt.Errorf("failed to insert voting offset subkeys: %w", err)
	}
	return nil
}

// rewriteVotingRows replaces everything the registry holds for the record's
// key (rows and header) with snap.  Used by format migration and by repair.
func rewriteVotingRows(tx *sql.Tx, pk int64, snap crypto.OneTimeSignatureSecretsPersistent) error {
	if _, err := tx.Exec(deleteVotingBatchesPK, pk); err != nil {
		return fmt.Errorf("failed to clear voting batch subkeys: %w", err)
	}
	if _, err := tx.Exec(deleteVotingOffsetsPK, pk); err != nil {
		return fmt.Errorf("failed to clear voting offset subkeys: %w", err)
	}
	if err := insertVotingRows(tx, pk, snap); err != nil {
		return err
	}
	return updateVotingHeader(tx, pk, snap.Header())
}

func updateVotingHeader(tx *sql.Tx, pk int64, hdr crypto.OneTimeSignatureSecretsHeader) error {
	result, err := tx.Exec(updateVotingHeaderPK, encodeVotingHeader(hdr), pk)
	return verifyExecWithOneRowEffected(err, result, "update voting header")
}

// syncVotingRows brings the record's subkey rows from the stored header to
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
func syncVotingRows(tx *sql.Tx, pk int64, stored crypto.OneTimeSignatureSecretsHeader, snap crypto.OneTimeSignatureSecretsPersistent) (*crypto.OneTimeSignatureSecretsHeader, error) {
	mem := snap.Header()
	if storedHeaderAhead(stored, mem) {
		return nil, fmt.Errorf("stored voting state (batch %d, offset %d, %d+%d subkeys) is ahead of memory (batch %d, offset %d, %d+%d subkeys): stale or corrupt store; refusing to resurrect deleted keys",
			stored.FirstBatch, stored.FirstOffset, stored.BatchCount, stored.OffsetCount,
			mem.FirstBatch, mem.FirstOffset, mem.BatchCount, mem.OffsetCount)
	}
	if stored == mem {
		return nil, nil
	}

	err := applyVotingTransition(tx, pk, stored, mem, snap)
	if errors.Is(err, errInconsistentVotingRows) {
		// reaching this path means a disk problem or a bug — repair it, but
		// never silently
		logging.Base().Warnf("participation voting subkey rows were inconsistent with the stored header and have been rebuilt from memory: %v", err)
		return nil, rewriteVotingRows(tx, pk, snap)
	}
	if err != nil {
		return nil, err
	}
	return &mem, nil
}

// votingTransitionBulk reports whether a syncVotingRows transition from
// stored to mem (returning hdr) wrote subkey rows wholesale: a rollover to a
// new batch, whose offset rows are written together and then consumed one
// per round, or a repair, which rewrites everything (a nil hdr for a changed
// state).  The caller erases such writes from the write-ahead log at once
// rather than at the next write; see db.Accessor.EraseWAL.
func votingTransitionBulk(stored, mem crypto.OneTimeSignatureSecretsHeader, hdr *crypto.OneTimeSignatureSecretsHeader) bool {
	return stored.FirstBatch != mem.FirstBatch || (hdr == nil && stored != mem)
}

// applyVotingTransition deletes (and, on a batch rollover, re-inserts) the
// subkey rows that differ between the stored and in-memory headers.  It does
// not touch the header itself.
func applyVotingTransition(tx *sql.Tx, pk int64, stored, mem crypto.OneTimeSignatureSecretsHeader, snap crypto.OneTimeSignatureSecretsPersistent) error {
	switch {
	case mem.Exhausted():
		if err := deleteExactly(tx, deleteVotingBatchesPK, []any{pk}, stored.BatchCount, "retiring batch subkeys"); err != nil {
			return err
		}
		return deleteExactly(tx, deleteVotingOffsetsPK, []any{pk}, stored.OffsetCount, "retiring offset subkeys")

	case mem.FirstBatch == stored.FirstBatch:
		// common per-round path: offsets consumed from the front of the
		// current batch (the guard guarantees mem.FirstOffset >= stored.FirstOffset)
		consumed := mem.FirstOffset - stored.FirstOffset
		if mem.BatchCount != stored.BatchCount || mem.OffsetCount+consumed != stored.OffsetCount {
			return fmt.Errorf("%w: same-batch transition with batch count %d->%d, offset count %d->%d, first offset %d->%d",
				errInconsistentVotingRows, stored.BatchCount, mem.BatchCount, stored.OffsetCount, mem.OffsetCount, stored.FirstOffset, mem.FirstOffset)
		}
		return deleteExactly(tx, deleteVotingOffsetsBelow, []any{pk, int64(mem.FirstOffset)}, consumed, "offset subkey trim")

	default:
		// batch rollover (mem.FirstBatch > stored.FirstBatch): batch rows
		// consumed from the front, offset rows regenerated for the new batch
		if mem.BatchCount > stored.BatchCount {
			return fmt.Errorf("%w: batch rollover with batch count %d->%d", errInconsistentVotingRows, stored.BatchCount, mem.BatchCount)
		}
		if err := deleteExactly(tx, deleteVotingBatchesBelow, []any{pk, int64(mem.FirstBatch)}, stored.BatchCount-mem.BatchCount, "batch subkey trim"); err != nil {
			return err
		}
		if err := deleteExactly(tx, deleteVotingOffsetsPK, []any{pk}, stored.OffsetCount, "offset subkey replacement"); err != nil {
			return err
		}
		if err := insertKeyedSubkeys(tx, insertVotingOffset, pk, snap.EncodedOffsets()); err != nil {
			return fmt.Errorf("failed to insert voting offset subkeys: %w", err)
		}
		return nil
	}
}

// deleteExactly runs a delete that must remove exactly expected rows.
func deleteExactly(tx *sql.Tx, query string, args []any, expected uint64, what string) error {
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

// readVotingHeader reads and decodes the stored header of the record pk.
func readVotingHeader(tx *sql.Tx, pk int64) (crypto.OneTimeSignatureSecretsHeader, error) {
	var raw []byte
	if err := tx.QueryRow(selectVotingHeaderPK, pk).Scan(&raw); err != nil {
		return crypto.OneTimeSignatureSecretsHeader{}, fmt.Errorf("failed to read the stored voting header: %w", err)
	}
	hdr, err := decodeVotingHeader(raw)
	if err != nil {
		return hdr, fmt.Errorf("stored voting header is undecodable: %w", err)
	}
	return hdr, nil
}

// readVotingRows reads the subkey rows of the record pk, each ordered by index.
func readVotingRows(tx *sql.Tx, pk int64) (batches, offsets []crypto.KeyedSubkey, err error) {
	if batches, err = readKeyedSubkeys(tx, selectVotingBatches, pk); err != nil {
		return nil, nil, err
	}
	if offsets, err = readKeyedSubkeys(tx, selectVotingOffsets, pk); err != nil {
		return nil, nil, err
	}
	return batches, offsets, nil
}

// votingFromRows reassembles voting secrets from a header and its rows.
func votingFromRows(hdr crypto.OneTimeSignatureSecretsHeader, batches, offsets []crypto.KeyedSubkey) (*crypto.OneTimeSignatureSecrets, error) {
	return crypto.OneTimeSignatureSecretsFromRows(hdr, batches, offsets)
}

// verifyVotingRowsMatch reads back what a migration wrote and compares the
// reassembled secrets against the original key material.
func verifyVotingRowsMatch(tx *sql.Tx, pk int64, original *crypto.OneTimeSignatureSecrets) error {
	hdr, err := readVotingHeader(tx, pk)
	if err != nil {
		return fmt.Errorf("reading back the converted voting state: %w", err)
	}
	batches, offsets, err := readVotingRows(tx, pk)
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
		return errors.New("converted voting state does not match the original key material")
	}
	return nil
}

// insertKeyedSubkeys bulk-inserts rows with a single prepared statement.
// insertSQL must take (pk, index, data).
func insertKeyedSubkeys(tx *sql.Tx, insertSQL string, pk int64, rows []crypto.KeyedSubkey) error {
	if len(rows) == 0 {
		return nil
	}
	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, row := range rows {
		if _, err := stmt.Exec(pk, row.Index, row.Key); err != nil {
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
