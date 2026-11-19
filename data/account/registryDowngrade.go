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
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// Schema versions of the registry, as PRAGMA user_version records them.
// Version 1 (algod 5.0 and earlier) keeps all remaining voting subkeys of a
// record in the Rolling.voting blob; version 2 (dbSchemaUpgrade1) keeps them
// in VotingBatches and VotingOffsets, described by Rolling.votingHeader.
const (
	registrySchemaVotingBlob = 1
	registrySchemaVotingRows = 2
)

// createRollingV1 is the Rolling table of a version 1 registry, as algod 5.0
// creates it (the text is copied from 5.0.5), so a downgraded registry has
// the same table definition as one 5.0 created.
const createRollingV1 = `CREATE TABLE Rolling (
			pk INTEGER PRIMARY KEY NOT NULL,

			lastVoteRound               INTEGER,
			lastBlockProposalRound      INTEGER,
			lastStateProofRound         INTEGER,
			effectiveFirstRound         INTEGER,
			effectiveLastRound          INTEGER,

			voting BLOB --*  msgpack encoding of ParticipationAccount.voting
		)`

// walEraseScratchTable is the table db.Accessor.EraseWAL writes its zero
// pages through. A version 1 registry does not have it.
const walEraseScratchTable = "walErase"

// ErrRegistryAlreadyVersion1 is returned by DowngradeRegistry for a registry
// that already has schema version 1.
var ErrRegistryAlreadyVersion1 = errors.New("participation registry already has schema version 1")

// errDowngradeDryRun rolls back the transaction of a dry run.
var errDowngradeDryRun = errors.New("dry run")

// DowngradedRecord describes a registry record converted by DowngradeRegistry.
type DowngradedRecord struct {
	ParticipationID ParticipationID
	Account         basics.Address
	FirstValid      basics.Round
	LastValid       basics.Round

	// Voting describes the voting subkeys moved into the record's
	// Rolling.voting blob; nil for a record stored without voting secrets.
	Voting *crypto.OneTimeSignatureSecretsHeader
}

// downgradeRecord is one Rolling row being converted, with the version 2
// state it was read from and the version 1 blob built from it.
type downgradeRecord struct {
	DowngradedRecord

	pk                int64
	lastVote          sql.NullInt64
	lastBlockProposal sql.NullInt64
	lastStateProof    sql.NullInt64
	effectiveFirst    sql.NullInt64
	effectiveLast     sql.NullInt64
	rawHeader         []byte
	batches, offsets  []crypto.KeyedSubkey
	voting            []byte
}

// DowngradeRegistry converts the participation registry database in filename
// from schema version 2 to version 1, so algod 5.0 or earlier can open it.
// No process may have the database open. The conversion runs in one
// transaction and is verified before it commits; afterwards the write-ahead
// log is erased, since it holds images of the dropped subkey rows.
//
// With dryRun the conversion and its verification run and are rolled back,
// leaving the database unchanged. A later algod upgrades the downgraded
// registry again when it opens it.
func DowngradeRegistry(filename string, dryRun bool) ([]DowngradedRecord, error) {
	// the accessor would create a missing file
	if _, err := os.Stat(filename); err != nil {
		return nil, err
	}
	accessor, err := db.MakeErasableAccessor(filename)
	if err != nil {
		return nil, err
	}
	defer accessor.Close()

	var records []DowngradedRecord
	err = accessor.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var txErr error
		records, txErr = dbSchemaDowngrade2(ctx, tx)
		if txErr == nil && dryRun {
			return errDowngradeDryRun
		}
		return txErr
	})
	if dryRun && errors.Is(err, errDowngradeDryRun) {
		return records, nil
	}
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	if err = accessor.EraseWAL(ctx, true); err != nil {
		return records, fmt.Errorf("registry downgraded, but erasing its write-ahead log failed: %w", err)
	}
	// EraseWAL leaves its scratch table behind; dropping it frees only zero
	// pages, and the TRUNCATE checkpoint then empties the log again
	if _, err = accessor.Handle.ExecContext(ctx, "DROP TABLE IF EXISTS "+walEraseScratchTable); err != nil {
		return records, fmt.Errorf("registry downgraded, but dropping %s failed: %w", walEraseScratchTable, err)
	}
	if _, err = accessor.Handle.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return records, fmt.Errorf("registry downgraded, but checkpointing its write-ahead log failed: %w", err)
	}
	return records, nil
}

// dbSchemaDowngrade2 is the inverse of dbSchemaUpgrade1: it reassembles each
// record's voting secrets from its header and subkey rows into the version 1
// Rolling.voting blob, rebuilds Rolling as version 1 creates it, drops the
// subkey tables and sets user_version to 1. It reads everything back and
// compares it with what it read before returning.
func dbSchemaDowngrade2(ctx context.Context, tx *sql.Tx) ([]DowngradedRecord, error) {
	version, err := db.GetUserVersion(ctx, tx)
	if err != nil {
		return nil, err
	}
	switch version {
	case registrySchemaVotingRows:
	case registrySchemaVotingBlob:
		return nil, ErrRegistryAlreadyVersion1
	default:
		return nil, fmt.Errorf("participation registry has schema version %d; only version %d can be downgraded", version, registrySchemaVotingRows)
	}
	// the subkey rows are dropped below and must be erased, not left in free pages
	if err = enableSecureDelete(tx); err != nil {
		return nil, err
	}

	records, err := readDowngradeRecords(ctx, tx)
	if err != nil {
		return nil, err
	}
	for i := range records {
		if err = records[i].buildVotingBlob(tx); err != nil {
			return nil, fmt.Errorf("registry record pk %d cannot be downgraded: %w", records[i].pk, err)
		}
	}

	if err = rebuildRollingV1(ctx, tx, records); err != nil {
		return nil, err
	}
	for _, table := range []string{"VotingBatches", "VotingOffsets", walEraseScratchTable} {
		if _, err = tx.ExecContext(ctx, "DROP TABLE IF EXISTS "+table); err != nil {
			return nil, fmt.Errorf("failed to drop %s: %w", table, err)
		}
	}
	if _, err = db.SetUserVersion(ctx, tx, registrySchemaVotingBlob); err != nil {
		return nil, err
	}

	if err = verifyDowngrade(ctx, tx, records); err != nil {
		return nil, fmt.Errorf("downgraded registry failed verification: %w", err)
	}

	result := make([]DowngradedRecord, len(records))
	for i := range records {
		result[i] = records[i].DowngradedRecord
	}
	return result, nil
}

// readDowngradeRecords reads every Rolling row of a version 2 registry, with
// the Keysets fields that identify it. A Rolling row without a Keysets row is
// kept, as version 1 would keep it.
func readDowngradeRecords(ctx context.Context, tx *sql.Tx) ([]downgradeRecord, error) {
	rows, err := tx.QueryContext(ctx, `SELECT
			r.pk, r.lastVoteRound, r.lastBlockProposalRound, r.lastStateProofRound,
			r.effectiveFirstRound, r.effectiveLastRound, r.votingHeader,
			k.participationID, k.account, k.firstValidRound, k.lastValidRound
		FROM Rolling r
		LEFT JOIN Keysets k
		ON k.pk = r.pk
		ORDER BY r.pk`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []downgradeRecord
	for rows.Next() {
		var r downgradeRecord
		var rawID, rawAccount []byte
		var firstValid, lastValid sql.NullInt64
		err = rows.Scan(&r.pk, &r.lastVote, &r.lastBlockProposal, &r.lastStateProof,
			&r.effectiveFirst, &r.effectiveLast, &r.rawHeader,
			&rawID, &rawAccount, &firstValid, &lastValid)
		if err != nil {
			return nil, err
		}
		copy(r.ParticipationID[:], rawID)
		copy(r.Account[:], rawAccount)
		r.FirstValid = basics.Round(firstValid.Int64)
		r.LastValid = basics.Round(lastValid.Int64)
		records = append(records, r)
	}
	return records, rows.Err()
}

// buildVotingBlob reads the record's subkey rows and encodes the voting
// secrets they describe as algod 5.0 stores them: the msgpack encoding of a
// crypto.OneTimeSignatureSecrets. A record without a header gets no blob,
// which is how dbSchemaUpgrade1 treats an empty blob.
func (r *downgradeRecord) buildVotingBlob(tx *sql.Tx) error {
	if len(r.rawHeader) == 0 {
		return nil
	}
	hdr, err := decodeVotingHeader(r.rawHeader)
	if err != nil {
		return fmt.Errorf("undecodable voting header: %w", err)
	}
	if r.batches, r.offsets, err = readVotingRows(tx, r.pk); err != nil {
		return err
	}
	secrets, err := votingFromRows(hdr, r.batches, r.offsets)
	if err != nil {
		return err
	}
	snap := secrets.Snapshot()
	r.voting = protocol.Encode(&snap)
	r.Voting = &hdr
	return nil
}

// rebuildRollingV1 replaces Rolling with the version 1 table holding the same
// rows, each with its voting blob instead of its header.
func rebuildRollingV1(ctx context.Context, tx *sql.Tx, records []downgradeRecord) error {
	const renamed = "RollingVotingRows"
	if _, err := tx.ExecContext(ctx, "ALTER TABLE Rolling RENAME TO "+renamed); err != nil {
		return fmt.Errorf("failed to rename Rolling: %w", err)
	}
	if _, err := tx.ExecContext(ctx, createRollingV1); err != nil {
		return fmt.Errorf("failed to create the version 1 Rolling table: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO Rolling (
			pk, lastVoteRound, lastBlockProposalRound, lastStateProofRound,
			effectiveFirstRound, effectiveLastRound, voting)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range records {
		_, err = stmt.ExecContext(ctx, r.pk, r.lastVote, r.lastBlockProposal, r.lastStateProof,
			r.effectiveFirst, r.effectiveLast, r.voting)
		if err != nil {
			return fmt.Errorf("failed to copy Rolling row pk %d: %w", r.pk, err)
		}
	}
	if _, err = tx.ExecContext(ctx, "DROP TABLE "+renamed); err != nil {
		return fmt.Errorf("failed to drop %s: %w", renamed, err)
	}
	return nil
}

// verifyDowngrade checks the converted registry against the records it was
// built from: the tables are those of version 1, every Rolling row keeps its
// fields, and every voting blob decodes to the header and subkey rows the
// record had.
func verifyDowngrade(ctx context.Context, tx *sql.Tx, records []downgradeRecord) error {
	var tables []string
	rows, err := tx.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, name)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	if want := []string{"Keysets", "Rolling", "StateProofKeys"}; !slices.Equal(tables, want) {
		return fmt.Errorf("tables %v, want %v", tables, want)
	}

	rows, err = tx.QueryContext(ctx, `SELECT pk, lastVoteRound, lastBlockProposalRound, lastStateProofRound,
			effectiveFirstRound, effectiveLastRound, voting
		FROM Rolling ORDER BY pk`)
	if err != nil {
		return err
	}
	defer rows.Close()
	i := 0
	for ; rows.Next(); i++ {
		var got downgradeRecord
		err = rows.Scan(&got.pk, &got.lastVote, &got.lastBlockProposal, &got.lastStateProof,
			&got.effectiveFirst, &got.effectiveLast, &got.voting)
		if err != nil {
			return err
		}
		if i >= len(records) {
			return fmt.Errorf("the Rolling table has more than the %d rows it had", len(records))
		}
		want := records[i]
		if got.pk != want.pk || got.lastVote != want.lastVote || got.lastBlockProposal != want.lastBlockProposal ||
			got.lastStateProof != want.lastStateProof || got.effectiveFirst != want.effectiveFirst || got.effectiveLast != want.effectiveLast {
			return fmt.Errorf("the Rolling row pk %d differs from the row it was copied from (pk %d)", got.pk, want.pk)
		}
		if err = verifyVotingBlob(got.voting, want); err != nil {
			return fmt.Errorf("the Rolling row pk %d: %w", got.pk, err)
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if i != len(records) {
		return fmt.Errorf("the Rolling table has %d rows, had %d", i, len(records))
	}
	return nil
}

func verifyVotingBlob(blob []byte, want downgradeRecord) error {
	if want.Voting == nil {
		if len(blob) != 0 {
			return errors.New("voting blob stored for a record without voting secrets")
		}
		return nil
	}
	var secrets crypto.OneTimeSignatureSecrets
	if err := protocol.Decode(blob, &secrets); err != nil {
		return fmt.Errorf("voting blob does not decode: %w", err)
	}
	p := secrets.OneTimeSignatureSecretsPersistent
	if p.Header() != *want.Voting {
		return errors.New("voting blob does not match the stored voting header")
	}
	if !keyedSubkeysEqual(p.EncodedBatches(), want.batches) || !keyedSubkeysEqual(p.EncodedOffsets(), want.offsets) {
		return errors.New("voting blob does not hold the stored voting subkeys")
	}
	return nil
}

func keyedSubkeysEqual(a, b []crypto.KeyedSubkey) bool {
	return slices.EqualFunc(a, b, func(x, y crypto.KeyedSubkey) bool {
		return x.Index == y.Index && bytes.Equal(x.Key, y.Key)
	})
}
