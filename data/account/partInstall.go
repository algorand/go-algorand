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
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

// PartTableSchemaName is the name of the table in the Schema Versions table storing the table + version details
const PartTableSchemaName = "parttable"

// PartTableSchemaVersion is the latest version of the PartTable schema
const PartTableSchemaVersion = 4

// PartTableSchemaVersionVotingSplit is the schema version that split the
// voting secrets into per-subkey rows.
const PartTableSchemaVersionVotingSplit = 4

// ErrUnsupportedSchema is the error returned when the PartTable schema version is wrong.
var ErrUnsupportedSchema = fmt.Errorf("unsupported participation file schema version (expected %d)", PartTableSchemaVersion)

func partInstallDatabase(tx *sql.Tx) error {
	var err error

	_, err = tx.Exec(`CREATE TABLE ParticipationAccount (
		parent BLOB,

		--* participation keys
		vrf BLOB,         --*  msgpack encoding of ParticipationAccount.vrf
		votingHeader BLOB, --*  msgpack encoding of crypto.OneTimeSignatureSecretsHeader

		firstValid INTEGER,
		lastValid INTEGER,

		keyDilution INTEGER NOT NULL DEFAULT 0,
		stateProof BLOB  --*  msgpack encoding of ParticipationAccount.StateProof
	);`)
	if err != nil {
		return err
	}

	err = createVotingSubkeyTables(tx)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`CREATE TABLE schema (
		tablename TEXT PRIMARY KEY,
		version INTEGER
	);`)
	if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT INTO schema (tablename, version) VALUES (?, ?)",
		PartTableSchemaName, PartTableSchemaVersion)
	if err != nil {
		return err
	}

	return nil
}

func partMigrate(tx *sql.Tx) (err error) {
	rows, err := tx.Query("SELECT tablename, version FROM schema")
	if err != nil {
		return ErrUnsupportedSchema
	}
	defer rows.Close()

	versions := make(map[string]int)
	for rows.Next() {
		var tableName string
		var version int
		err = rows.Scan(&tableName, &version)
		if err != nil {
			return err
		}
		versions[tableName] = version
	}

	err = rows.Err()
	if err != nil {
		return err
	}

	partVersion, has := versions[PartTableSchemaName]
	if !has {
		return ErrUnsupportedSchema
	}

	partVersion, err = updateDB(tx, partVersion)
	if err != nil {
		return err
	}

	if partVersion != PartTableSchemaVersion {
		return ErrUnsupportedSchema
	}

	return nil
}

func updateDB(tx *sql.Tx, partVersion int) (int, error) {
	if partVersion == 3 {
		err := migrateVotingBlobToRows(tx)
		if err != nil {
			return 0, err
		}

		partVersion = 4
		_, err = tx.Exec("UPDATE schema SET version=? WHERE tablename=?", partVersion, PartTableSchemaName)
		if err != nil {
			return 0, err
		}
	}
	return partVersion, nil
}

func createVotingSubkeyTables(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE VotingBatches (
		batch INTEGER PRIMARY KEY, --* absolute batch number
		data BLOB NOT NULL         --* msgpack encoding of the batch subkey
	);`)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`CREATE TABLE VotingOffsets (
		batch INTEGER NOT NULL, --* the batch these offsets belong to (FirstBatch-1)
		off INTEGER NOT NULL,   --* absolute offset within batch
		data BLOB NOT NULL,     --* msgpack encoding of the offset subkey
		PRIMARY KEY (batch, off)
	);`)
	return err
}

// migrateVotingBlobToRows converts the whole-secrets voting blob of a version
// 3 file into a votingHeader column plus per-subkey rows.  The converted state
// is read back and compared against the original key material before the
// transaction may commit, and the legacy column is then dropped so the blob
// (which held every subkey) is erased from the file.
func migrateVotingBlobToRows(tx *sql.Tx) error {
	if err := createVotingSubkeyTables(tx); err != nil {
		return err
	}
	if _, err := tx.Exec("ALTER TABLE ParticipationAccount ADD COLUMN votingHeader BLOB"); err != nil {
		return fmt.Errorf("migrateVotingBlobToRows: failed to add the votingHeader column: %w", err)
	}

	var rawVoting []byte
	err := tx.QueryRow("SELECT voting FROM ParticipationAccount").Scan(&rawVoting)
	switch {
	case err == sql.ErrNoRows:
		// no account row (partially initialized file); nothing to convert
	case err != nil:
		return err
	case len(rawVoting) > 0:
		voting := &crypto.OneTimeSignatureSecrets{}
		if err := protocol.Decode(rawVoting, voting); err != nil {
			return fmt.Errorf("migrateVotingBlobToRows: failed to decode the voting blob: %w", err)
		}
		// freshly decoded and unshared: no lock is needed for the snapshot
		if err := rewriteVotingRows(tx, partkeyFileVotingTarget, voting.OneTimeSignatureSecretsPersistent); err != nil {
			return fmt.Errorf("migrateVotingBlobToRows: %w", err)
		}
		if err := verifyVotingRowsMatch(tx, partkeyFileVotingTarget, voting); err != nil {
			return fmt.Errorf("migrateVotingBlobToRows: %w", err)
		}
	}

	if _, err := tx.Exec("ALTER TABLE ParticipationAccount DROP COLUMN voting"); err != nil {
		return fmt.Errorf("migrateVotingBlobToRows: failed to drop the legacy voting column: %w", err)
	}
	return nil
}

// PartkeySchemaVersion reads the participation file's schema version without
// migrating it.  Returns ErrUnsupportedSchema if no version is recorded.
func PartkeySchemaVersion(store db.Accessor) (version int, err error) {
	err = store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		serr := tx.QueryRow("SELECT version FROM schema WHERE tablename=?", PartTableSchemaName).Scan(&version)
		if serr == sql.ErrNoRows {
			return ErrUnsupportedSchema
		}
		return serr
	})
	return version, err
}
