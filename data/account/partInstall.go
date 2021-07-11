// Copyright (C) 2019-2021 Algorand, Inc.
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
	"fmt"
)

// PartTableSchemaName is the name of the table in the Schema Versions table storing the table + version details
const PartTableSchemaName = "parttable"

// PartTableSchemaVersion is the latest version of the PartTable schema
const PartTableSchemaVersion = 3

// ErrUnsupportedSchema is the error returned when the PartTable schema version is wrong.
var ErrUnsupportedSchema = fmt.Errorf("unsupported participation file schema version (expected %d)", PartTableSchemaVersion)

func partInstallDatabase(tx *sql.Tx) error {
	var err error

	_, err = tx.Exec(`CREATE TABLE ParticipationAccount (
		parent BLOB,

		--* participation keys
		vrf BLOB,         --*  msgpack encoding of ParticipationAccount.vrf
		voting BLOB,      --*  msgpack encoding of ParticipationAccount.voting
		blockProof BLOB,  --*  msgpack encoding of ParticipationAccount.BlockProof

		firstValid INTEGER,
		lastValid INTEGER,

		keyDilution INTEGER NOT NULL DEFAULT 0
	);`)
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
	if partVersion == 1 {
		_, err := tx.Exec("ALTER TABLE ParticipationAccount ADD keyDilution INTEGER NOT NULL DEFAULT 0")
		if err != nil {
			return 0, err
		}

		partVersion = 2
		_, err = tx.Exec("UPDATE schema SET version=? WHERE tablename=?", partVersion, PartTableSchemaName)
		if err != nil {
			return 0, err
		}
	}

	if partVersion == 2 {
		_, err := tx.Exec("ALTER TABLE ParticipationAccount ADD blockProof BLOB")
		if err != nil {
			return 0, err
		}

		partVersion = 3
		_, err = tx.Exec("UPDATE schema SET version=? WHERE tablename=?", partVersion, PartTableSchemaName)
		if err != nil {
			return 0, err
		}
	}
	return partVersion, nil
}
