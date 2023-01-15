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

/* This file contains every database and persistence related method for the merkle Secrets.
 * It is used when generating the State Proof keys (storing them into a database), and for
 * importing those keys from the created database file into the algod participation registry.
 */

package merklesignature

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

const merkleSignatureSchemaVersion = 1
const merkleSignatureTableSchemaName = "merklesignaturescheme"

// Errors for the persistent merkle signature scheme
var (
	errSelectKeysError = errors.New("failed to fetch stateproof keys from DB")
	errKeyDecodeError  = errors.New("failed to decode stateproof key")
)

// InstallStateProofTable creates (or migrates if exists already) the StateProofKeys database table
func InstallStateProofTable(tx *sql.Tx) error {
	var schemaVersion sql.NullInt32
	err := tx.QueryRow("SELECT version FROM schema where tablename = ?", merkleSignatureTableSchemaName).Scan(&schemaVersion)
	switch err {
	case sql.ErrNoRows:
		// proceed with the installation of the StateProofKeys table.
	case nil:
		// we were able to read from the schema successfully.
		if schemaVersion.Valid {
			switch schemaVersion.Int32 {
			case merkleSignatureSchemaVersion:
				// we're already at the desired version.
				return nil
			default:
				// we're not at the desired version, proceed with update.
			}
		}
	default:
		// we hit some unexpected error
		return fmt.Errorf("unable to query version from schema table : %w", err)
	}

	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS StateProofKeys (
    	id	  INTEGER PRIMARY KEY, 
    	round INTEGER,	    --*  committed round for this key
		key   BLOB  --*  msgpack encoding of ParticipationAccount.StateProof.GenericSigningKey
		);`)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS roundIdx ON StateProofKeys (round);`)
	if err != nil {
		return err
	}

	// drop existing value from the schema and insert updated value.
	_, err = tx.Exec("DELETE FROM schema WHERE tablename = ?", merkleSignatureTableSchemaName)
	if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT INTO schema (tablename, version) VALUES (?, ?)", merkleSignatureTableSchemaName, merkleSignatureSchemaVersion)

	return err
}

// Persist dumps the keys into the database and deletes the reference to them in Secrets
func (s *Secrets) Persist(store db.Accessor) error {
	if s.ephemeralKeys == nil {
		return fmt.Errorf("no keys provided (nil)")
	}
	if s.KeyLifetime == 0 {
		return fmt.Errorf("Secrets.Persist: %w", ErrKeyLifetimeIsZero)
	}
	round := indexToRound(s.FirstValid, s.KeyLifetime, 0)
	encodedKey := protocol.GetEncodingBuf()
	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		err := InstallStateProofTable(tx) // assumes schema table already exists (created by partInstallDatabase)
		if err != nil {
			return err
		}

		insertStmt, err := tx.PrepareContext(ctx, "INSERT INTO StateProofKeys (id, round, key) VALUES (?,?,?)")
		if err != nil {
			return fmt.Errorf("unable to prepare insert stateproofkeys statement: %w", err)
		}
		defer insertStmt.Close()

		for i, key := range s.ephemeralKeys {
			// reset the slice
			encodedKey = encodedKey[:0]
			// store the encoded key into the slice
			encodedKey = key.MarshalMsg(encodedKey)
			_, err := insertStmt.ExecContext(ctx, i, round, encodedKey)

			if err != nil {
				return fmt.Errorf("failed to insert StateProof key number %v round %d. SQL Error: %w", i, round, err)
			}
			round += s.KeyLifetime
		}

		return nil
	})
	protocol.PutEncodingBuf(encodedKey)
	if err != nil {
		return fmt.Errorf("Secrets.Persist: %w", err)
	}

	return nil // Success
}

// RestoreAllSecrets fetch all stateproof secrets from a persisted storage into memory
func (s *Secrets) RestoreAllSecrets(store db.Accessor) error {
	var keys []crypto.FalconSigner

	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.Query("SELECT key FROM StateProofKeys")
		if err != nil {
			return fmt.Errorf("%w - %v", errSelectKeysError, err)
		}
		defer rows.Close()
		for rows.Next() {
			var keyB []byte
			key := crypto.FalconSigner{}
			err := rows.Scan(&keyB)
			if err != nil {
				return fmt.Errorf("%w - %v", errKeyDecodeError, err)
			}
			err = protocol.Decode(keyB, &key)
			if err != nil {
				return err
			}
			keys = append(keys, key)
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.ephemeralKeys = keys
	return nil
}
