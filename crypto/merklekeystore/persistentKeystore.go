// Copyright (C) 2019-2022 Algorand, Inc.
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

package merklekeystore

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

const keystoreSchemaVersion = 1
const keystoreTableSchemaName = "merklekeystore"

// PersistentKeystore Provides an abstraction to the keystore, the DB operations for fetching/storing them and an internal caching mechanism
type PersistentKeystore struct {
	store db.Accessor
}

// Persist dumps the keys into the database as separate row for each key
func (p *PersistentKeystore) Persist(keys []crypto.GenericSigningKey, firstValid uint64, interval uint64) error {
	if keys == nil {
		return fmt.Errorf("no keys provided (nil)")
	}

	err := p.store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		err := keystoreInstallDatabase(tx) // assumes schema table already exists (created by partInstallDatabase)
		if err != nil {
			return err
		}

		if interval == 0 {
			return errIntervalZero
		}
		round := indexToRound(firstValid, interval, 0)
		for i, key := range keys {
			encodedKey := key.MarshalMsg(protocol.GetEncodingBuf())
			_, err := tx.Exec("INSERT INTO StateProofKeys (id, round, key) VALUES (?,?,?)", i, round, encodedKey)
			protocol.PutEncodingBuf(encodedKey)
			if err != nil {
				return fmt.Errorf("failed to insert StateProof key number %v round %d. SQL Error: %w", i, round, err)
			}
			round += interval
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("PersistentKeystore.Persist: %w", err)
	}

	return nil // Success
}

// GetKey receives a round number and returns the corresponding (previously committed on) key.
func (p *PersistentKeystore) GetKey(round uint64) (*crypto.GenericSigningKey, error) {
	var keyB []byte
	err := p.store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		row := tx.QueryRow("SELECT key FROM StateProofKeys WHERE round = ?", round)
		err := row.Scan(&keyB)
		if err != nil {
			return fmt.Errorf("failed to select stateProof key for round %d : %w", round, err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("PersistentKeystore.GetKey: %w", err)
	}

	key := &crypto.GenericSigningKey{}
	err = protocol.Decode(keyB, key)
	if err != nil {
		return nil, fmt.Errorf("PersistentKeystore.GetKey: %w", err)
	}

	return key, nil
}

// DropKeys deletes the keys up to the specified round (including)
func (p *PersistentKeystore) DropKeys(round uint64) (count int64, err error) {
	err = p.store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		res, err := tx.Exec("DELETE FROM StateProofKeys WHERE round <= ?", round)
		if err == nil {
			count, err = res.RowsAffected()
		}
		return err
	})
	return count, err
}

func keystoreInstallDatabase(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE StateProofKeys (
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
	_, err = tx.Exec("INSERT INTO schema (tablename, version) VALUES (?, ?)", keystoreTableSchemaName, keystoreSchemaVersion)

	return err
}

// RestoreKeystore loads the PersistentKeystore from given database
func RestoreKeystore(store db.Accessor) (PersistentKeystore, error) {
	err := store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		return MigrateDB(tx)
	})
	if err != nil {
		return PersistentKeystore{}, err
	}

	return PersistentKeystore{store}, nil
}

// MigrateDB updates the database if necessary, according the schema version
func MigrateDB(tx *sql.Tx) error {
	var version int
	schemaQuery := `SELECT version FROM schema WHERE tablename = ?`
	err := tx.QueryRow(schemaQuery, keystoreTableSchemaName).Scan(&version)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		// In the future this should not return quietly, as stateproof keys will be required
		return err
	}

	// When migrations are required: err = updateDB(tx, version)
	return nil
}
