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
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/util/db"
)

const maxBalLookback = 320

// ParticipationID identifies a particular set of participation keys.
type ParticipationID crypto.Digest

// ParticipationRecord contains all metadata relating to a set of participation keys.
type ParticipationRecord struct {
	ParticipationID ParticipationID

	Account     basics.Address
	FirstValid  basics.Round
	LastValid   basics.Round
	KeyDilution uint64

	LastVote               basics.Round
	LastBlockProposal      basics.Round
	LastCompactCertificate basics.Round
	EffectiveFirst         basics.Round
	EffectiveLast          basics.Round

	// VRFSecrets
	// OneTimeSignatureSecrets
}

// ParticipationAction is used when recording participation actions.
type ParticipationAction int

// ParticipationAction types
const (
	Vote ParticipationAction = iota
	BlockProposal
	CompactCertificate
)

// ErrParticipationIDNotFound is used when attempting to update a set of keys which do not exist.
var ErrParticipationIDNotFound = errors.New("the participation ID was not found")

// ErrInvalidRegisterRange is used when attempting to register a participation key on a round that is out of range.
var ErrInvalidRegisterRange = errors.New("key would not be active within range")

// ParticipationRegistry contain all functions for interacting with the Participation Registry.
type ParticipationRegistry interface {
	// Insert adds a record to storage and computes the ParticipationID
	Insert(record Participation) (ParticipationID, error)

	// Delete removes a record from storage.
	Delete(id ParticipationID) error

	// Get a participation record.
	Get(id ParticipationID) (ParticipationRecord, error)

	// GetAll of the participation records.
	GetAll() ([]ParticipationRecord, error)

	// Register updates the EffectiveFirst and EffectiveLast fields. If there are multiple records for the account
	// then it is possible for multiple records to be updated.
	Register(id ParticipationID, on basics.Round) error

	// Record sets the Last* field for the active ParticipationID for the given account.
	Record(account basics.Address, round basics.Round, participationType ParticipationAction) error
}

// MakeParticipationRegistry creates a db.Accessor backed ParticipationRegistry.
func MakeParticipationRegistry(accessor db.Accessor) (ParticipationRegistry, error) {
	migrations := []db.Migration{
		dbSchemaUpgrade0,
	}

	err := db.Initialize(accessor, migrations)
	if err != nil {
		return nil, err
	}

	return &participationDB{
		store: accessor,
	}, nil
}

// Queries
var (
	createKeysets = `CREATE TABLE Keysets (
			pk INTEGER PRIMARY KEY,

			participationID BLOB,
			account BLOB,

			firstValidRound INTEGER NOT NULL DEFAULT 0,
			lastValidRound INTEGER  NOT NULL DEFAULT 0,
			keyDilution INTEGER     NOT NULL DEFAULT 0

			-- vrf BLOB,    --*  msgpack encoding of ParticipationAccount.vrf
		)`
	createRolling = `CREATE TABLE Rolling (
			pk INTEGER PRIMARY KEY,

			lastVoteRound INTEGER               NOT NULL DEFAULT 0,
			lastBlockProposalRound INTEGER      NOT NULL DEFAULT 0,
			lastCompactCertificateRound INTEGER NOT NULL DEFAULT 0,
			effectiveFirstValidRound INTEGER    NOT NULL DEFAULT 0,
			effectiveLastValidRound INTEGER     NOT NULL DEFAULT 0

			-- voting BLOB, --*  msgpack encoding of ParticipationAccount.voting
		)`
	insertKeysetQuery  = `INSERT INTO Keysets (participationID, account, firstValidRound, lastValidRound, keyDilution) VALUES (?, ?, ?, ?, ?)`
	insertRollingQuery = `INSERT INTO Rolling (pk) VALUES (?)`

	// SELECT pk FROM Keysets WHERE participationID = ?
	selectPK      = `SELECT pk FROM Keysets WHERE participationID = ? LIMIT 1`
	selectLastPK  = `SELECT pk FROM Keysets ORDER BY pk DESC LIMIT 1`
	selectRecords = `SELECT 
			participationID, account, firstValidRound, lastValidRound, keyDilution,
			lastVoteRound, lastBlockProposalRound, lastCompactCertificateRound,
			effectiveFirstValidRound, effectiveLastValidRound
		FROM Keysets, Rolling
		WHERE Keysets.pk = Rolling.pk`
	selectRecord  = selectRecords + ` AND participationID = ?`
	deleteKeysets = `DELETE FROM Keysets WHERE pk=?`
	deleteRolling = `DELETE FROM Rolling WHERE pk=?`
	// there should be, at most, a single record within the effective range.
	// only the effectiveLastValid can change here.
	clearRegistered = `UPDATE Rolling
		 SET effectiveLastValidRound = ?1
		 WHERE pk IN (SELECT pk FROM Keysets WHERE account = ?2)
		 AND effectiveFirstValidRound < ?1
		 AND effectiveLastValidRound > ?1`
	setRegistered = `UPDATE Rolling
		 SET effectiveFirstValidRound=?,
		     effectiveLastValidRound=?
		 WHERE pk = (SELECT pk FROM Keysets WHERE participationID = ?)`
	// there should only be a single record within the effective range.
	updateRollingFieldX = `UPDATE Rolling
		 SET %s=?1
		 WHERE effectiveFirstValidRound < ?1
		 AND effectiveLastValidRound > ?1
		 AND pk IN (SELECT pk FROM Keysets WHERE account=?2)`
)

// dbSchemaUpgrade0 initialize the tables.
func dbSchemaUpgrade0(ctx context.Context, tx *sql.Tx, newDatabase bool) error {
	// Keysets is for the immutable data.
	_, err := tx.Exec(createKeysets)
	if err != nil {
		return err
	}

	// Rolling may change over time.
	_, err = tx.Exec(createRolling)
	if err != nil {
		return err
	}

	return nil
}

// participationDB is a private implementation of ParticipationRegistry.
type participationDB struct {
	store db.Accessor
}

func (db *participationDB) Insert(record Participation) (id ParticipationID, err error) {
	id = record.ParticipationID()
	err = db.store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec(
			insertKeysetQuery,
			id[:],
			record.Parent[:],
			record.FirstValid,
			record.LastValid,
			record.KeyDilution)
		if err != nil {
			return fmt.Errorf("unable to insert keyset: %w", err)
		}

		// Fetch primary key
		var pk int
		row := tx.QueryRow(selectLastPK, id[:])
		err = row.Scan(&pk)
		if err != nil {
			return fmt.Errorf("unable to scan pk: %w", err)
		}

		// Create Rolling entry
		_, err = tx.Exec(insertRollingQuery, pk)
		if err != nil {
			return fmt.Errorf("unable insert rolling: %w", err)
		}

		return nil
	})
	return
}

func (db *participationDB) Delete(id ParticipationID) error {
	return db.store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// Fetch primary key
		var pk int
		row := tx.QueryRow(selectPK, id[:])
		err := row.Scan(&pk)
		if err != nil {
			return fmt.Errorf("unable to scan pk: %w", err)
		}

		// Delete rows

		_, err = tx.Exec(deleteKeysets, pk)
		if err != nil {
			return err
		}

		_, err = tx.Exec(deleteRolling, pk)
		if err != nil {
			return err
		}

		return nil
	})
}

func scanRecords(rows *sql.Rows) ([]ParticipationRecord, error) {
	results := make([]ParticipationRecord, 0)
	for rows.Next() {
		var record ParticipationRecord
		var participationBlob []byte
		var accountBlob []byte
		err := rows.Scan(
			&participationBlob,
			&accountBlob,
			&record.FirstValid,
			&record.LastValid,
			&record.KeyDilution,
			&record.LastVote,
			&record.LastBlockProposal,
			&record.LastCompactCertificate,
			&record.EffectiveFirst,
			&record.EffectiveLast,
		)
		if err != nil {
			return nil, err
		}

		copy(record.ParticipationID[:], participationBlob)
		copy(record.Account[:], accountBlob)

		results = append(results, record)
	}

	return results, nil
}

func (db *participationDB) Get(id ParticipationID) (record ParticipationRecord, err error) {
	err = db.store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.Query(selectRecord, id[:])
		if err != nil {
			return fmt.Errorf("unable to scan record: %w", err)
		}

		records, err := scanRecords(rows)
		if err != nil {
			return fmt.Errorf("unable to scan record: %w", err)
		}

		if len(records) != 1 {
			return fmt.Errorf("expected 1 result found %d", len(records))
		}

		record = records[0]

		return nil
	})

	return
}

func (db *participationDB) GetAll() (records []ParticipationRecord, err error) {
	err = db.store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.Query(selectRecords)
		if err != nil {
			return fmt.Errorf("unable to query records: %w", err)
		}

		records, err = scanRecords(rows)
		if err != nil {
			records = nil
			return fmt.Errorf("problem scanning records: %w", err)
		}

		return nil
	})

	return
}

func (db *participationDB) Register(id ParticipationID, on basics.Round) error {
	// Lookup record for first/last valid and account.
	record, err := db.Get(id)
	if err != nil {
		return fmt.Errorf("unable to lookup id: %w", err)
	}

	// round out of valid range.
	if on+maxBalLookback > record.LastValid || on+maxBalLookback < record.FirstValid {
		return ErrInvalidRegisterRange
	}

	return db.store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// if the is an active key, shut it down.
		_, err = tx.Exec(clearRegistered, on+maxBalLookback, record.Account[:])
		if err != nil {
			return fmt.Errorf("unable to clear registered key: %w", err)
		}

		// update id
		_, err = tx.Exec(setRegistered, on+maxBalLookback, record.LastValid, id[:])
		if err != nil {
			return fmt.Errorf("unable to update registered key: %w", err)
		}

		return nil
	})
}

func (db *participationDB) Record(account basics.Address, round basics.Round, participationAction ParticipationAction) error {
	var field string
	switch participationAction {
	case Vote:
		field = "lastVoteRound"
	case BlockProposal:
		field = "lastBlockProposalRound"
	case CompactCertificate:
		field = "lastCompactCertificateRound"
	default:
		return fmt.Errorf("unknown participation action: %d", participationAction)
	}

	query := fmt.Sprintf(updateRollingFieldX, field)

	return db.store.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		r, err := tx.Exec(query, round, account[:])
		if err != nil {
			return err
		}

		// If multiple rows were changed there is probably a problem with Register.
		rowsEffected, err := r.RowsAffected()
		if err != nil {
			return err
		} else if rowsEffected > 1 {
			return fmt.Errorf("too many rows effected: %d", rowsEffected)
		}

		return nil
	})
}
