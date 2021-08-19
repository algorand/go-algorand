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
	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/util/db"
)

// ParticipationID identifies a particular set of participation keys.
//msgp:ignore ParticipationID
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
	RegisteredFirst        basics.Round
	RegisteredLast         basics.Round

	// VRFSecrets
	// OneTimeSignatureSecrets
}

// ParticipationAction is used when recording participation actions.
//msgp:ignore ParticipationAction
type ParticipationAction int

// ParticipationAction types
const (
	Vote ParticipationAction = iota
	BlockProposal
	CompactCertificate
)

var participationActionFields = map[ParticipationAction]string{
	Vote:               "lastVoteRound",
	BlockProposal:      "lastBlockProposalRound",
	CompactCertificate: "lastCompactCertificateRound",
}

// ErrParticipationIDNotFound is used when attempting to update a set of keys which do not exist.
var ErrParticipationIDNotFound = errors.New("the participation ID was not found")

// ErrInvalidRegisterRange is used when attempting to register a participation key on a round that is out of range.
var ErrInvalidRegisterRange = errors.New("key would not be active within range")

// ErrUnknownParticipationAction is used when record is given something other than the known actions.
var ErrUnknownParticipationAction = errors.New("unknown participation action")

// ErrAlreadyInserted is used when inserting a key which already exists in the registery.
var ErrAlreadyInserted = errors.New("these participation keys are already inserted")

// ErrActiveKeyNotFound is used when attempting to update an account with no active key
var ErrActiveKeyNotFound = errors.New("no active participation key found for account")

// ErrMultipleValidKeys is used when recording a result but multiple valid keys were found. This should not be possible.
var ErrMultipleValidKeys = errors.New("multiple valid keys found while recording key usage")

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

	// Flush ensures that all changes have been written to the underlying data store.
	Flush() error

	// Close any resources used to implement the interface.
	Close()
}

// MakeParticipationRegistry creates a db.Accessor backed ParticipationRegistry.
func MakeParticipationRegistry(accessor db.Pair) (ParticipationRegistry, error) {
	migrations := []db.Migration{
		dbSchemaUpgrade0,
	}

	err := db.Initialize(accessor.Wdb, migrations)
	if err != nil {
		accessor.Close()
		return nil, fmt.Errorf("unable to initialize participation registry database: %w", err)
	}

	registry := &participationDB{
		store: accessor,
	}

	err = registry.initializeCache()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize participation registry cache: %w", err)
	}

	return registry, nil
}

// Queries
var (
	createKeysets = `CREATE TABLE Keysets (
			pk INTEGER PRIMARY KEY NOT NULL,

			participationID BLOB,
			account BLOB,

			firstValidRound INTEGER NOT NULL DEFAULT 0,
			lastValidRound  INTEGER NOT NULL DEFAULT 0,
			keyDilution     INTEGER NOT NULL DEFAULT 0

			-- vrf BLOB,    --*  msgpack encoding of ParticipationAccount.vrf
		)`
	createRolling = `CREATE TABLE Rolling (
			pk INTEGER PRIMARY KEY NOT NULL,

			lastVoteRound               INTEGER NOT NULL DEFAULT 0,
			lastBlockProposalRound      INTEGER NOT NULL DEFAULT 0,
			lastCompactCertificateRound INTEGER NOT NULL DEFAULT 0,
			registeredFirstRound        INTEGER NOT NULL DEFAULT 0,
			registeredLastRound         INTEGER NOT NULL DEFAULT 0

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
			registeredFirstRound, registeredLastRound
		FROM Keysets
		INNER JOIN Rolling
		ON Keysets.pk = Rolling.pk`
	selectRecord  = selectRecords + ` AND participationID = ?`
	deleteKeysets = `DELETE FROM Keysets WHERE pk=?`
	deleteRolling = `DELETE FROM Rolling WHERE pk=?`
	setRegistered = `UPDATE Rolling
		 SET registeredFirstRound=?,
		     registeredLastRound=?
		 WHERE pk = (SELECT pk FROM Keysets WHERE participationID = ?)`
	updateRollingFields = `UPDATE Rolling
		 SET lastVoteRound=?,
		     lastBlockProposalRound=?,
		     lastCompactCertificateRound=?,
		     registeredFirstRound=?,
		     registeredLastRound=?
		 WHERE pk=(SELECT pk FROM Keysets WHERE participationID=?)`
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
	cache map[ParticipationID]ParticipationRecord
	dirty map[ParticipationID]struct{}

	store db.Pair
	mutex deadlock.RWMutex
}

func (db *participationDB) initializeCache() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	db.cache = make(map[ParticipationID]ParticipationRecord)
	db.dirty = make(map[ParticipationID]struct{})

	records, err := db.getAllFromDB()
	if err != nil {
		return err
	}

	for _, record := range records {
		db.cache[record.ParticipationID] = record
	}

	return nil
}

func (db *participationDB) Insert(record Participation) (id ParticipationID, err error) {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	id = record.ParticipationID()
	if _, ok := db.cache[id]; ok {
		return ParticipationID{}, ErrAlreadyInserted
	}

	err = db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
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

	// update cache.
	// TODO: simplify to re-initializing with initializeCache()?
	if err == nil {
		db.cache[id] = ParticipationRecord{
			ParticipationID:        id,
			Account:                record.Address(),
			FirstValid:             record.FirstValid,
			LastValid:              record.LastValid,
			KeyDilution:            record.KeyDilution,
			LastVote:               0,
			LastBlockProposal:      0,
			LastCompactCertificate: 0,
			RegisteredFirst:        0,
			RegisteredLast:         0,
		}
	}

	return
}

func (db *participationDB) Delete(id ParticipationID) error {
	err := db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
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

	if err == nil {
		db.mutex.Lock()
		defer db.mutex.Unlock()

		delete(db.dirty, id)
		delete(db.cache, id)
	}

	return err
}

// scanRecords is a helper to manage scanning participation records.
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
			&record.RegisteredFirst,
			&record.RegisteredLast,
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

func (db *participationDB) get(id ParticipationID) (record ParticipationRecord, err error) {
	err = db.store.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
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

func (db *participationDB) getAllFromDB() (records []ParticipationRecord, err error) {
	err = db.store.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
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

func (db *participationDB) Get(id ParticipationID) (record ParticipationRecord, err error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	record, ok := db.cache[id]
	if !ok {
		return ParticipationRecord{}, ErrParticipationIDNotFound
	}
	return record, nil
}

func (db *participationDB) GetAll() ([]ParticipationRecord, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	results := make([]ParticipationRecord, 0, len(db.cache))
	for _, record := range db.cache {
		results = append(results, record)
	}
	return results, nil
}

// updateRollingFields sets all of the rolling fields according to the record object.
func (db *participationDB) updateRollingFields(ctx context.Context, tx *sql.Tx, record ParticipationRecord) error {
	_, err := tx.ExecContext(ctx, updateRollingFields,
		record.LastVote,
		record.LastBlockProposal,
		record.LastCompactCertificate,
		record.RegisteredFirst,
		record.RegisteredLast,
		record.ParticipationID[:])
	return err
}

func (db *participationDB) Register(id ParticipationID, on basics.Round) error {
	// Lookup recordToRegister for first/last valid and account.
	recordToRegister, err := db.Get(id)
	if err != nil {
		return err
	}

	// round out of valid range.
	if on > recordToRegister.LastValid || on < recordToRegister.FirstValid {
		return ErrInvalidRegisterRange
	}

	updated := make(map[ParticipationID]ParticipationRecord, 0)
	err = db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// Disable active key
		for _, record := range db.cache {
			if record.RegisteredFirst <= on && on <= record.RegisteredLast {
				// TODO: this should probably be "on - 1"
				record.RegisteredLast = on
				err := db.updateRollingFields(ctx, tx, record)
				if err != nil {
					return fmt.Errorf("unable to disable old key when registering %s", id)
				}

				copy := record
				updated[record.ParticipationID] = copy
			}
		}

		// Mark registered.
		recordToRegister.RegisteredFirst = on
		recordToRegister.RegisteredLast = recordToRegister.LastValid

		err := db.updateRollingFields(ctx, tx, recordToRegister)
		if err != nil {
			return fmt.Errorf("unable to registering key with id: %s", id)
		}
		updated[recordToRegister.ParticipationID] = recordToRegister

		return nil
	})

	// Update cache
	if err == nil {
		db.mutex.Lock()
		defer db.mutex.Unlock()

		for id, record := range updated {
			delete(db.dirty, id)
			db.cache[id] = record
		}
	}

	return err
}

func (db *participationDB) Record(account basics.Address, round basics.Round, participationAction ParticipationAction) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	matches := make([]ParticipationID, 0)
	// At most one id should be updated.
	for _, record := range db.cache {
		if record.Account == account && record.FirstValid <= round && round <= record.LastValid {
			matches = append(matches, record.ParticipationID)
		}
	}

	// Good case, one key found.
	if len(matches) == 1 {
		record := db.cache[matches[0]]

		switch participationAction {
		case Vote:
			record.LastVote = round
		case BlockProposal:
			record.LastBlockProposal = round
		case CompactCertificate:
			record.LastCompactCertificate = round
		default:
			return ErrUnknownParticipationAction
		}

		db.dirty[record.ParticipationID] = struct{}{}
		copy := record
		db.cache[record.ParticipationID] = copy
		return nil
	}

	// This probably means there is a bug in the key participation registry Register implementation.
	if len(matches) > 1 {
		return ErrMultipleValidKeys
	}

	// This indicates the participation registry is not synchronized with agreement.
	return ErrActiveKeyNotFound
}

func (db *participationDB) Flush() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if len(db.dirty) == 0 {
		return nil
	}

	return db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		for id := range db.dirty {
			record, ok := db.cache[id]
			if !ok {
				return ErrParticipationIDNotFound
			}
			err := db.updateRollingFields(ctx, tx, record)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (db *participationDB) Close() {
	db.Flush()
	db.store.Close()
}
