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
	"strings"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
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
	EffectiveFirst         basics.Round
	EffectiveLast          basics.Round

	// VRFSecrets
	// OneTimeSignatureSecrets
}

var zeroParticipationRecord = ParticipationRecord{}

// IsZero returns true if the object contains zero values.
func (r ParticipationRecord) IsZero() bool {
	return r == zeroParticipationRecord
}

// Duplicate creates a copy of the current object. This is required once secrets are stored.
func (r ParticipationRecord) Duplicate() ParticipationRecord {
	return ParticipationRecord{
		ParticipationID:        r.ParticipationID,
		Account:                r.Account,
		FirstValid:             r.FirstValid,
		LastValid:              r.LastValid,
		KeyDilution:            r.KeyDilution,
		LastVote:               r.LastVote,
		LastBlockProposal:      r.LastBlockProposal,
		LastCompactCertificate: r.LastCompactCertificate,
		EffectiveFirst:         r.EffectiveFirst,
		EffectiveLast:          r.EffectiveLast,
	}
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

// ErrAlreadyInserted is used when inserting a key which already exists in the registry.
var ErrAlreadyInserted = errors.New("these participation keys are already inserted")

// ErrActiveKeyNotFound is used when attempting to update an account with no active key
var ErrActiveKeyNotFound = errors.New("no active participation key found for account")

// ErrMultipleValidKeys is used when recording a result but multiple valid keys were found. This should not be possible.
var ErrMultipleValidKeys = errors.New("multiple valid keys found while recording key usage")

// ErrMultipleKeysForID this should never happen. Multiple keys with the same participationID
var ErrMultipleKeysForID = errors.New("multiple valid keys found for the same participationID")

// ErrNoKeyForID there may be cases where a key is deleted and used at the same time, so this error should be handled.
var ErrNoKeyForID = errors.New("no valid key found for the participationID")

// ParticipationRegistry contain all functions for interacting with the Participation Registry.
type ParticipationRegistry interface {
	// Insert adds a record to storage and computes the ParticipationID
	Insert(record Participation) (ParticipationID, error)

	// Delete removes a record from storage.
	Delete(id ParticipationID) error

	// Get a participation record.
	Get(id ParticipationID) ParticipationRecord

	// GetAll of the participation records.
	GetAll() []ParticipationRecord

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
func MakeParticipationRegistry(accessor db.Pair, log logging.Logger) (ParticipationRegistry, error) {
	return makeParticipationRegistry(accessor, log)
}

// makeParticipationRegistry creates a db.Accessor backed ParticipationRegistry.
func makeParticipationRegistry(accessor db.Pair, log logging.Logger) (*participationDB, error) {
	if log == nil {
		return nil, fmt.Errorf("invalid logger provided")
	}

	migrations := []db.Migration{
		dbSchemaUpgrade0,
	}

	err := db.Initialize(accessor.Wdb, migrations)
	if err != nil {
		accessor.Close()
		return nil, fmt.Errorf("unable to initialize participation registry database: %w", err)
	}

	registry := &participationDB{
		log:   log,
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
			effectiveFirstRound        INTEGER NOT NULL DEFAULT 0,
			effectiveLastRound         INTEGER NOT NULL DEFAULT 0

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
			effectiveFirstRound, effectiveLastRound
		FROM Keysets
		INNER JOIN Rolling
		ON Keysets.pk = Rolling.pk`
	deleteKeysets       = `DELETE FROM Keysets WHERE pk=?`
	deleteRolling       = `DELETE FROM Rolling WHERE pk=?`
	updateRollingFields = `UPDATE Rolling
		 SET lastVoteRound=?,
		     lastBlockProposalRound=?,
		     lastCompactCertificateRound=?,
		     effectiveFirstRound=?,
		     effectiveLastRound=?
		 WHERE pk IN (SELECT pk FROM Keysets WHERE participationID=?)`
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

	log   logging.Logger
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
		// Check if it already exists
		if _, ok := db.cache[record.ParticipationID]; ok {
			return ErrMultipleKeysForID
		}
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
		result, err := tx.Exec(
			insertKeysetQuery,
			id[:],
			record.Parent[:],
			record.FirstValid,
			record.LastValid,
			record.KeyDilution)
		if err != nil {
			return fmt.Errorf("unable to insert keyset: %w", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("unable to insert keyset: %w", err)
		}
		if rows != 1 {
			return fmt.Errorf("unexpected number of rows")
		}
		pk, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("unable to insert keyset: %w", err)
		}

		// Create Rolling entry
		result, err = tx.Exec(insertRollingQuery, pk)
		if err != nil {
			return fmt.Errorf("unable insert rolling: %w", err)
		}
		rows, err = result.RowsAffected()
		if err != nil {
			return fmt.Errorf("unable to insert keyset: %w", err)
		}
		if rows != 1 {
			return fmt.Errorf("unexpected number of rows")
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
			EffectiveFirst:         0,
			EffectiveLast:          0,
		}
	}

	return
}

func (db *participationDB) Delete(id ParticipationID) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// NoOp if key does not exist.
	if _, ok := db.cache[id]; !ok {
		return nil
	}

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

func (db *participationDB) Get(id ParticipationID) ParticipationRecord {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	record, ok := db.cache[id]
	if !ok {
		return ParticipationRecord{}
	}
	return record.Duplicate()
}

func (db *participationDB) GetAll() []ParticipationRecord {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	results := make([]ParticipationRecord, 0, len(db.cache))
	for _, record := range db.cache {
		results = append(results, record.Duplicate())
	}
	return results
}

// updateRollingFields sets all of the rolling fields according to the record object.
func (db *participationDB) updateRollingFields(ctx context.Context, tx *sql.Tx, record ParticipationRecord) error {
	result, err := tx.ExecContext(ctx, updateRollingFields,
		record.LastVote,
		record.LastBlockProposal,
		record.LastCompactCertificate,
		record.EffectiveFirst,
		record.EffectiveLast,
		record.ParticipationID[:])
	if err != nil {
		return err
	}

	numRows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if numRows > 1 {
		return ErrMultipleKeysForID
	}

	if numRows < 1 {
		return ErrNoKeyForID
	}

	return nil
}

func recordActive(record ParticipationRecord, on basics.Round) bool {
	return record.EffectiveLast != 0 && record.EffectiveFirst <= on && on <= record.EffectiveLast
}

func (db *participationDB) Register(id ParticipationID, on basics.Round) error {
	// Lookup recordToRegister for first/last valid and account.
	recordToRegister := db.Get(id)
	if recordToRegister.IsZero() {
		return ErrParticipationIDNotFound
	}

	// No-op If the record is already active
	if recordActive(recordToRegister, on) {
		return nil
	}

	// round out of valid range.
	if on < recordToRegister.FirstValid || on > recordToRegister.LastValid {
		return ErrInvalidRegisterRange
	}

	updated := make(map[ParticipationID]ParticipationRecord)
	err := db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// Disable active key if there is one
		for _, record := range db.cache {
			if record.Account == recordToRegister.Account && record.ParticipationID != id && recordActive(record, on) {
				// TODO: this should probably be "on - 1"
				record.EffectiveLast = on
				err := db.updateRollingFields(ctx, tx, record)
				// Repair the case when no keys were updated
				if err == ErrNoKeyForID {
					db.log.Warn("participationDB unable to update key in cache. Removing from cache.")
					delete(db.cache, id)
				}
				if err != nil {
					return fmt.Errorf("unable to disable old key when registering %s", id)
				}

				updated[record.ParticipationID] = record.Duplicate()
			}
		}

		// Mark registered.
		recordToRegister.EffectiveFirst = on
		recordToRegister.EffectiveLast = recordToRegister.LastValid

		err := db.updateRollingFields(ctx, tx, recordToRegister)
		if err == ErrNoKeyForID {
			db.log.Warn("participationDB unable to update key in cache. Removing from cache.")
			delete(db.cache, id)
		}
		if err != nil {
			return fmt.Errorf("unable to registering key with id (%s): %w", id, err)
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

	matches := make([]ParticipationRecord, 0, 1)

	// At most one id should be updated, exit with error if a second is found.
	for _, record := range db.cache {
		if record.Account == account && recordActive(record, round) {
			if len(matches) != 0 {
				// This probably means there is a bug in the key participation registry Register implementation.
				return ErrMultipleValidKeys
			}
			matches = append(matches, record)
		}
	}

	if len(matches) == 0 {
		// This indicates the participation registry is not synchronized with agreement.
		return ErrActiveKeyNotFound
	}

	record := matches[0]
	// Good case, one key found.
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
	db.cache[record.ParticipationID] = record
	return nil
}

func (db *participationDB) Flush() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// Verify that the dirty flag has not desynchronized from the cache.
	for id := range db.dirty {
		if _, ok := db.cache[id]; !ok {
			db.log.Warnf("participationDB fixing dirty flag de-synchronization for %s", id)
			delete(db.cache, id)
		}
	}

	if len(db.dirty) == 0 {
		return nil
	}

	err := db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var errorStr strings.Builder
		for id := range db.dirty {
			err := db.updateRollingFields(ctx, tx, db.cache[id])
			// This should only be updating key usage so ignoring missing keys is not a problem.
			if err != nil && err != ErrNoKeyForID {
				if errorStr.Len() > 0 {
					errorStr.WriteString(", ")
				}
				errorStr.WriteString(err.Error())
			}
		}
		if errorStr.Len() > 0 {
			return errors.New(errorStr.String())
		}
		return nil
	})

	if err != nil {
		return err
	}

	db.dirty = make(map[ParticipationID]struct{})
	return nil
}

func (db *participationDB) Close() {
	if err := db.Flush(); err != nil {
		db.log.Warnf("participationDB unhandled error during Close/Flush: %w", err)
	}

	db.store.Close()
}
