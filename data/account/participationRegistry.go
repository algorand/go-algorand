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
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

const defaultTimeout = 5 * time.Second

// ParticipationID identifies a particular set of participation keys.
//msgp:ignore ParticipationID
type ParticipationID crypto.Digest

// IsZero returns true if the ParticipationID is all zero bytes.
func (pid ParticipationID) IsZero() bool {
	return (crypto.Digest(pid)).IsZero()
}

// String prints a b32 version of this ID.
func (pid ParticipationID) String() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(pid[:])
}

// ParseParticipationID takes a string and returns a ParticipationID object
func ParseParticipationID(str string) (d ParticipationID, err error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(str)
	if err != nil {
		return d, err
	}
	if len(decoded) != len(d) {
		return d, fmt.Errorf(`attempted to decode a string which was not a participation id: "%s"`, str)
	}
	copy(d[:], decoded[:])
	return d, err
}

// ParticipationRecord contains all metadata relating to a set of participation keys.
type ParticipationRecord struct {
	ParticipationID ParticipationID

	Account     basics.Address
	FirstValid  basics.Round
	LastValid   basics.Round
	KeyDilution uint64

	LastVote          basics.Round
	LastBlockProposal basics.Round
	LastStateProof    basics.Round
	EffectiveFirst    basics.Round
	EffectiveLast     basics.Round

	VRF    *crypto.VRFSecrets
	Voting *crypto.OneTimeSignatureSecrets
}

// StateProofKey is a placeholder for the real state proof key type.
// PKI TODO: Replace this with a real object.
type StateProofKey []byte

// ParticipationRecordForRound adds in the per-round state proof key.
type ParticipationRecordForRound struct {
	ParticipationRecord

	StateProof StateProofKey
}

// IsZero returns true if the object contains zero values.
func (r ParticipationRecordForRound) IsZero() bool {
	return r.StateProof == nil && r.ParticipationRecord.IsZero()
}

var zeroParticipationRecord = ParticipationRecord{}

// IsZero returns true if the object contains zero values.
func (r ParticipationRecord) IsZero() bool {
	return r == zeroParticipationRecord
}

// Duplicate creates a copy of the current object. This is required once secrets are stored.
func (r ParticipationRecord) Duplicate() ParticipationRecord {
	var vrf crypto.VRFSecrets
	if r.VRF != nil {
		copy(vrf.SK[:], r.VRF.SK[:])
		copy(vrf.PK[:], r.VRF.PK[:])
	}

	var voting crypto.OneTimeSignatureSecrets
	if r.Voting != nil {
		voting = r.Voting.Snapshot()
	}
	return ParticipationRecord{
		ParticipationID:   r.ParticipationID,
		Account:           r.Account,
		FirstValid:        r.FirstValid,
		LastValid:         r.LastValid,
		KeyDilution:       r.KeyDilution,
		LastVote:          r.LastVote,
		LastBlockProposal: r.LastBlockProposal,
		LastStateProof:    r.LastStateProof,
		EffectiveFirst:    r.EffectiveFirst,
		EffectiveLast:     r.EffectiveLast,
		VRF:               &vrf,
		Voting:            &voting,
	}
}

// ParticipationAction is used when recording participation actions.
//msgp:ignore ParticipationAction
type ParticipationAction int

// ParticipationAction types
const (
	Vote ParticipationAction = iota
	BlockProposal
	StateProof
)

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

// ErrSecretNotFound is used when attempting to lookup secrets for a particular round.
var ErrSecretNotFound = errors.New("the participation ID did not have secrets for the requested round")

// ParticipationRegistry contain all functions for interacting with the Participation Registry.
type ParticipationRegistry interface {
	// Insert adds a record to storage and computes the ParticipationID
	Insert(record Participation) (ParticipationID, error)

	// AppendKeys appends state proof keys to an existing Participation record. Keys can only be appended
	// once, an error will occur when the data is flushed when inserting a duplicate key.
	AppendKeys(id ParticipationID, keys map[uint64]StateProofKey) error

	// Delete removes a record from storage.
	Delete(id ParticipationID) error

	// DeleteExpired removes all records from storage which are expired on the given round.
	DeleteExpired(round basics.Round) error

	// Get a participation record.
	Get(id ParticipationID) ParticipationRecord

	// GetAll of the participation records.
	GetAll() []ParticipationRecord

	// GetForRound fetches a record with all secrets for a particular round.
	GetForRound(id ParticipationID, round basics.Round) (ParticipationRecordForRound, error)

	// Register updates the EffectiveFirst and EffectiveLast fields. If there are multiple records for the account
	// then it is possible for multiple records to be updated.
	Register(id ParticipationID, on basics.Round) error

	// Record sets the Last* field for the active ParticipationID for the given account.
	Record(account basics.Address, round basics.Round, participationType ParticipationAction) error

	// Flush ensures that all changes have been written to the underlying data store.
	Flush(timeout time.Duration) error

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
		return nil, errors.New("invalid logger provided")
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
		log:            log,
		store:          accessor,
		writeQueue:     make(chan partDBWriteRecord, 10),
		writeQueueDone: make(chan struct{}),
		flushTimeout:   defaultTimeout,
	}
	go registry.writeThread()

	err = registry.initializeCache()
	if err != nil {
		registry.Close()
		return nil, fmt.Errorf("unable to initialize participation registry cache: %w", err)
	}

	return registry, nil
}

// Queries
const (
	createKeysets = `CREATE TABLE Keysets (
			pk INTEGER PRIMARY KEY NOT NULL,

			participationID BLOB NOT NULL,
			account         BLOB NOT NULL,

			firstValidRound INTEGER NOT NULL,
			lastValidRound  INTEGER NOT NULL,
			keyDilution     INTEGER NOT NULL,

			vrf BLOB,       --*  msgpack encoding of ParticipationAccount.vrf
			stateProof BLOB --*  msgpack encoding of ParticipationAccount.BlockProof
		)`

	createRolling = `CREATE TABLE Rolling (
			pk INTEGER PRIMARY KEY NOT NULL,

			lastVoteRound               INTEGER,
			lastBlockProposalRound      INTEGER,
			lastStateProofRound         INTEGER,
			effectiveFirstRound         INTEGER,
			effectiveLastRound          INTEGER,

			voting BLOB --*  msgpack encoding of ParticipationAccount.voting
		)`

	createStateProof = `CREATE TABLE StateProofKeys (
			pk    INTEGER NOT NULL, --* join with keyset to find key for a particular participation id
			round INTEGER NOT NULL, --*  committed round for this key
			key   BLOB    NOT NULL, --*  msgpack encoding of ParticipationAccount.BlockProof.SignatureAlgorithm
			PRIMARY KEY (pk, round)
		)`
	insertKeysetQuery         = `INSERT INTO Keysets (participationID, account, firstValidRound, lastValidRound, keyDilution, vrf, stateProof) VALUES (?, ?, ?, ?, ?, ?, ?)`
	insertRollingQuery        = `INSERT INTO Rolling (pk, voting) VALUES (?, ?)`
	appendStateProofKeysQuery = `INSERT INTO StateProofKeys (pk, round, key) VALUES(?, ?, ?)`

	// SELECT pk FROM Keysets WHERE participationID = ?
	selectPK      = `SELECT pk FROM Keysets WHERE participationID = ? LIMIT 1`
	selectLastPK  = `SELECT pk FROM Keysets ORDER BY pk DESC LIMIT 1`
	selectRecords = `SELECT
			k.participationID, k.account, k.firstValidRound,
       		k.lastValidRound, k.keyDilution, k.vrf,
			r.lastVoteRound, r.lastBlockProposalRound, r.lastStateProofRound,
			r.effectiveFirstRound, r.effectiveLastRound, r.voting
		FROM Keysets k
		INNER JOIN Rolling r
		ON k.pk = r.pk`
	selectStateProofKeys = `SELECT s.key
		FROM StateProofKeys s
		WHERE round=?
		   AND pk IN (SELECT pk FROM Keysets WHERE participationID=?)`
	deleteKeysets          = `DELETE FROM Keysets WHERE pk=?`
	deleteRolling          = `DELETE FROM Rolling WHERE pk=?`
	updateRollingFieldsSQL = `UPDATE Rolling
		 SET lastVoteRound=?,
		     lastBlockProposalRound=?,
		     lastStateProofRound=?,
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

	// For performance reasons, state proofs are in a separate table.
	_, err = tx.Exec(createStateProof)
	if err != nil {
		return err
	}

	return nil
}

// participationDB provides a concrete implementation of the ParticipationRegistry interface.
type participationDB struct {
	cache map[ParticipationID]ParticipationRecord

	// dirty marked on Record(), cleared on Register(), Delete(), Flush()
	dirty map[ParticipationID]struct{}

	log   logging.Logger
	store db.Pair
	mutex deadlock.RWMutex

	writeQueue     chan partDBWriteRecord
	writeQueueDone chan struct{}

	flushTimeout time.Duration
}

type updatingParticipationRecord struct {
	ParticipationRecord

	required bool
}

// partDBWriteRecord event object sent to the writeThread to facilitate async
// database writes. Only one set of event fields should be set at a time.
type partDBWriteRecord struct {
	insertID ParticipationID
	insert   Participation
	keys     map[uint64]StateProofKey

	registerUpdated map[ParticipationID]updatingParticipationRecord

	delete ParticipationID

	flushResultChannel chan error
}

func (db *participationDB) initializeCache() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	records, err := db.getAllFromDB()
	if err != nil {
		return err
	}

	cache := make(map[ParticipationID]ParticipationRecord)
	for _, record := range records {
		// Check if it already exists
		if _, ok := cache[record.ParticipationID]; ok {
			return ErrMultipleKeysForID
		}
		cache[record.ParticipationID] = record
	}

	db.cache = cache
	db.dirty = make(map[ParticipationID]struct{})
	return nil
}

func (db *participationDB) writeThread() {
	defer close(db.writeQueueDone)
	var err error
	var lastErr error
	for {
		var wr partDBWriteRecord
		var chanOk bool

		// blocking read until next activity or close
		wr, chanOk = <-db.writeQueue
		if !chanOk {
			return // chan closed
		}

		if len(wr.registerUpdated) != 0 {
			err = db.registerInner(wr.registerUpdated)
		} else if !wr.insertID.IsZero() {
			if wr.insert != (Participation{}) {
				err = db.insertInner(wr.insert, wr.insertID)
			} else if len(wr.keys) != 0 {
				err = db.appendKeysInner(wr.insertID, wr.keys)
			}
		} else if !wr.delete.IsZero() {
			err = db.deleteInner(wr.delete)
		} else if wr.flushResultChannel != nil {
			err = db.flushInner()
		}
		if err != nil {
			lastErr = err
		}

		if wr.flushResultChannel != nil {
			wr.flushResultChannel <- lastErr
			lastErr = nil
		}
	}
}

// verifyExecWithOneRowEffected checks for a successful Exec and also verifies exactly 1 row was affected
func verifyExecWithOneRowEffected(err error, result sql.Result, operationName string) error {
	if err != nil {
		return fmt.Errorf("unable to execute %s: %w", operationName, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("unable to get %s rows affected: %w", operationName, err)
	}
	if rows != 1 {
		return fmt.Errorf("unexpected number of %s rows affected, expected 1 found %d", operationName, rows)
	}
	return nil
}

func (db *participationDB) insertInner(record Participation, id ParticipationID) (err error) {
	var rawVRF []byte
	var rawVoting []byte
	var rawStateProof []byte

	if record.VRF != nil {
		rawVRF = protocol.Encode(record.VRF)
	}
	if record.Voting != nil {
		voting := record.Voting.Snapshot()
		rawVoting = protocol.Encode(&voting)
	}
	// PKI TODO: Extract state proof from record.

	err = db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		result, err := tx.Exec(
			insertKeysetQuery,
			id[:],
			record.Parent[:],
			record.FirstValid,
			record.LastValid,
			record.KeyDilution,
			rawVRF,
			rawStateProof)
		if err = verifyExecWithOneRowEffected(err, result, "insert keyset"); err != nil {
			return err
		}
		pk, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("unable to get pk from keyset: %w", err)
		}

		// Create Rolling entry
		result, err = tx.Exec(insertRollingQuery, pk, rawVoting)
		if err = verifyExecWithOneRowEffected(err, result, "insert rolling"); err != nil {
			return err
		}

		return nil
	})
	return err
}

func (db *participationDB) appendKeysInner(id ParticipationID, keys map[uint64]StateProofKey) error {
	err := db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// Fetch primary key
		var pk int
		row := tx.QueryRow(selectPK, id[:])
		err := row.Scan(&pk)
		if err == sql.ErrNoRows {
			// nothing to do.
			return nil
		}
		if err != nil {
			return fmt.Errorf("unable to scan pk: %w", err)
		}

		stmt, err := tx.Prepare(appendStateProofKeysQuery)
		if err != nil {
			return fmt.Errorf("unable to prepare state proof insert: %w", err)
		}

		for k, v := range keys {
			result, err := stmt.Exec(pk, k, v)
			if err = verifyExecWithOneRowEffected(err, result, "append keys"); err != nil {
				return err
			}
		}

		return nil
	})
	return err
}

func (db *participationDB) registerInner(updated map[ParticipationID]updatingParticipationRecord) error {
	var cacheDeletes []ParticipationID
	err := db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// Disable active key if there is one
		for id, record := range updated {
			err := updateRollingFields(ctx, tx, record.ParticipationRecord)
			// Repair the case when no keys were updated
			if err == ErrNoKeyForID {
				db.log.Warn("participationDB unable to update key in cache. Removing from cache.")
				cacheDeletes = append(cacheDeletes, id)
				if !record.required {
					err = nil
				}
			}
			if err != nil {
				return fmt.Errorf("unable to disable old key when registering %s: %w", id, err)
			}
		}
		return nil
	})

	// Update cache
	if err == nil && len(cacheDeletes) != 0 {
		db.mutex.Lock()
		defer db.mutex.Unlock()
		for _, id := range cacheDeletes {
			delete(db.cache, id)
			delete(db.dirty, id)
		}
	}
	return err
}

func (db *participationDB) deleteInner(id ParticipationID) error {
	err := db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// Fetch primary key
		var pk int
		row := tx.QueryRow(selectPK, id[:])
		err := row.Scan(&pk)
		if err == sql.ErrNoRows {
			// nothing to do.
			return nil
		}
		if err != nil {
			return fmt.Errorf("unable to scan pk: %w", err)
		}

		// Delete rows
		result, err := tx.Exec(deleteKeysets, pk)
		if err = verifyExecWithOneRowEffected(err, result, "delete keyset"); err != nil {
			return err
		}

		result, err = tx.Exec(deleteRolling, pk)
		if err = verifyExecWithOneRowEffected(err, result, "delete rolling"); err != nil {
			return err
		}

		return nil
	})
	return err
}

func (db *participationDB) flushInner() error {
	var dirty map[ParticipationID]struct{}
	db.mutex.Lock()
	if len(db.dirty) != 0 {
		dirty = db.dirty
		db.dirty = make(map[ParticipationID]struct{})
	} else {
		dirty = nil
	}

	var needsUpdate []ParticipationRecord
	// Verify that the dirty flag has not desynchronized from the cache.
	for id := range dirty {
		if rec, ok := db.cache[id]; !ok {
			db.log.Warnf("participationDB fixing dirty flag de-synchronization for %s", id)
			delete(db.cache, id)
		} else {
			needsUpdate = append(needsUpdate, rec)
		}
	}
	db.mutex.Unlock()

	if dirty == nil {
		return nil
	}

	err := db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		var errorStr strings.Builder
		for _, record := range needsUpdate {
			err := updateRollingFields(ctx, tx, record)
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
		// put back what we didn't finish with
		db.mutex.Lock()
		for id, v := range dirty {
			db.dirty[id] = v
		}
		db.mutex.Unlock()
	}

	return err
}

func (db *participationDB) Insert(record Participation) (id ParticipationID, err error) {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	id = record.ID()
	if _, ok := db.cache[id]; ok {
		// PKI TODO: Add a special case to set the StateProof public key if it is in the input
		//           but not in the cache.
		return id, ErrAlreadyInserted
	}

	db.writeQueue <- partDBWriteRecord{
		insertID: id,
		insert:   record,
	}

	// Make some copies.
	var vrf *crypto.VRFSecrets
	if record.VRF != nil {
		vrf = new(crypto.VRFSecrets)
		copy(vrf.SK[:], record.VRF.SK[:])
		copy(vrf.PK[:], record.VRF.PK[:])
	}

	var voting *crypto.OneTimeSignatureSecrets
	if record.Voting != nil {
		voting = new(crypto.OneTimeSignatureSecrets)
		*voting = record.Voting.Snapshot()
	}

	// update cache.
	db.cache[id] = ParticipationRecord{
		ParticipationID:   id,
		Account:           record.Address(),
		FirstValid:        record.FirstValid,
		LastValid:         record.LastValid,
		KeyDilution:       record.KeyDilution,
		LastVote:          0,
		LastBlockProposal: 0,
		LastStateProof:    0,
		EffectiveFirst:    0,
		EffectiveLast:     0,
		Voting:            voting,
		VRF:               vrf,
	}

	return
}

func (db *participationDB) AppendKeys(id ParticipationID, keys map[uint64]StateProofKey) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if _, ok := db.cache[id]; !ok {
		return ErrParticipationIDNotFound
	}

	keyCopy := make(map[uint64]StateProofKey, len(keys))
	for k, v := range keys {
		keyCopy[k] = v // PKI TODO: Deep copy?
	}

	// Update the DB asynchronously.
	db.writeQueue <- partDBWriteRecord{
		insertID: id,
		keys:     keyCopy,
	}
	return nil
}

func (db *participationDB) Delete(id ParticipationID) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// NoOp if key does not exist.
	if _, ok := db.cache[id]; !ok {
		return nil
	}
	delete(db.dirty, id)
	delete(db.cache, id)

	// do the db part async
	db.writeQueue <- partDBWriteRecord{
		delete: id,
	}
	return nil
}

func (db *participationDB) DeleteExpired(round basics.Round) error {
	// This could be optimized to delete everything with one query.
	for _, v := range db.GetAll() {
		if v.LastValid < round {
			err := db.Delete(v.ParticipationID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// scanRecords is a helper to manage scanning participation records.
func scanRecords(rows *sql.Rows) ([]ParticipationRecord, error) {
	results := make([]ParticipationRecord, 0)
	for rows.Next() {
		var record ParticipationRecord
		var rawParticipation []byte
		var rawAccount []byte
		var rawVRF []byte
		var rawVoting []byte

		var lastVote sql.NullInt64
		var lastBlockProposal sql.NullInt64
		var lastCompactCertificate sql.NullInt64
		var effectiveFirst sql.NullInt64
		var effectiveLast sql.NullInt64

		err := rows.Scan(
			&rawParticipation,
			&rawAccount,
			&record.FirstValid,
			&record.LastValid,
			&record.KeyDilution,
			&rawVRF,
			&lastVote,
			&lastBlockProposal,
			&lastCompactCertificate,
			&effectiveFirst,
			&effectiveLast,
			&rawVoting,
		)
		if err != nil {
			return nil, err
		}

		copy(record.ParticipationID[:], rawParticipation)
		copy(record.Account[:], rawAccount)

		if len(rawVRF) > 0 {
			record.VRF = &crypto.VRFSecrets{}
			err = protocol.Decode(rawVRF, record.VRF)
			if err != nil {
				return nil, fmt.Errorf("unable to decode VRF: %w", err)
			}
		}

		if len(rawVoting) > 0 {
			record.Voting = &crypto.OneTimeSignatureSecrets{}
			err = protocol.Decode(rawVoting, record.Voting)
			if err != nil {
				return nil, fmt.Errorf("unable to decode Voting: %w", err)
			}
		}

		// Check optional values.
		if lastVote.Valid {
			record.LastVote = basics.Round(lastVote.Int64)
		}

		if lastBlockProposal.Valid {
			record.LastBlockProposal = basics.Round(lastBlockProposal.Int64)
		}

		if lastCompactCertificate.Valid {
			record.LastStateProof = basics.Round(lastCompactCertificate.Int64)
		}

		if effectiveFirst.Valid {
			record.EffectiveFirst = basics.Round(effectiveFirst.Int64)
		}

		if effectiveLast.Valid {
			record.EffectiveLast = basics.Round(effectiveLast.Int64)
		}

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

// GetForRound fetches a record with all secrets for a particular round.
func (db *participationDB) GetForRound(id ParticipationID, round basics.Round) (ParticipationRecordForRound, error) {
	var result ParticipationRecordForRound
	result.ParticipationRecord = db.Get(id)
	if result.ParticipationRecord.IsZero() {
		return ParticipationRecordForRound{}, ErrParticipationIDNotFound
	}

	err := db.store.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		row := tx.QueryRow(selectStateProofKeys, round, id[:])
		err := row.Scan(&result.StateProof)
		if err == sql.ErrNoRows {
			return ErrSecretNotFound
		}
		if err != nil {
			return fmt.Errorf("error while querying secrets: %w", err)
		}

		return nil
	})

	if err != nil {
		return ParticipationRecordForRound{}, fmt.Errorf("unable to lookup secrets: %w", err)
	}

	return result, nil
}

// updateRollingFields sets all of the rolling fields according to the record object.
func updateRollingFields(ctx context.Context, tx *sql.Tx, record ParticipationRecord) error {
	result, err := tx.ExecContext(ctx, updateRollingFieldsSQL,
		record.LastVote,
		record.LastBlockProposal,
		record.LastStateProof,
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

// PKI TODO: Register needs a bit more work to make sure EffectiveFirst and
//           EffectiveLast are set at the right time. Specifically, the node
//           doesn't call Register until the key becomes active and is about
//           to be used, so effective first/last is updated just-in-time. It
//           would be better to update them when the KeyRegistration occurs.
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

	var toUpdate []ParticipationRecord
	db.mutex.Lock()
	for _, record := range db.cache {
		if record.Account == recordToRegister.Account && record.ParticipationID != id && recordActive(record, on) {
			toUpdate = append(toUpdate, record)
		}
	}
	db.mutex.Unlock()

	updated := make(map[ParticipationID]updatingParticipationRecord)

	// Disable active key if there is one
	for _, record := range toUpdate {
		record.EffectiveLast = on - 1
		updated[record.ParticipationID] = updatingParticipationRecord{
			record.Duplicate(),
			false,
		}
	}
	// Mark registered.
	recordToRegister.EffectiveFirst = on
	recordToRegister.EffectiveLast = recordToRegister.LastValid
	updated[recordToRegister.ParticipationID] = updatingParticipationRecord{
		recordToRegister,
		true,
	}

	if len(updated) != 0 {
		db.writeQueue <- partDBWriteRecord{
			registerUpdated: updated,
		}
		db.mutex.Lock()
		for id, record := range updated {
			delete(db.dirty, id)
			db.cache[id] = record.ParticipationRecord
		}
		db.mutex.Unlock()
	}

	db.log.Infof("Registered key (%s) for account (%s) first valid (%d) last valid (%d)\n",
		id, recordToRegister.Account, recordToRegister.FirstValid, recordToRegister.LastValid)
	return nil
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
	case StateProof:
		record.LastStateProof = round
	default:
		return ErrUnknownParticipationAction
	}

	db.dirty[record.ParticipationID] = struct{}{}
	db.cache[record.ParticipationID] = record
	return nil
}

// Flush waits until all enqueued asynchronous IO has completed.
// Waiting for all asynchronous IO to complete includes actions from other threads.
// Flush waits for the participation registry to be idle.
// Flush returns the latest error generated by async IO, if any.
func (db *participationDB) Flush(timeout time.Duration) error {
	resultCh := make(chan error, 1)
	timeoutCh := time.After(timeout)
	writeRecord := partDBWriteRecord{
		flushResultChannel: resultCh,
	}

	select {
	case db.writeQueue <- writeRecord:
	case <-timeoutCh:
		return fmt.Errorf("timeout while requesting flush, check results manually")
	}

	select {
	case err := <-resultCh:
		return err
	case <-timeoutCh:
		return fmt.Errorf("timeout while flushing changes, check results manually")
	}
}

// Close attempts to flush with db.flushTimeout, then waits for the write queue for another db.flushTimeout.
func (db *participationDB) Close() {
	if err := db.Flush(db.flushTimeout); err != nil {
		db.log.Warnf("participationDB unhandled error during Close/Flush: %w", err)
	}

	db.store.Close()
	close(db.writeQueue)

	// Wait for write queue to close.
	select {
	case <-db.writeQueueDone:
		return
	case <-time.After(db.flushTimeout):
		db.log.Warnf("Close(): timeout while waiting for WriteQueue to finish.")
	}
}
