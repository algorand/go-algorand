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
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

const defaultTimeout = 5 * time.Second

// ParticipationID identifies a particular set of participation keys.
//
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

type (
	// ParticipationRecord contains all metadata relating to a set of participation keys.
	ParticipationRecord struct {
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

		StateProof *merklesignature.Verifier
		VRF        *crypto.VRFSecrets
		Voting     *crypto.OneTimeSignatureSecrets
	}

	// StateProofKeys represents a set of ephemeral stateproof keys with their corresponding round
	//msgp:allocbound StateProofKeys 1000
	StateProofKeys []merklesignature.KeyRoundPair

	// ParticipationRecordForRound contains participant's secrets that corresponds to
	// one specific round. In Addition, it also returns the participation metadata
	ParticipationRecordForRound struct {
		ParticipationRecord
	}

	// StateProofSecretsForRound contains participant's state proof secrets that corresponds to
	// one specific round. In Addition, it also returns the participation metadata.
	// If there are no secrets for the round a nil is returned in Stateproof field.
	StateProofSecretsForRound struct {
		ParticipationRecord

		StateProofSecrets *merklesignature.Signer
	}

	// SortUint64 implements sorting by uint64 keys for
	// canonical encoding of maps in msgpack format.
	SortUint64 = basics.SortUint64
)

// IsZero returns true if the object contains zero values.
func (r ParticipationRecordForRound) IsZero() bool {
	return r.ParticipationRecord.IsZero()
}

// VotingSigner returns the voting secrets associated with this Participation account,
// together with the KeyDilution value.
func (r *ParticipationRecordForRound) VotingSigner() crypto.OneTimeSigner {
	return crypto.OneTimeSigner{
		OneTimeSignatureSecrets: r.Voting,
		OptionalKeyDilution:     r.KeyDilution,
	}
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

	var stateProof *merklesignature.Verifier
	if r.StateProof != nil {
		stateProof = &merklesignature.Verifier{}
		copy(stateProof.Commitment[:], r.StateProof.Commitment[:])
		stateProof.KeyLifetime = r.StateProof.KeyLifetime
	}

	dupParticipation := ParticipationRecord{
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
		StateProof:        stateProof,
		VRF:               &vrf,
		Voting:            &voting,
	}

	return dupParticipation
}

// OverlapsInterval returns true if the partkey is valid at all within the range of rounds (inclusive)
func (r ParticipationRecord) OverlapsInterval(first, last basics.Round) bool {
	if last < first {
		logging.Base().Panicf("Round interval should be ordered (first = %v, last = %v)", first, last)
	}
	if last < r.FirstValid || first > r.LastValid {
		return false
	}
	return true
}

// ParticipationAction is used when recording participation actions.
//
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

// ErrRequestedRoundOutOfRange is used when the requested round for GetForRound is outside the valid range of this participation
var ErrRequestedRoundOutOfRange = errors.New("request range is not within the validity range")

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

// ErrStateProofVerifierNotFound states that no state proof field was found.
var ErrStateProofVerifierNotFound = errors.New("record contains no StateProofVerifier")

// ParticipationRegistry contain all functions for interacting with the Participation Registry.
type ParticipationRegistry interface {
	// Insert adds a record to storage and computes the ParticipationID
	Insert(record Participation) (ParticipationID, error)

	// AppendKeys appends state proof keys to an existing Participation record. Keys can only be appended
	// once, an error will occur when the data is flushed when inserting a duplicate key.
	AppendKeys(id ParticipationID, keys StateProofKeys) error

	// DeleteStateProofKeys removes all stateproof keys up to, and not including, a given round
	DeleteStateProofKeys(id ParticipationID, round basics.Round) error

	// Delete removes a record from storage.
	Delete(id ParticipationID) error

	// DeleteExpired removes all records and ephemeral voting keys from storage that are expired on the given round.
	DeleteExpired(latestRound basics.Round, proto config.ConsensusParams) error

	// Get a participation record.
	Get(id ParticipationID) ParticipationRecord

	// GetAll of the participation records.
	GetAll() []ParticipationRecord

	// GetForRound fetches a record with voting secrets for a particular round.
	GetForRound(id ParticipationID, round basics.Round) (ParticipationRecordForRound, error)

	// GetStateProofSecretsForRound fetches a record with stateproof secrets for a particular round.
	GetStateProofSecretsForRound(id ParticipationID, round basics.Round) (StateProofSecretsForRound, error)

	// HasLiveKeys quickly tests to see if there is a valid participation key over some range of rounds
	HasLiveKeys(from, to basics.Round) bool

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
		func(ctx context.Context, tx *sql.Tx, newDatabase bool) error {
			err := dbSchemaUpgrade1(ctx, tx, newDatabase, log)
			if err != nil {
				// db.Initialize masks the cause; keep it in the log
				log.Errorf("participationDB: registry upgrade to version 2 failed: %v", err)
			}
			return err
		},
	}

	err := db.Initialize(accessor.Wdb, migrations)
	if err != nil {
		accessor.Close()
		return nil, fmt.Errorf("unable to initialize participation registry database: %w", err)
	}

	registry := &participationDB{
		log:            log,
		store:          accessor,
		writeQueue:     make(chan opRequest, 10),
		writeQueueDone: make(chan struct{}),
		flushTimeout:   defaultTimeout,
		pendingInserts: make(map[ParticipationID]bool),
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
			stateProof BLOB --*  msgpack encoding of merklesignature.SignerContext
		)`

	// Rolling maintains a 1-to-1 relationship with Keysets by primary key
	createRolling = `CREATE TABLE Rolling (
			pk INTEGER PRIMARY KEY NOT NULL,

			lastVoteRound               INTEGER,
			lastBlockProposalRound      INTEGER,
			lastStateProofRound         INTEGER,
			effectiveFirstRound         INTEGER,
			effectiveLastRound          INTEGER,

			votingHeader BLOB --*  msgpack encoding of crypto.OneTimeSignatureSecretsHeader
		)`

	createStateProof = `CREATE TABLE StateProofKeys (
			pk    INTEGER NOT NULL, --* join with keyset to find key for a particular participation id
			round INTEGER NOT NULL, --*  committed round for this key
			key   BLOB    NOT NULL, --*  msgpack encoding of ParticipationAccount.BlockProof.SignatureAlgorithm
			PRIMARY KEY (pk, round)
		)`

	// VotingBatches/VotingOffsets hold one row per ephemeral voting subkey,
	// so per-round key deletion is a row delete instead of a rewrite of the
	// whole keyset (Rolling.votingHeader describes the rows).  WITHOUT ROWID
	// makes the composite primary key the table's only B-tree; a rowid table
	// would maintain a separate index B-tree and write an extra page per
	// deleted row.
	createVotingBatches = `CREATE TABLE VotingBatches (
			pk    INTEGER NOT NULL,
			batch INTEGER NOT NULL, --* absolute batch number
			data  BLOB    NOT NULL, --* msgpack encoding of the batch subkey
			PRIMARY KEY (pk, batch)
		) WITHOUT ROWID`
	createVotingOffsets = `CREATE TABLE VotingOffsets (
			pk    INTEGER NOT NULL,
			off   INTEGER NOT NULL, --* absolute offset within the expanded batch (FirstBatch-1 of the header)
			data  BLOB    NOT NULL, --* msgpack encoding of the offset subkey
			PRIMARY KEY (pk, off)
		) WITHOUT ROWID`
	insertKeysetQuery         = `INSERT INTO Keysets (participationID, account, firstValidRound, lastValidRound, keyDilution, vrf, stateProof) VALUES (?, ?, ?, ?, ?, ?, ?)`
	insertRollingQuery        = `INSERT INTO Rolling (pk, votingHeader) VALUES (?, ?)`
	appendStateProofKeysQuery = `INSERT INTO StateProofKeys (pk, round, key) VALUES(?, ?, ?)`
	deleteStateProofKeysQuery = `DELETE FROM StateProofKeys WHERE pk=? AND round<?`

	// SELECT pk FROM Keysets WHERE participationID = ?
	selectPK      = `SELECT pk FROM Keysets WHERE participationID = ? LIMIT 1`
	selectLastPK  = `SELECT pk FROM Keysets ORDER BY pk DESC LIMIT 1`
	selectRecords = `SELECT
			k.pk, k.participationID, k.account, k.firstValidRound,
       		k.lastValidRound, k.keyDilution, k.vrf, k.stateProof,
			r.lastVoteRound, r.lastBlockProposalRound, r.lastStateProofRound,
			r.effectiveFirstRound, r.effectiveLastRound, r.votingHeader
		FROM Keysets k
		INNER JOIN Rolling r
		ON k.pk = r.pk`
	selectStateProofData = `SELECT stateProof FROM Keysets WHERE participationID = ? LIMIT 1`
	selectStateProofKey  = `SELECT s.key
		FROM StateProofKeys s
		WHERE round=?
		   AND pk IN (SELECT pk FROM Keysets WHERE participationID=?)`
	selectRollingVotingByID = `SELECT r.pk, r.votingHeader
		FROM Rolling r
		WHERE r.pk IN (SELECT pk FROM Keysets WHERE participationID=?)`
	selectVotingBatches   = `SELECT batch, data FROM VotingBatches WHERE pk=? ORDER BY batch`
	selectVotingOffsets   = `SELECT off, data FROM VotingOffsets WHERE pk=? ORDER BY off`
	deleteKeysets         = `DELETE FROM Keysets WHERE pk=?`
	deleteRolling         = `DELETE FROM Rolling WHERE pk=?`
	deleteStateProofByPK  = `DELETE FROM StateProofKeys WHERE pk=?`
	deleteVotingBatchesPK = `DELETE FROM VotingBatches WHERE pk=?`
	deleteVotingOffsetsPK = `DELETE FROM VotingOffsets WHERE pk=?`

	// insert-time clearing of any pre-existing rows for a participation ID
	// (child tables first — their subqueries depend on Keysets)
	clearRollingByID       = `DELETE FROM Rolling WHERE pk IN (SELECT pk FROM Keysets WHERE participationID=?)`
	clearStateProofByID    = `DELETE FROM StateProofKeys WHERE pk IN (SELECT pk FROM Keysets WHERE participationID=?)`
	clearVotingBatchesByID = `DELETE FROM VotingBatches WHERE pk IN (SELECT pk FROM Keysets WHERE participationID=?)`
	clearVotingOffsetsByID = `DELETE FROM VotingOffsets WHERE pk IN (SELECT pk FROM Keysets WHERE participationID=?)`
	clearKeysetsByID       = `DELETE FROM Keysets WHERE participationID=?`
	// a NULL votingHeader argument keeps the stored header
	updateRollingFieldsSQL = `UPDATE Rolling
		 SET lastVoteRound=?,
		     lastBlockProposalRound=?,
		     lastStateProofRound=?,
		     effectiveFirstRound=?,
		     effectiveLastRound=?,
		     votingHeader=COALESCE(?, votingHeader)
		 WHERE pk=?`
	updateRegistrationFieldsSQL = `UPDATE Rolling
		 SET effectiveFirstRound=?,
		     effectiveLastRound=?
		 WHERE pk=?`
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

// unusableVotingHeader marks a record whose legacy voting blob could not be
// converted: a single msgpack "never used" byte.  It holds no secrets and
// never decodes as a header, so the record is excluded at load and any
// re-insert of the key fails closed, exactly as for a damaged header.
var unusableVotingHeader = []byte{0xc1}

// dbSchemaUpgrade1 moves the voting subkeys out of the whole-secrets
// Rolling.voting blob into per-subkey rows described by a Rolling.votingHeader
// column, then drops the legacy column so the blob (which held every subkey)
// is erased from the registry.
//
// A record whose blob cannot be decoded or converted does not fail the
// upgrade: db.Initialize would report only the schema versions, leaving algod
// unable to start with no indication of which record is at fault.  Instead
// the failure is logged with its pk and cause, and its votingHeader is set to
// unusableVotingHeader, so the record is excluded from the cache at load
// time while its blob is erased along with the legacy column.
func dbSchemaUpgrade1(ctx context.Context, tx *sql.Tx, newDatabase bool, log logging.Logger) error {
	_, err := tx.Exec(createVotingBatches)
	if err != nil {
		return err
	}
	_, err = tx.Exec(createVotingOffsets)
	if err != nil {
		return err
	}

	if newDatabase {
		// dbSchemaUpgrade0 already created Rolling with votingHeader
		return nil
	}

	// the legacy blobs hold every subkey: whatever is freed below must be
	// erased, not left in free pages
	if err = enableSecureDelete(tx); err != nil {
		return err
	}
	_, err = tx.Exec("ALTER TABLE Rolling ADD COLUMN votingHeader BLOB")
	if err != nil {
		return fmt.Errorf("failed to add the votingHeader column: %w", err)
	}

	type pkVoting struct {
		pk        int64
		rawVoting []byte
	}
	var blobs []pkVoting
	rows, err := tx.Query("SELECT pk, voting FROM Rolling")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var entry pkVoting
		if err = rows.Scan(&entry.pk, &entry.rawVoting); err != nil {
			return err
		}
		blobs = append(blobs, entry)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	rows.Close()

	for _, entry := range blobs {
		if len(entry.rawVoting) == 0 {
			continue
		}
		convErr := convertLegacyVotingBlob(tx, entry.pk, entry.rawVoting)
		if convErr == nil {
			continue
		}
		log.Errorf("participationDB: voting blob of registry record pk %d cannot be converted and is discarded; the record will be excluded at load and must be re-installed (%v)", entry.pk, convErr)
		if _, err = tx.Exec("UPDATE Rolling SET votingHeader=? WHERE pk=?", unusableVotingHeader, entry.pk); err != nil {
			return fmt.Errorf("failed to mark the voting header of pk %d unusable: %w", entry.pk, err)
		}
	}

	_, err = tx.Exec("ALTER TABLE Rolling DROP COLUMN voting")
	if err != nil {
		return fmt.Errorf("failed to drop the legacy voting column: %w", err)
	}
	return nil
}

// convertLegacyVotingBlob converts one record's whole-secrets blob into a
// header and rows, verified by read-back, under a savepoint so a failure
// leaves nothing of the attempt behind.
func convertLegacyVotingBlob(tx *sql.Tx, pk int64, rawVoting []byte) error {
	voting := &crypto.OneTimeSignatureSecrets{}
	if err := protocol.Decode(rawVoting, voting); err != nil {
		return fmt.Errorf("undecodable voting blob: %w", err)
	}
	if _, err := tx.Exec("SAVEPOINT convert_record"); err != nil {
		return err
	}
	target := registryVotingTarget(pk)
	// freshly decoded and unshared: no lock is needed for the snapshot
	err := rewriteVotingRows(tx, target, voting.OneTimeSignatureSecretsPersistent)
	if err == nil {
		err = verifyVotingRowsMatch(tx, target, voting)
	}
	if err != nil {
		if _, rerr := tx.Exec("ROLLBACK TO SAVEPOINT convert_record"); rerr != nil {
			return fmt.Errorf("%v (and rolling the attempt back failed: %w)", err, rerr)
		}
	}
	if _, rerr := tx.Exec("RELEASE SAVEPOINT convert_record"); rerr != nil {
		return rerr
	}
	return err
}

// participationDB provides a concrete implementation of the ParticipationRegistry interface.
type participationDB struct {
	cache map[ParticipationID]ParticipationRecord

	// dirty marked on Record(), DeleteExpired(), cleared on Register(), Delete(), Flush()
	dirty map[ParticipationID]struct{}

	// pendingInserts holds the IDs of inserts whose write has not completed
	// yet; they are not in the cache, so this is what dedups them.  The value
	// records whether a Delete arrived meanwhile, to be honored once the
	// write lands; the ID stays reserved until that deletion is queued.
	pendingInserts map[ParticipationID]bool

	// testInsertGate, when set (tests only), runs after an insert's write has
	// landed and before its deferred deletion is queued.
	testInsertGate func()

	// excluded holds the stored keys whose voting data failed validation at
	// load, with their LastValid.  They are kept out of the cache (they
	// cannot vote) and their subkey rows are erased, but they stay tracked so
	// they are deleted when they expire or on request, and replaced if the
	// key is re-inserted.
	excluded map[ParticipationID]basics.Round

	log   logging.Logger
	store db.Pair
	mutex deadlock.RWMutex

	writeQueue     chan opRequest
	writeQueueDone chan struct{}

	flushTimeout time.Duration
}

// DeleteStateProofKeys is a non-blocking operation, responsible for removing state-proof keys from the DB.
func (db *participationDB) DeleteStateProofKeys(id ParticipationID, round basics.Round) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if _, ok := db.cache[id]; !ok {
		return ErrParticipationIDNotFound
	}

	db.writeQueue <- makeOpRequest(&deleteStateProofKeysOp{
		ParticipationID: id,
		round:           round,
	})
	return nil
}

type updatingParticipationRecord struct {
	ParticipationRecord

	required bool
}

func (db *participationDB) initializeCache() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	records, corrupt, err := db.getAllFromDB()
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

	// Forward security: the subkeys of a record that failed validation can
	// no longer be accounted for, so they are erased now instead of lingering
	// past their rounds.  The header stays, so a re-insert of the key from
	// its file can still be checked against the stored deletion cursor.
	if len(corrupt) > 0 {
		err = db.store.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
			for id := range corrupt {
				for _, query := range []string{clearVotingBatchesByID, clearVotingOffsetsByID} {
					if _, err = tx.Exec(query, id[:]); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("unable to erase the voting subkeys of corrupt records: %w", err)
		}
	}

	db.cache = cache
	db.dirty = make(map[ParticipationID]struct{})
	db.excluded = corrupt
	return nil
}

func (db *participationDB) writeThread() {
	defer close(db.writeQueueDone)
	var lastErr error

	for op := range db.writeQueue {
		err := op.operation.apply(db)
		if op.errChannel == nil {
			// fire-and-forget: surfaced by the next flush
			if err != nil {
				lastErr = err
			}
			continue
		}
		// an op with a channel reports its own result; a flush additionally
		// surfaces the errors of earlier fire-and-forget ops
		if _, isFlush := op.operation.(*flushOp); isFlush {
			if err == nil {
				err = lastErr
			}
			lastErr = nil
		}
		op.errChannel <- err
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

// Insert stores the participation key and makes it available.  The write is
// validated on the write thread before the record enters the cache (a copy
// that lags the stored deletion cursor is fast-forwarded, and one whose
// relation to the stored state cannot be established is rejected), so a
// rejected copy is never usable.
//
// A Delete that arrives while the write is in flight is honored as soon as
// the write lands.  Insert still reports success in that case, since the key
// was stored, so a caller that reads the key back immediately may find it
// already gone; a re-insert racing that deletion is reported as
// ErrAlreadyInserted until the deletion has been queued.
func (db *participationDB) Insert(record Participation) (id ParticipationID, err error) {
	id = record.ID()

	db.mutex.Lock()
	_, inCache := db.cache[id]
	_, pending := db.pendingInserts[id]
	if inCache || pending {
		db.mutex.Unlock()
		// PKI TODO: Add a special case to set the StateProof public key if it is in the input
		//           but not in the cache.
		return id, ErrAlreadyInserted
	}
	db.pendingInserts[id] = false
	_, replacesExcluded := db.excluded[id]
	db.mutex.Unlock()

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

	// hand the write op the same frozen snapshot the cache gets: the caller
	// may keep advancing the live secrets (e.g. the partkey file's copy),
	// and persisting a newer state than the cache holds would trip the
	// monotonicity guard on the next flush
	record.Voting = voting
	written := make(chan error, 1)
	db.writeQueue <- makeOpRequestWithError(&insertOp{
		id:               id,
		record:           record,
		replacesExcluded: replacesExcluded,
	}, written)
	err = <-written

	var stateProofVerifierPtr *merklesignature.Verifier
	if record.StateProofSecrets != nil {
		stateProofVerifierPtr = &merklesignature.Verifier{}
		copy(stateProofVerifierPtr.Commitment[:], record.StateProofSecrets.GetVerifier().Commitment[:])
		stateProofVerifierPtr.KeyLifetime = record.StateProofSecrets.GetVerifier().KeyLifetime
	}

	db.mutex.Lock()
	deleteRequested := db.pendingInserts[id]
	if !deleteRequested {
		delete(db.pendingInserts, id)
	}
	if err == nil || deleteRequested {
		delete(db.excluded, id) // replaced by the insert, or deleted on request
	}
	if err == nil && !deleteRequested {
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
			StateProof:        stateProofVerifierPtr,
			Voting:            voting,
			VRF:               vrf,
		}
	}
	db.mutex.Unlock()

	if deleteRequested {
		// A Delete arrived while the write was pending: honor it now that the
		// rows exist (a no-op if the insert was rejected).  The ID stays
		// reserved until the deletion is queued, so a concurrent re-insert
		// cannot order its write ahead of it and lose its rows to it.
		if db.testInsertGate != nil {
			db.testInsertGate()
		}
		db.writeQueue <- makeOpRequest(&deleteOp{id})
		db.mutex.Lock()
		delete(db.pendingInserts, id)
		db.mutex.Unlock()
	}
	if err != nil {
		return id, fmt.Errorf("participationDB: unable to insert key %s: %w", id, err)
	}
	return id, nil
}

func (db *participationDB) AppendKeys(id ParticipationID, keys StateProofKeys) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if _, ok := db.cache[id]; !ok {
		return ErrParticipationIDNotFound
	}

	// Update the DB asynchronously.
	db.writeQueue <- makeOpRequest(&appendKeysOp{
		id:   id,
		keys: keys,
	})

	return nil
}

func (db *participationDB) Delete(id ParticipationID) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// A key whose insert is still being written is deleted once the write
	// lands, so the delete is not lost to the pending window.
	if _, pending := db.pendingInserts[id]; pending {
		db.pendingInserts[id] = true
		return nil
	}
	// NoOp if key does not exist (an excluded record is deletable too).
	_, cached := db.cache[id]
	_, isExcluded := db.excluded[id]
	if !cached && !isExcluded {
		return nil
	}
	delete(db.dirty, id)
	delete(db.cache, id)
	delete(db.excluded, id)

	// do the db part async
	db.writeQueue <- makeOpRequest(&deleteOp{id})

	return nil
}

func (db *participationDB) DeleteExpired(latestRound basics.Round, agreementProto config.ConsensusParams) error {
	// We need a key for round r+1 for agreement.
	nextRound := latestRound + 1
	var updated []ParticipationRecord

	for _, v := range db.GetAll() {
		if v.LastValid < latestRound { // this participation key is no longer valid; delete it
			// This could be optimized to delete everything with one query.
			err := db.Delete(v.ParticipationID)
			if err != nil {
				return err
			}
		} else if v.FirstValid <= latestRound { // this key is valid; update it
			keyDilution := v.KeyDilution
			if keyDilution == 0 {
				keyDilution = agreementProto.DefaultKeyDilution
			}
			v.Voting.DeleteBeforeFineGrained(basics.OneTimeIDForRound(nextRound, keyDilution), keyDilution)
			updated = append(updated, v)
		}
	}

	// merge the advanced voting secrets into the cache and mark the records
	// dirty, so they will be flushed by a call to FlushRegistry after each round
	db.mutex.Lock()
	db.mergeAdvancedVoting(updated)
	// excluded records cannot vote, but they expire like any other key
	var expired []ParticipationID
	for id, lastValid := range db.excluded {
		if lastValid < latestRound {
			expired = append(expired, id)
		}
	}
	db.mutex.Unlock()
	for _, id := range expired {
		if err := db.Delete(id); err != nil {
			return err
		}
	}
	return nil
}

// mergeAdvancedVoting stores the voting secrets of the given snapshots into
// the live cache entries and marks them dirty.  Only Voting is merged: the
// snapshots predate the lock the caller holds, so a Register or Record that
// ran in between has already updated the other fields of the live entry, and
// overwriting the whole record would lose (and then flush over) that update.
// The caller must hold db.mutex.
//
// A key deleted and re-inserted under the same ID in that window receives the
// snapshot's Voting as well.  That is deliberate and safe: the ID pins the key
// material, and the snapshot was advanced past the stored cursor the
// re-inserted copy was fast-forwarded to, so it never rewinds the entry.
// Skipping such entries would instead leave this round's deletion out of the
// cache until the next pass.
func (db *participationDB) mergeAdvancedVoting(updated []ParticipationRecord) {
	for _, r := range updated {
		live, ok := db.cache[r.ParticipationID]
		if !ok {
			// deleted meanwhile; do not resurrect it in the cache
			continue
		}
		live.Voting = r.Voting
		db.cache[r.ParticipationID] = live
		db.dirty[r.ParticipationID] = struct{}{}
	}
}

// scannedRecord is one Keysets+Rolling row: the record, its primary key, and
// its raw voting header.  The caller decodes the voting secrets, so a corrupt
// record can be excluded instead of failing the whole scan.
type scannedRecord struct {
	record    ParticipationRecord
	pk        int64
	rawHeader []byte
}

// scanRecords is a helper to manage scanning participation records.
func scanRecords(rows *sql.Rows) ([]scannedRecord, error) {
	results := make([]scannedRecord, 0)
	for rows.Next() {
		var pk int64
		var record ParticipationRecord
		var rawParticipation []byte
		var rawAccount []byte
		var rawVRF []byte
		var rawVoting []byte
		var rawStateProof []byte

		var lastVote sql.NullInt64
		var lastBlockProposal sql.NullInt64
		var lastStateProof sql.NullInt64
		var effectiveFirst sql.NullInt64
		var effectiveLast sql.NullInt64

		err := rows.Scan(
			&pk,
			&rawParticipation,
			&rawAccount,
			&record.FirstValid,
			&record.LastValid,
			&record.KeyDilution,
			&rawVRF,
			&rawStateProof,
			&lastVote,
			&lastBlockProposal,
			&lastStateProof,
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

		if len(rawStateProof) > 0 {
			stateProof := merklesignature.Signer{}
			err = protocol.Decode(rawStateProof, &stateProof.SignerContext)
			if err != nil {
				return nil, fmt.Errorf("unable to decode stateproof: %w", err)
			}
			var stateProofVerifer merklesignature.Verifier
			copy(stateProofVerifer.Commitment[:], stateProof.GetVerifier().Commitment[:])
			stateProofVerifer.KeyLifetime = stateProof.GetVerifier().KeyLifetime
			record.StateProof = &stateProofVerifer
		}

		// Check optional values.
		if lastVote.Valid {
			record.LastVote = basics.Round(lastVote.Int64)
		}

		if lastBlockProposal.Valid {
			record.LastBlockProposal = basics.Round(lastBlockProposal.Int64)
		}

		if lastStateProof.Valid {
			record.LastStateProof = basics.Round(lastStateProof.Int64)
		}

		if effectiveFirst.Valid {
			record.EffectiveFirst = basics.Round(effectiveFirst.Int64)
		}

		if effectiveLast.Valid {
			record.EffectiveLast = basics.Round(effectiveLast.Int64)
		}

		results = append(results, scannedRecord{record: record, pk: pk, rawHeader: rawVoting})
	}

	// an iteration error ends the loop the same way exhaustion does; without
	// this check it would silently truncate the result set
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// getAllFromDB loads every stored record.  Records whose voting data fails
// validation are returned separately in corrupt (id to LastValid), so the
// caller can keep them out of the cache without failing the whole load.
func (db *participationDB) getAllFromDB() (records []ParticipationRecord, corrupt map[ParticipationID]basics.Round, err error) {
	corrupt = make(map[ParticipationID]basics.Round)
	err = db.store.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.Query(selectRecords)
		if err != nil {
			return fmt.Errorf("unable to query records: %w", err)
		}
		defer rows.Close()

		scanned, err := scanRecords(rows)
		if err != nil {
			return fmt.Errorf("problem scanning records: %w", err)
		}
		// release the cursor before issuing the subkey queries below
		rows.Close()

		// reassemble each key's voting secrets from its subkey rows; a record
		// whose voting data is corrupt is excluded with an error log rather
		// than blocking the whole registry (and with it the node) from loading
		records = make([]ParticipationRecord, 0, len(scanned))
		for _, sr := range scanned {
			batches, offsets, err := readVotingRows(tx, registryVotingTarget(sr.pk))
			if err != nil {
				return fmt.Errorf("unable to read the voting subkeys of pk %d: %w", sr.pk, err)
			}
			if len(sr.rawHeader) > 0 || len(batches)+len(offsets) > 0 {
				var voting *crypto.OneTimeSignatureSecrets
				hdr, verr := decodeVotingHeader(sr.rawHeader)
				if verr == nil {
					voting, verr = votingFromRows(hdr, batches, offsets)
				}
				if verr != nil {
					db.log.Errorf("participationDB: excluding key %s (pk %d) from the registry and erasing its voting subkeys, its voting data is corrupt: %v; the key cannot vote until it is re-installed (a key with a .partkey file is re-installed at startup; one installed over the REST API must be installed again), or delete %s and restart to rebuild the registry",
						sr.record.ParticipationID, sr.pk, verr, config.ParticipationRegistryFilename)
					corrupt[sr.record.ParticipationID] = sr.record.LastValid
					continue
				}
				sr.record.Voting = voting
			}
			records = append(records, sr.record)
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

func (db *participationDB) HasLiveKeys(from, to basics.Round) bool {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	for _, record := range db.cache {
		if record.OverlapsInterval(from, to) {
			return true
		}
	}
	return false
}

// GetStateProofSecretsForRound returns the state proof data required to sign the compact certificate for this round
func (db *participationDB) GetStateProofSecretsForRound(id ParticipationID, round basics.Round) (StateProofSecretsForRound, error) {
	partRecord, err := db.GetForRound(id, round)
	if err != nil {
		return StateProofSecretsForRound{}, err
	}
	if partRecord.StateProof == nil {
		return StateProofSecretsForRound{},
			fmt.Errorf("%w: for participation ID %v", ErrStateProofVerifierNotFound, id)
	}

	var result StateProofSecretsForRound
	result.ParticipationRecord = partRecord.ParticipationRecord
	var rawStateProofKey []byte
	err = db.store.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// fetch secret key
		keyFirstValidRound, err2 := partRecord.StateProof.FirstRoundInKeyLifetime(uint64(round))
		if err2 != nil {
			return err2
		}

		row := tx.QueryRow(selectStateProofKey, keyFirstValidRound, id[:])
		err2 = row.Scan(&rawStateProofKey)
		if err2 == sql.ErrNoRows {
			return ErrSecretNotFound
		}
		if err2 != nil {
			return fmt.Errorf("error while querying secrets: %w", err2)
		}

		return nil
	})
	if err != nil {
		return StateProofSecretsForRound{}, fmt.Errorf("failed to fetch state proof for round %d: %w", round, err)
	}

	// Init stateproof fields after being able to retrieve key from database
	result.StateProofSecrets = &merklesignature.Signer{}
	result.StateProofSecrets.SigningKey = &crypto.FalconSigner{}
	result.StateProofSecrets.Round = uint64(round)

	err = protocol.Decode(rawStateProofKey, result.StateProofSecrets.SigningKey)
	if err != nil {
		return StateProofSecretsForRound{}, err
	}

	var rawSignerContext []byte
	err = db.store.Rdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		// fetch stateproof public data
		row := tx.QueryRow(selectStateProofData, id[:])
		err2 := row.Scan(&rawSignerContext)
		if err2 != nil {
			return fmt.Errorf("error while querying stateproof data: %w", err2)
		}
		return nil
	})
	if err != nil {
		return StateProofSecretsForRound{}, err
	}
	err = protocol.Decode(rawSignerContext, &result.StateProofSecrets.SignerContext)
	if err != nil {
		return StateProofSecretsForRound{}, err
	}
	return result, nil
}

// GetForRound fetches a record with all secrets for a particular round.
func (db *participationDB) GetForRound(id ParticipationID, round basics.Round) (ParticipationRecordForRound, error) {
	var result ParticipationRecordForRound

	result.ParticipationRecord = db.Get(id)
	if result.ParticipationRecord.IsZero() {
		return ParticipationRecordForRound{}, ErrParticipationIDNotFound
	}

	if round > result.LastValid {
		return ParticipationRecordForRound{}, ErrRequestedRoundOutOfRange
	}

	return result, nil
}

// rollingHeader is one Rolling row of a participation ID: its primary key
// and stored voting header.
type rollingHeader struct {
	pk  int64
	raw []byte
}

// readRollingHeaders returns every Rolling row stored for a participation ID
// (normally exactly one).
func readRollingHeaders(ctx context.Context, tx *sql.Tx, id ParticipationID) ([]rollingHeader, error) {
	rows, err := tx.QueryContext(ctx, selectRollingVotingByID, id[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var headers []rollingHeader
	for rows.Next() {
		var h rollingHeader
		if err = rows.Scan(&h.pk, &h.raw); err != nil {
			return nil, err
		}
		headers = append(headers, h)
	}
	return headers, rows.Err()
}

// resolveRollingPK looks up the Rolling primary key and stored voting
// header for a participation ID, keeping the legacy ErrNoKeyForID and
// ErrMultipleKeysForID semantics that callers special-case.
func resolveRollingPK(ctx context.Context, tx *sql.Tx, id ParticipationID) (pk int64, rawHeader []byte, err error) {
	headers, err := readRollingHeaders(ctx, tx, id)
	if err != nil {
		return 0, nil, err
	}
	if len(headers) > 1 {
		return 0, nil, ErrMultipleKeysForID
	}
	if len(headers) < 1 {
		return 0, nil, ErrNoKeyForID
	}
	return headers[0].pk, headers[0].raw, nil
}

// updateRegistrationFields persists only the registration window
// (EffectiveFirst/EffectiveLast) of the record.  Registration deliberately
// does not touch the voting secrets or the last-used rounds: the record it
// carries is a snapshot taken when Register was called, and a flush that ran
// in between may already have persisted a newer deletion cursor.
func updateRegistrationFields(ctx context.Context, tx *sql.Tx, record ParticipationRecord) error {
	pk, _, err := resolveRollingPK(ctx, tx, record.ParticipationID)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, updateRegistrationFieldsSQL, record.EffectiveFirst, record.EffectiveLast, pk)
	return verifyExecWithOneRowEffected(err, result, "update registration fields")
}

// updateRollingFields sets all of the rolling fields according to the record
// object, persisting the voting secrets incrementally: the stored voting
// header is compared against the record's secrets, only the transition
// (consumed subkey rows, refreshed offsets) is written, and the new header
// travels in the same UPDATE as the rolling fields.
func updateRollingFields(ctx context.Context, tx *sql.Tx, record ParticipationRecord) error {
	pk, rawHeader, err := resolveRollingPK(ctx, tx, record.ParticipationID)
	if err != nil {
		return err
	}

	// A record stored without voting secrets (a NULL header and no rows)
	// carries a zero-value placeholder in the cache, since Duplicate never
	// hands out a nil Voting: nothing to persist for it.
	var newHeader *crypto.OneTimeSignatureSecretsHeader
	var snap crypto.OneTimeSignatureSecretsPersistent
	if record.Voting != nil {
		snap = votingSnapshot(record.Voting)
	}
	if record.Voting != nil && (len(rawHeader) > 0 || snap.Header() != (crypto.OneTimeSignatureSecretsHeader{})) {
		// Fail closed: without the stored cursor there is no way to tell
		// whether memory lags storage, and rewriting from memory could
		// resurrect keys the registry already retired.
		stored, herr := decodeVotingHeader(rawHeader)
		if herr != nil {
			return fmt.Errorf("stored voting header for key %s is undecodable; refusing to rewrite voting rows from memory (delete %s and restart to rebuild the registry): %v",
				record.ParticipationID, config.ParticipationRegistryFilename, herr)
		}
		newHeader, err = syncVotingRows(tx, registryVotingTarget(pk), stored, snap)
		if err != nil {
			return err
		}
	}

	// one UPDATE per record: the rolling fields, plus the voting header when
	// the transition produced a new one (NULL keeps the stored header)
	var rawNewHeader []byte
	if newHeader != nil {
		rawNewHeader = encodeVotingHeader(*newHeader)
	}
	result, err := tx.ExecContext(ctx, updateRollingFieldsSQL,
		record.LastVote, record.LastBlockProposal, record.LastStateProof,
		record.EffectiveFirst, record.EffectiveLast, rawNewHeader, pk)
	return verifyExecWithOneRowEffected(err, result, "update rolling fields")
}

func recordActive(record ParticipationRecord, on basics.Round) bool {
	return record.EffectiveLast != 0 && record.EffectiveFirst <= on && on <= record.EffectiveLast
}

// PKI TODO: Register needs a bit more work to make sure EffectiveFirst and
//
//	EffectiveLast are set at the right time. Specifically, the node
//	doesn't call Register until the key becomes active and is about
//	to be used, so effective first/last is updated just-in-time. It
//	would be better to update them when the KeyRegistration occurs.
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
		db.writeQueue <- makeOpRequest(&registerOp{updated: updated})

		// Merge only the registration window into the live cache entries.
		// The snapshots in updated predate this lock: a DeleteExpired in
		// between may have advanced the cached voting secrets, and
		// overwriting them would rewind the cache.  The dirty flags stay
		// set — registration persists nothing else, so pending changes
		// still need the next flush.
		db.mutex.Lock()
		for id, record := range updated {
			current, ok := db.cache[id]
			if !ok {
				// deleted meanwhile; do not resurrect it in the cache
				continue
			}
			current.EffectiveFirst = record.EffectiveFirst
			current.EffectiveLast = record.EffectiveLast
			db.cache[id] = current
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
	writeRecord := makeOpRequestWithError(&flushOp{}, resultCh)

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
		db.log.Warnf("participationDB unhandled error during Close/Flush: %v", err)
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
