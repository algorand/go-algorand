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

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/util/db"
)

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

// ParticipationIDNotFoundErr is used when attempting to update a set of keys which do not exist.
var ParticipationIDNotFoundErr error

func init() {
	ParticipationIDNotFoundErr = errors.New("the participation ID was not found")
}

// ParticipationRegistry contain all functions for interacting with the Participation Registry.
type ParticipationRegistry interface {
	// Insert adds a record to storage and computes the ParticipationID
	Insert(record ParticipationRecord) (ParticipationID, error)

	// Delete removes a record from storage.
	Delete(id ParticipationID) error

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

// dbSchemaUpgrade0 initializes the tables
func dbSchemaUpgrade0(ctx context.Context, tx *sql.Tx, newDatabase bool) error {
	// Keysets is for the immutable data, Rolling may change over time.
	tableSchema := []string {
		`CREATE TABLE Keysets (
			pk INTEGER,

			participationID BLOB
			account BLOB,

			firstValidRound INTEGER,
			lastValidRound INTEGER,
			keyDilution INTEGER NOT NULL DEFAULT 0

			--vrf BLOB,    --*  msgpack encoding of ParticipationAccount.vrf
		);`,
		`CREATE TABLE Rolling (
			pk INTEGER,

			lastVoteRound INTEGER,
			lastBlockProposalRound INTEGER,
			lastCompactCertificateRound INTEGER,
			effectiveFirstValidRound INTEGER,
			effectiveLastValidRound INTEGER,

			--voting BLOB, --*  msgpack encoding of ParticipationAccount.voting
		);`,
	}

	for _, tableCreate := range tableSchema {
		_, err := tx.Exec(tableCreate)
		if err != nil {
			return err
		}
	}

	return nil
}

// participationDB is a private implementation of ParticipationRegistry.
type participationDB struct {
	store db.Accessor
}

func (db *participationDB) Insert(record ParticipationRecord) (ParticipationID, error) {
	return ParticipationID{}, nil
}

func (db *participationDB) Delete(id ParticipationID) error {
	return nil
}

func (db *participationDB) Register(id ParticipationID, on basics.Round) error {
	return nil
}

func (db *participationDB) Record(account basics.Address, round basics.Round, participationType ParticipationAction) error {
	return nil
}
