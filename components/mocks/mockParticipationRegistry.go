// Copyright (C) 2019-2024 Algorand, Inc.
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

package mocks

import (
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
)

// MockParticipationRegistry is a dummy ParticipationRegistry that doesn't do anything
type MockParticipationRegistry struct {
}

// Insert adds a record to storage and computes the ParticipationID
func (m *MockParticipationRegistry) Insert(record account.Participation) (account.ParticipationID, error) {
	return account.ParticipationID{}, nil
}

// AppendKeys appends state proof keys to an existing Participation record. Keys can only be appended
// once, an error will occur when the data is flushed when inserting a duplicate key.
func (m *MockParticipationRegistry) AppendKeys(id account.ParticipationID, keys account.StateProofKeys) error {
	return nil
}

// Delete removes a record from storage.
func (m *MockParticipationRegistry) Delete(id account.ParticipationID) error {
	return nil
}

// DeleteStateProofKeys removes all stateproof keys preceding a given round (including)
func (m *MockParticipationRegistry) DeleteStateProofKeys(id account.ParticipationID, round basics.Round) error {
	return nil
}

// DeleteExpired removes all records from storage which are expired on the given round.
func (m *MockParticipationRegistry) DeleteExpired(latestRound basics.Round, agreementProto config.ConsensusParams) error {
	return nil
}

// Get a participation record.
func (m *MockParticipationRegistry) Get(id account.ParticipationID) account.ParticipationRecord {
	return account.ParticipationRecord{}
}

// GetAll of the participation records.
func (m *MockParticipationRegistry) GetAll() []account.ParticipationRecord {
	return []account.ParticipationRecord{}
}

// GetForRound fetches a record with voting secrets for a particular round.
func (m *MockParticipationRegistry) GetForRound(id account.ParticipationID, round basics.Round) (account.ParticipationRecordForRound, error) {
	return account.ParticipationRecordForRound{}, nil
}

// GetStateProofSecretsForRound fetches a record with stateproof secrets for a particular round.
func (m *MockParticipationRegistry) GetStateProofSecretsForRound(id account.ParticipationID, round basics.Round) (account.StateProofSecretsForRound, error) {
	return account.StateProofSecretsForRound{}, nil
}

// HasLiveKeys quickly tests to see if there is a valid participation key over some range of rounds
func (m *MockParticipationRegistry) HasLiveKeys(from, to basics.Round) bool {
	return false
}

// Register updates the EffectiveFirst and EffectiveLast fields. If there are multiple records for the account
// then it is possible for multiple records to be updated.
func (m *MockParticipationRegistry) Register(id account.ParticipationID, on basics.Round) error {
	return nil
}

// Record sets the Last* field for the active ParticipationID for the given account.
func (m *MockParticipationRegistry) Record(account basics.Address, round basics.Round, participationType account.ParticipationAction) error {
	return nil
}

// Flush ensures that all changes have been written to the underlying data store.
func (m *MockParticipationRegistry) Flush(timeout time.Duration) error {
	return nil
}

// Close any resources used to implement the interface.
func (m *MockParticipationRegistry) Close() {

}
