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

package data

import (
	"fmt"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
)

// AccountManager loads and manages accounts for the node
type AccountManager struct {
	mu deadlock.Mutex

	// syncronized by mu
	partKeys map[account.ParticipationKeyIdentity]account.PersistedParticipation

	// Map to keep track of accounts for which we've sent
	// AccountRegistered telemetry events
	// syncronized by mu
	registeredAccounts map[string]bool

	registry account.ParticipationRegistry
	log      logging.Logger
}

// MakeAccountManager creates a new AccountManager with a custom logger
func MakeAccountManager(log logging.Logger, registry account.ParticipationRegistry) *AccountManager {
	manager := &AccountManager{}
	manager.log = log
	manager.partKeys = make(map[account.ParticipationKeyIdentity]account.PersistedParticipation)
	manager.registeredAccounts = make(map[string]bool)
	manager.registry = registry

	return manager
}

// Keys returns a list of Participation accounts, and their keys/secrets for requested round.
func (manager *AccountManager) Keys(rnd basics.Round) (out []account.ParticipationRecordForRound) {
	for _, part := range manager.registry.GetAll() {
		if part.OverlapsInterval(rnd, rnd) {
			partRndSecrets, err := manager.registry.GetForRound(part.ParticipationID, rnd)
			if err != nil {
				manager.log.Warnf("error while loading round secrets from participation registry: %w", err)
				continue
			}
			out = append(out, partRndSecrets)
		}
	}
	return out
}

// StateProofKeys returns a list of Participation accounts, and their stateproof secrets
func (manager *AccountManager) StateProofKeys(rnd basics.Round) (out []account.StateProofRecordForRound) {
	for _, part := range manager.registry.GetAll() {
		if part.OverlapsInterval(rnd, rnd) {
			partRndSecrets, err := manager.registry.GetStateProofForRound(part.ParticipationID, rnd)
			if err != nil {
				manager.log.Warnf("error while loading round secrets from participation registry: %w", err)
				continue
			}
			out = append(out, partRndSecrets)
		}
	}
	return out
}

// HasLiveKeys returns true if we have any Participation
// keys valid for the specified round range (inclusive)
func (manager *AccountManager) HasLiveKeys(from, to basics.Round) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	return manager.registry.HasLiveKeys(from, to)
}

// AddParticipation adds a new account.Participation to be managed.
// The return value indicates if the key has been added (true) or
// if this is a duplicate key (false).
func (manager *AccountManager) AddParticipation(participation account.PersistedParticipation) bool {
	// Tell the ParticipationRegistry about the Participation. Duplicate entries
	// are ignored.
	pid, err := manager.registry.Insert(participation.Participation)
	if err != nil && err != account.ErrAlreadyInserted {
		manager.log.Warnf("Failed to insert participation key.")
	}
	manager.log.Infof("Inserted key (%s) for account (%s) first valid (%d) last valid (%d)\n",
		pid, participation.Parent, participation.FirstValid, participation.LastValid)

	manager.mu.Lock()
	defer manager.mu.Unlock()

	address := participation.Address()

	first, last := participation.ValidInterval()
	partkeyID := account.ParticipationKeyIdentity{
		Parent:      address,
		FirstValid:  first,
		LastValid:   last,
		VRFSK:       participation.VRF.SK,
		VoteID:      participation.Voting.OneTimeSignatureVerifier,
		KeyDilution: participation.KeyDilution,
	}

	// Check if we already have participation keys for this address in this interval
	_, alreadyPresent := manager.partKeys[partkeyID]
	if alreadyPresent {
		return false
	}

	manager.partKeys[partkeyID] = participation

	addressString := address.String()
	manager.log.EventWithDetails(telemetryspec.Accounts, telemetryspec.PartKeyRegisteredEvent, telemetryspec.PartKeyRegisteredEventDetails{
		Address:    addressString,
		FirstValid: uint64(first),
		LastValid:  uint64(last),
	})

	_, has := manager.registeredAccounts[addressString]
	if !has {
		manager.registeredAccounts[addressString] = true

		manager.log.EventWithDetails(telemetryspec.Accounts, telemetryspec.AccountRegisteredEvent, telemetryspec.AccountRegisteredEventDetails{
			Address: addressString,
		})
	}

	return true
}

// DeleteOldKeys deletes all accounts' ephemeral keys strictly older than the
// next round needed for each account.
func (manager *AccountManager) DeleteOldKeys(latestHdr bookkeeping.BlockHeader, agreementProto config.ConsensusParams) {
	manager.mu.Lock()
	pendingItems := make(map[string]<-chan error, len(manager.partKeys))

	partKeys := make([]account.PersistedParticipation, 0, len(manager.partKeys))
	for _, part := range manager.partKeys {
		partKeys = append(partKeys, part)
	}
	manager.mu.Unlock()
	for _, part := range partKeys {
		// We need a key for round r+1 for agreement.
		nextRound := latestHdr.Round + 1

		// we pre-create the reported error string here, so that we won't need to have the participation key object if error is detected.
		first, last := part.ValidInterval()
		errString := fmt.Sprintf("AccountManager.DeleteOldKeys(): key for %s (%d-%d), nextRound %d",
			part.Address().String(), first, last, nextRound)
		errCh := part.DeleteOldKeys(nextRound, agreementProto)

		pendingItems[errString] = errCh
	}

	// wait for all disk flushes, and report errors as they appear.
	for errString, errCh := range pendingItems {
		err := <-errCh
		if err != nil {
			logging.Base().Warnf("%s: %v", errString, err)
		}
	}

	// Delete expired records from participation registry.
	if err := manager.registry.DeleteExpired(latestHdr.Round, agreementProto); err != nil {
		manager.log.Warnf("error while deleting expired records from participation registry: %w", err)
	}
}

// Registry fetches the ParticipationRegistry.
func (manager *AccountManager) Registry() account.ParticipationRegistry {
	return manager.registry
}

// Record asynchronously records a participation key usage event.
func (manager *AccountManager) Record(account basics.Address, round basics.Round, participationType account.ParticipationAction) {
	// This function updates a cache in the ParticipationRegistry, we must call Flush to persist the changes.
	err := manager.registry.Record(account, round, participationType)
	if err != nil {
		manager.log.Warnf("node.Record: Account %v not able to record participation (%d) on round %d: %w", account, participationType, round, err)
	}
}
