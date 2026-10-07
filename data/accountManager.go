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

package data

import (
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

	// Map to keep track of accounts for which we've sent
	// AccountRegistered telemetry events
	// syncronized by mu
	registeredAccounts map[string]bool

	registry account.ParticipationRegistry
	log      logging.Logger
}

// DeleteStateProofKey deletes keys related to a ParticipationID. The function removes
// all keys up to, and not including, the given round.
func (manager *AccountManager) DeleteStateProofKey(id account.ParticipationID, round basics.Round) error {
	return manager.registry.DeleteStateProofKeys(id, round)
}

// MakeAccountManager creates a new AccountManager with a custom logger
func MakeAccountManager(log logging.Logger, registry account.ParticipationRegistry) *AccountManager {
	manager := &AccountManager{}
	manager.log = log
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
				manager.log.Warnf("error while loading round secrets from participation registry: %v", err)
				continue
			}
			out = append(out, partRndSecrets)
		}
	}
	return out
}

// StateProofKeys returns a list of Participation accounts, and their stateproof secrets
func (manager *AccountManager) StateProofKeys(rnd basics.Round) (out []account.StateProofSecretsForRound) {
	for _, part := range manager.registry.GetAll() {
		if part.StateProof != nil && part.OverlapsInterval(rnd, rnd) {
			partRndSecrets, err := manager.registry.GetStateProofSecretsForRound(part.ParticipationID, rnd)
			if err != nil {
				manager.log.Warnf("could not load state proof keys from participation registry: %v", err)
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

// AddParticipation adds a new account.Participation to the participation
// registry. The return value indicates if the key has been added (true) or
// if this is a duplicate key (false).
func (manager *AccountManager) AddParticipation(participation account.Participation) bool {
	// Tell the ParticipationRegistry about the Participation. Duplicate entries
	// are ignored.
	pid, err := manager.registry.Insert(participation)
	if err != nil && err != account.ErrAlreadyInserted {
		manager.log.Warnf("Failed to insert participation key.")
	}

	if err == account.ErrAlreadyInserted {
		return false
	}

	manager.log.Infof("Inserted key (%s) for account (%s) first valid (%d) last valid (%d)\n",
		pid, participation.Parent, participation.FirstValid, participation.LastValid)

	manager.mu.Lock()
	defer manager.mu.Unlock()

	address := participation.Address()

	first, last := participation.ValidInterval()

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
	if err := manager.registry.DeleteExpired(latestHdr.Round, agreementProto); err != nil {
		manager.log.Warnf("error while deleting expired records from participation registry: %v", err)
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
		manager.log.Warnf("node.Record: Account %v not able to record participation (%d) on round %d: %v", account, participationType, round, err)
	}
}
