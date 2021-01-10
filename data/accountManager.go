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

package data

import (
	"fmt"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
)

// AccountManager loads and manages accounts for the node
type AccountManager struct {
	mu deadlock.Mutex

	partIntervals map[account.ParticipationInterval]account.Participation

	// Map to keep track of accounts for which we've sent
	// AccountRegistered telemetry events
	registeredAccounts map[string]bool

	log logging.Logger
}

// MakeAccountManager creates a new AccountManager with a custom logger
func MakeAccountManager(log logging.Logger) *AccountManager {
	manager := &AccountManager{}
	manager.log = log
	manager.partIntervals = make(map[account.ParticipationInterval]account.Participation)
	manager.registeredAccounts = make(map[string]bool)

	return manager
}

// Keys returns a list of Participation accounts.
func (manager *AccountManager) Keys() (out []account.Participation) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	for _, part := range manager.partIntervals {
		out = append(out, part)
	}
	return out
}

// HasLiveKeys returns true if we have any Participation
// keys valid for the specified round range (inclusive)
func (manager *AccountManager) HasLiveKeys(from, to basics.Round) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	for _, part := range manager.partIntervals {
		if part.OverlapsInterval(from, to) {
			return true
		}
	}
	return false
}

// AddParticipation adds a new account.Participation to be managed.
// The return value indicates if the key has been added (true) or
// if this is a duplicate key (false).
func (manager *AccountManager) AddParticipation(participation account.Participation) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	address := participation.Address()

	first, last := participation.ValidInterval()
	interval := account.ParticipationInterval{
		Address:    address,
		FirstValid: first,
		LastValid:  last,
	}

	// Check if we already have participation keys for this address in this interval
	_, alreadyPresent := manager.partIntervals[interval]
	if alreadyPresent {
		return false
	}

	manager.partIntervals[interval] = participation

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
func (manager *AccountManager) DeleteOldKeys(nextRoundFunc func(account.Participation) basics.Round, proto config.ConsensusParams) {
	manager.mu.Lock()
	pendingItems := make(map[string]<-chan error, len(manager.partIntervals))
	func() {
		defer manager.mu.Unlock()
		for _, part := range manager.partIntervals {
			nextRound := nextRoundFunc(part)

			// we pre-create the reported error string here, so that we won't need to have the participation key object if error is detected.
			first, last := part.ValidInterval()
			errString := fmt.Sprintf("AccountManager.DeleteOldKeys(): key for %s (%d-%d), nextRound %d",
				part.Address().String(), first, last, nextRound)
			errCh := part.DeleteOldKeys(nextRound, proto)

			pendingItems[errString] = errCh
		}
	}()

	// wait all all disk flushes, and report errors as they appear.
	for errString, errCh := range pendingItems {
		err := <-errCh
		if err != nil {
			logging.Base().Warnf("%s: %v", errString, err)
		}
	}
}
