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
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/protocol"
)

// AccountManager loads and manages accounts for the node
type AccountManager struct {
	mu deadlock.Mutex

	partKeys map[account.ParticipationKeyIdentity]account.PersistedParticipation

	// Map to keep track of accounts for which we've sent
	// AccountRegistered telemetry events
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

// Keys returns a list of Participation accounts.
func (manager *AccountManager) Keys(rnd basics.Round) (out []account.Participation) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	for _, part := range manager.partKeys {
		if part.OverlapsInterval(rnd, rnd) {
			out = append(out, part.Participation)
		}
	}
	return out

	// PKI TODO: source keys from the registry.
	// This kinda works, but voting keys are not updated.
	/*
		for _, record := range manager.registry.GetAll() {
			part := account.Participation{
				Parent:      record.Account,
				VRF:         record.VRF,
				Voting:      record.Voting,
				FirstValid:  record.FirstValid,
				LastValid:   record.LastValid,
				KeyDilution: record.KeyDilution,
			}

			if part.OverlapsInterval(rnd, rnd) {
				out = append(out, part)

				id := part.ID()
				if !bytes.Equal(id[:], record.ParticipationID[:]) {
					manager.log.Warnf("Participation IDs do not equal while fetching keys... %s != %s\n", id, record.ParticipationID)
				}
			}
		}
		return out
	*/
}

// HasLiveKeys returns true if we have any Participation
// keys valid for the specified round range (inclusive)
func (manager *AccountManager) HasLiveKeys(from, to basics.Round) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	for _, part := range manager.partKeys {
		if part.OverlapsInterval(from, to) {
			return true
		}
	}
	return false
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
func (manager *AccountManager) DeleteOldKeys(latestHdr bookkeeping.BlockHeader, ccSigs map[basics.Address]basics.Round, agreementProto config.ConsensusParams) {
	latestProto := config.Consensus[latestHdr.CurrentProtocol]

	manager.mu.Lock()
	pendingItems := make(map[string]<-chan error, len(manager.partKeys))
	func() {
		defer manager.mu.Unlock()
		for _, part := range manager.partKeys {
			// We need a key for round r+1 for agreement.
			nextRound := latestHdr.Round + 1

			if latestHdr.CompactCert[protocol.CompactCertBasic].CompactCertNextRound > 0 {
				// We need a key for the next compact cert round.
				// This would be CompactCertNextRound+1 (+1 because compact
				// cert code uses the next round's ephemeral key), except
				// if we already used that key to produce a signature (as
				// reported in ccSigs).
				nextCC := latestHdr.CompactCert[protocol.CompactCertBasic].CompactCertNextRound + 1
				if ccSigs[part.Parent] >= nextCC {
					nextCC = ccSigs[part.Parent] + basics.Round(latestProto.CompactCertRounds) + 1
				}

				if nextCC < nextRound {
					nextRound = nextCC
				}
			}

			// we pre-create the reported error string here, so that we won't need to have the participation key object if error is detected.
			first, last := part.ValidInterval()
			errString := fmt.Sprintf("AccountManager.DeleteOldKeys(): key for %s (%d-%d), nextRound %d",
				part.Address().String(), first, last, nextRound)
			errCh := part.DeleteOldKeys(nextRound, agreementProto)

			pendingItems[errString] = errCh
		}
	}()

	// wait for all disk flushes, and report errors as they appear.
	for errString, errCh := range pendingItems {
		err := <-errCh
		if err != nil {
			logging.Base().Warnf("%s: %v", errString, err)
		}
	}

	// PKI TODO: This needs to update the partkeys also, see the 'DeleteOldKeys' function above, it's part
	//       is part of PersistedParticipation, but just calls 'part.Voting.DeleteBeforeFineGrained'
	// Delete expired records from participation registry.
	if err := manager.registry.DeleteExpired(latestHdr.Round); err != nil {
		manager.log.Warnf("error while deleting expired records from participation registry: %w", err)
	}
}

// Registry fetches the ParticipationRegistry.
func (manager *AccountManager) Registry() account.ParticipationRegistry {
	return manager.registry
}

// FlushRegistry tells the underlying participation registry to flush it's change cache to the DB.
func (manager *AccountManager) FlushRegistry(timeout time.Duration) {
	err := manager.registry.Flush(timeout)
	if err != nil {
		manager.log.Warnf("error while flushing the registry: %w", err)
	}
}

// Record asynchronously records a participation key usage event.
func (manager *AccountManager) Record(account basics.Address, round basics.Round, participationType account.ParticipationAction) {
	// This function updates a cache in the ParticipationRegistry, we must call Flush to persist the changes.
	err := manager.registry.Record(account, round, participationType)
	if err != nil {
		manager.log.Warnf("node.Record: Account %v not able to record participation (%d) on round %d: %w", account, participationType, round, err)
	}
}
