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

package agreement

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
)

func makeRecordingKeyManager(accounts []account.Participation) *recordingKeyManager {
	return &recordingKeyManager{
		keys:      accounts,
		recording: make(map[basics.Address]map[account.ParticipationAction]basics.Round),
	}
}

// recordingKeyManager provides a simple implementation of a KeyManager for unit tests.
type recordingKeyManager struct {
	keys      []account.Participation
	recording map[basics.Address]map[account.ParticipationAction]basics.Round
	mutex     deadlock.Mutex
}

// VotingKeys implements KeyManager.VotingKeys.
func (m *recordingKeyManager) VotingKeys(votingRound, _ basics.Round) []account.ParticipationRecordForRound {
	var km []account.ParticipationRecordForRound
	for _, acc := range m.keys {
		if acc.OverlapsInterval(votingRound, votingRound) {
			partRecordForRound := account.ParticipationRecordForRound{
				ParticipationRecord: account.ParticipationRecord{
					ParticipationID:   acc.ID(),
					Account:           acc.Parent,
					FirstValid:        acc.FirstValid,
					LastValid:         acc.LastValid,
					KeyDilution:       acc.KeyDilution,
					LastVote:          0,
					LastBlockProposal: 0,
					LastStateProof:    0,
					EffectiveFirst:    0,
					EffectiveLast:     acc.LastValid,
					VRF:               acc.VRF,
					Voting:            acc.Voting,
				},
			}
			km = append(km, partRecordForRound)
		}
	}
	return km
}

// DeleteOldKeys implements KeyManager.DeleteOldKeys.
func (m *recordingKeyManager) DeleteOldKeys(r basics.Round) {
}

// Record implements KeyManager.Record.
func (m *recordingKeyManager) Record(acct basics.Address, round basics.Round, action account.ParticipationAction) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if _, ok := m.recording[acct]; !ok {
		m.recording[acct] = make(map[account.ParticipationAction]basics.Round)
	}
	m.recording[acct][action] = round
}

// ValidateVoteRound requires that the given address voted on a particular round.
func (m *recordingKeyManager) ValidateVoteRound(t *testing.T, address basics.Address, round basics.Round) {
	m.mutex.Lock()
	require.Equal(t, round, m.recording[address][account.Vote])
	require.Equal(t, round, m.recording[address][account.BlockProposal])
	m.mutex.Unlock()
}
