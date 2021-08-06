package agreement

import (
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
)

func makeRecordingKeyManager(accounts []account.Participation) recordingKeyManager {
	return recordingKeyManager{
		keys: accounts,
		recording: make(map[basics.Address]map[account.ParticipationAction]basics.Round),
	}
}

// recordingKeyManager provides a simple implementation of a KeyManager for unit tests.
type recordingKeyManager struct {
	keys []account.Participation
	recording map[basics.Address]map[account.ParticipationAction]basics.Round
}

// VotingKeys implements KeyManager.VotingKeys.
func (m recordingKeyManager) VotingKeys(votingRound, _ basics.Round) []account.Participation {
	var km []account.Participation
	for _, acc := range m.keys {
		if acc.OverlapsInterval(votingRound, votingRound) {
			km = append(km, acc)
		}
	}
	return km
}

// DeleteOldKeys implements KeyManager.DeleteOldKeys.
func (m recordingKeyManager) DeleteOldKeys(r basics.Round) {
}

// Record implements KeyManager.Record.
func (m recordingKeyManager) RecordAsync(acct basics.Address, round basics.Round, action account.ParticipationAction) {
	if _, ok := m.recording[acct]; !ok {
		m.recording[acct] = make(map[account.ParticipationAction]basics.Round)
	}
	m.recording[acct][action] = round
}
