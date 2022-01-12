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

package agreementtest

import (
	"github.com/algorand/go-algorand/crypto/merklekeystore"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
)

// SimpleKeyManager provides a simple implementation of a KeyManager for unit tests.
type SimpleKeyManager []account.Participation

// VotingKeys implements KeyManager.VotingKeys.
func (m SimpleKeyManager) VotingKeys(votingRound, _ basics.Round) []account.ParticipationRecordForRound {
	var km []account.ParticipationRecordForRound
	for _, acc := range m {
		if acc.OverlapsInterval(votingRound, votingRound) {
			record := account.ParticipationRecord{
				ParticipationID:   acc.ID(),
				Account:           acc.Parent,
				FirstValid:        acc.FirstValid,
				LastValid:         acc.LastValid,
				KeyDilution:       acc.KeyDilution,
				LastVote:          0,
				LastBlockProposal: 0,
				LastStateProof:    0,
				EffectiveFirst:    acc.FirstValid,
				EffectiveLast:     acc.LastValid,
				VRF:               acc.VRF,
				Voting:            acc.Voting,
			}
			// Usually this struct will be retrieved from the registry, however in this test
			// case we can allow ourselves to generate it from the data already in memory
			// (within the Participation after calling FillDB)
			var stateproofSinger *merklekeystore.Signer
			stateproofSinger = nil
			if acc.StateProofSecrets != nil {
				stateproofSinger = acc.StateProofSecrets.GetSigner(uint64(votingRound))
			}
			partRecForRound := account.ParticipationRecordForRound{
				ParticipationRecord: record,
				StateProofSecrets:   stateproofSinger,
			}
			km = append(km, partRecForRound)
		}
	}
	return km
}

// DeleteOldKeys implements KeyManager.DeleteOldKeys.
func (m SimpleKeyManager) DeleteOldKeys(r basics.Round) {
}

// Record implements KeyManager.Record.
func (m SimpleKeyManager) Record(account basics.Address, round basics.Round, action account.ParticipationAction) {
}
