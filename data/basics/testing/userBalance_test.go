// Copyright (C) 2019-2025 Algorand, Inc.
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

package testing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// Helper function to create a sample account data for testing
func getSampleAccountData() basics.AccountData {
	oneTimeSecrets := crypto.GenerateOneTimeSignatureSecrets(0, 1)
	vrfSecrets := crypto.GenerateVRFSecrets()
	var stateProofID merklesignature.Commitment
	crypto.RandBytes(stateProofID[:])

	return basics.AccountData{
		Status:             basics.NotParticipating,
		MicroAlgos:         basics.MicroAlgos{},
		RewardsBase:        0x1234123412341234,
		RewardedMicroAlgos: basics.MicroAlgos{},
		VoteID:             oneTimeSecrets.OneTimeSignatureVerifier,
		SelectionID:        vrfSecrets.PK,
		StateProofID:       stateProofID,
		VoteFirstValid:     basics.Round(0x1234123412341234),
		VoteLastValid:      basics.Round(0x1234123412341234),
		VoteKeyDilution:    0x1234123412341234,
		AssetParams:        make(map[basics.AssetIndex]basics.AssetParams),
		Assets:             make(map[basics.AssetIndex]basics.AssetHolding),
		AppLocalStates:     make(map[basics.AppIndex]basics.AppLocalState),
		AppParams:          make(map[basics.AppIndex]basics.AppParams),
		AuthAddr:           basics.Address(crypto.Hash([]byte{1, 2, 3, 4})),
		IncentiveEligible:  true,
	}
}

func TestOnlineAccountData(t *testing.T) {
	partitiontest.PartitionTest(t)

	ad := getSampleAccountData()
	ad.MicroAlgos.Raw = 1000000
	ad.Status = basics.Offline

	oad := OnlineAccountData(ad)
	require.Empty(t, oad)

	ad.Status = basics.Online
	oad = OnlineAccountData(ad)
	require.Equal(t, ad.MicroAlgos, oad.MicroAlgosWithRewards)
	require.Equal(t, ad.VoteID, oad.VoteID)
	require.Equal(t, ad.SelectionID, oad.SelectionID)
	require.Equal(t, ad.IncentiveEligible, oad.IncentiveEligible)
}
