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

package v2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestConvertAccountOverride(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	authAddr := basics.Address{1}
	authAddrStr := authAddr.String()
	voteKey := make([]byte, 32)
	voteKey[0] = 2
	selectionKey := make([]byte, 32)
	selectionKey[0] = 3
	stateProofKey := make([]byte, 64)
	stateProofKey[0] = 4
	balance := uint64(5)
	first, last := basics.Round(6), basics.Round(7)
	dilution := uint64(8)
	yes := true
	lastProposed, lastHeartbeat := basics.Round(9), basics.Round(10)
	status := "Online"

	override, err := convertAccountOverride(model.SimulateAccountOverride{
		Balance:                   &balance,
		AuthAddr:                  &authAddrStr,
		Status:                    &status,
		VoteParticipationKey:      &voteKey,
		SelectionParticipationKey: &selectionKey,
		StateProofKey:             &stateProofKey,
		VoteFirstValid:            &first,
		VoteLastValid:             &last,
		VoteKeyDilution:           &dilution,
		IncentiveEligible:         &yes,
		LastProposed:              &lastProposed,
		LastHeartbeat:             &lastHeartbeat,
	})
	require.NoError(t, err)
	online := basics.Online
	require.Equal(t, simulation.AccountOverride{
		Balance:           &basics.MicroAlgos{Raw: balance},
		AuthAddr:          &authAddr,
		Status:            &online,
		VoteID:            &crypto.OneTimeSignatureVerifier{2},
		SelectionID:       &crypto.VRFVerifier{3},
		StateProofID:      &merklesignature.Commitment{4},
		VoteFirstValid:    &first,
		VoteLastValid:     &last,
		VoteKeyDilution:   &dilution,
		IncentiveEligible: &yes,
		LastProposed:      &lastProposed,
		LastHeartbeat:     &lastHeartbeat,
	}, override)

	// Omitted fields are left unset
	override, err = convertAccountOverride(model.SimulateAccountOverride{})
	require.NoError(t, err)
	require.Equal(t, simulation.AccountOverride{}, override)

	statuses := map[string]basics.Status{
		"Offline":           basics.Offline,
		"Online":            basics.Online,
		"NotParticipating":  basics.NotParticipating,
		"Not Participating": basics.NotParticipating,
	}
	for str, expected := range statuses {
		override, err = convertAccountOverride(model.SimulateAccountOverride{Status: &str})
		require.NoError(t, err, str)
		require.Equal(t, expected, *override.Status, str)
	}

	badStatus := "Asleep"
	badAddr := "not an address"
	short := []byte{1}
	invalid := []struct {
		name     string
		override model.SimulateAccountOverride
		expected string
	}{
		{"bad status", model.SimulateAccountOverride{Status: &badStatus}, "unknown account status"},
		{"bad auth addr", model.SimulateAccountOverride{AuthAddr: &badAddr}, "auth addr"},
		{"short vote key", model.SimulateAccountOverride{VoteParticipationKey: &short}, "vote participation key must be 32 bytes"},
		{"short selection key", model.SimulateAccountOverride{SelectionParticipationKey: &short}, "selection participation key must be 32 bytes"},
		{"short state proof key", model.SimulateAccountOverride{StateProofKey: &short}, "state proof key must be 64 bytes"},
	}
	for _, tc := range invalid {
		_, err = convertAccountOverride(tc.override)
		require.ErrorContains(t, err, tc.expected, tc.name)
	}
}
