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

package ledgercore

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

func TestAccountTotalsCanMarshalMsg(t *testing.T) {
	var at *AccountTotals
	require.True(t, at.CanMarshalMsg(interface{}(at)))
	require.False(t, at.CanMarshalMsg(interface{}(t)))
	require.True(t, at.CanUnmarshalMsg(interface{}(at)))
	require.False(t, at.CanUnmarshalMsg(interface{}(t)))
}
func TestAccountTotalsMarshalMsg(t *testing.T) {
	at := AccountTotals{
		Online: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340001},
			RewardUnits: 0x1234123412340002,
		},
		Offline: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340003},
			RewardUnits: 0x1234123412340004,
		},
		NotParticipating: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340005},
			RewardUnits: 0x1234123412340006,
		},
		RewardsLevel: 0x1234123412340007,
	}
	inBuffer := make([]byte, 0, 128)
	outBuffer := at.MarshalMsg(inBuffer)
	require.True(t, len(outBuffer) < cap(inBuffer))

	// allocate a buffer that is just the right size.
	inBuffer = make([]byte, len(outBuffer))
	outBuffer = at.MarshalMsg(inBuffer)
	require.True(t, len(outBuffer) > 0)
}

func TestAlgoCountMarshalMsg(t *testing.T) {
	ac := AlgoCount{
		Money:       basics.MicroAlgos{Raw: 0x4321432143214321},
		RewardUnits: 0x1234123412341234,
	}
	inBuffer := make([]byte, 0, 128)
	outBuffer := ac.MarshalMsg(inBuffer)
	require.Truef(t, len(outBuffer) > len(inBuffer), "len(outBuffer) : %d\nlen(inBuffer): %d\n", len(outBuffer), len(inBuffer))

	// allocate a buffer that is just the right size.
	inBuffer = make([]byte, len(outBuffer))
	outBuffer = ac.MarshalMsg(inBuffer)
	require.True(t, len(outBuffer) > 0)
}

var uniqueAccountTotals = []AccountTotals{
	{
		Online: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		Offline: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		NotParticipating: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		RewardsLevel: 0x1234123412340000,
	},
	{
		Online: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340001},
			RewardUnits: 0x1234123412340000,
		},
		Offline: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		NotParticipating: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		RewardsLevel: 0x1234123412340000,
	},
	{
		Online: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340001,
		},
		Offline: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		NotParticipating: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		RewardsLevel: 0x1234123412340000,
	},
	{
		Online: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		Offline: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340001},
			RewardUnits: 0x1234123412340000,
		},
		NotParticipating: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		RewardsLevel: 0x1234123412340000,
	},
	{
		Online: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		Offline: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340001,
		},
		NotParticipating: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		RewardsLevel: 0x1234123412340000,
	},
	{
		Online: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		Offline: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		NotParticipating: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340001},
			RewardUnits: 0x1234123412340000,
		},
		RewardsLevel: 0x1234123412340000,
	},
	{
		Online: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		Offline: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		NotParticipating: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340001,
		},
		RewardsLevel: 0x1234123412340000,
	},
	{
		Online: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		Offline: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		NotParticipating: AlgoCount{
			Money:       basics.MicroAlgos{Raw: 0x1234123412340000},
			RewardUnits: 0x1234123412340000,
		},
		RewardsLevel: 0x1234123412340001,
	},
}

func TestAccountTotalsMarshalMsgUnique(t *testing.T) {
	uniqueAt := make(map[crypto.Digest]bool, 0)
	for _, at := range uniqueAccountTotals {
		inBuffer := make([]byte, 0, 128)
		outBuffer := at.MarshalMsg(inBuffer)
		outBufDigest := crypto.Hash(outBuffer)
		require.False(t, uniqueAt[outBufDigest])
		uniqueAt[outBufDigest] = true
	}
}

func TestAccountTotalsMarshalUnMarshal(t *testing.T) {
	for _, at := range uniqueAccountTotals {
		inBuffer := make([]byte, 0, 128)
		outBuffer := at.MarshalMsg(inBuffer)
		var at2 AccountTotals
		_, err := at2.UnmarshalMsg(outBuffer)
		require.NoError(t, err)
		require.Equal(t, at, at2)
	}
}
