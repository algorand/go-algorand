// Copyright (C) 2019-2020 Algorand, Inc.
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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

func TestAccount(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusFuture]
	appIdx := basics.AppIndex(1)
	round := basics.Round(2)

	params := basics.AppParams{
		ApprovalProgram: []byte{1},
		StateSchemas: basics.StateSchemas{
			GlobalStateSchema: basics.StateSchema{NumUint: 1},
		},
	}
	a := basics.AccountData{
		Status:             basics.Online,
		MicroAlgos:         basics.MicroAlgos{Raw: 80000000},
		RewardedMicroAlgos: basics.MicroAlgos{Raw: ^uint64(0)},
		RewardsBase:        0,
		AppParams:          map[basics.AppIndex]basics.AppParams{appIdx: params},
		AppLocalStates: map[basics.AppIndex]basics.AppLocalState{
			appIdx: {
				Schema: basics.StateSchema{NumUint: 10},
				KeyValue: basics.TealKeyValue{
					"uint":  basics.TealValue{Type: basics.TealUintType, Uint: 2},
					"bytes": basics.TealValue{Type: basics.TealBytesType, Bytes: "value"},
				},
			},
		},
	}
	b := a.WithUpdatedRewards(proto, 100)

	addr := basics.Address{}.String()
	conv, err := AccountDataToAccount(addr, &b, map[basics.AssetIndex]string{}, round, a.MicroAlgos)
	require.NoError(t, err)
	require.Equal(t, conv.Address, addr)
	require.Equal(t, conv.Amount, b.MicroAlgos.Raw)
	require.Equal(t, conv.AmountWithoutPendingRewards, a.MicroAlgos.Raw)
	require.NotNil(t, conv.CreatedApps)
	require.Equal(t, 1, len(*conv.CreatedApps))
	app := (*conv.CreatedApps)[0]
	require.Equal(t, uint64(appIdx), app.Id)
	require.Equal(t, params.ApprovalProgram, app.Params.ApprovalProgram)
	require.Equal(t, params.GlobalStateSchema.NumUint, app.Params.GlobalStateSchema.NumUint)
	require.Equal(t, params.GlobalStateSchema.NumByteSlice, app.Params.GlobalStateSchema.NumByteSlice)
	require.NotNil(t, conv.AppsLocalState)
	require.Equal(t, 1, len(*conv.AppsLocalState))

	ls := (*conv.AppsLocalState)[0]
	require.Equal(t, uint64(appIdx), ls.Id)
	require.Equal(t, uint64(10), ls.Schema.NumUint)
	require.Equal(t, uint64(0), ls.Schema.NumByteSlice)
	require.Equal(t, 2, len(*(ls.KeyValue)))
	value1 := generated.TealKeyValue{
		Key: "uint",
		Value: generated.TealValue{
			Type: uint64(basics.TealUintType),
			Uint: 2,
		},
	}
	value2 := generated.TealKeyValue{
		Key: "bytes",
		Value: generated.TealValue{
			Type:  uint64(basics.TealBytesType),
			Bytes: "value",
		},
	}
	require.Contains(t, ls.KeyValue, value1)
	require.Contains(t, ls.KeyValue, value2)

	c, err := AccountToAccountData(&conv)
	require.NoError(t, err)
	require.Equal(t, b, c)
}
