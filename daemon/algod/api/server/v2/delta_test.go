// Copyright (C) 2019-2023 Algorand, Inc.
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
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var txLease = [32]byte{}

func TestDelta(t *testing.T) {
	partitiontest.PartitionTest(t)
	original := ledgercore.StateDelta{
		Accts: ledgercore.AccountDeltas{
			Accts: []ledgercore.BalanceRecord{
				{
					Addr: poolAddr,
					AccountData: ledgercore.AccountData{
						AccountBaseData: ledgercore.AccountBaseData{
							Status:              0,
							MicroAlgos:          basics.MicroAlgos{Raw: 5000},
							RewardsBase:         2,
							RewardedMicroAlgos:  basics.MicroAlgos{Raw: 0},
							TotalExtraAppPages:  0,
							TotalAppParams:      0,
							TotalAppLocalStates: 0,
							TotalAssetParams:    0,
							TotalAssets:         0,
							TotalBoxes:          0,
							TotalBoxBytes:       0,
						},
					},
				},
			},
			AppResources: []ledgercore.AppResourceRecord{
				{
					Aidx: basics.AppIndex(2),
					Addr: poolAddr,
					Params: ledgercore.AppParamsDelta{
						Params: &basics.AppParams{
							ApprovalProgram:   []byte("1"),
							ClearStateProgram: []byte("2"),
							GlobalState:       basics.TealKeyValue{},
							StateSchemas:      basics.StateSchemas{},
							ExtraProgramPages: 0,
						},
						Deleted: false,
					},
				},
			},
			AssetResources: []ledgercore.AssetResourceRecord{
				{
					Aidx: basics.AssetIndex(1),
					Addr: poolAddr,
					Params: ledgercore.AssetParamsDelta{
						Params:  nil,
						Deleted: true,
					},
				},
			},
		},
		KvMods: map[string]ledgercore.KvValueDelta{
			"box1": {
				Data:    []byte("foobar"),
				OldData: []byte("barfoo"),
			},
		},
		Txleases: map[ledgercore.Txlease]basics.Round{
			{Sender: poolAddr, Lease: txLease}: 600,
		},
		Creatables: map[basics.CreatableIndex]ledgercore.ModifiedCreatable{},
		Hdr: &bookkeeping.BlockHeader{
			Round:     4,
			TimeStamp: 0,
			RewardsState: bookkeeping.RewardsState{
				FeeSink:                   basics.Address{},
				RewardsPool:               basics.Address{},
				RewardsLevel:              500,
				RewardsRate:               510,
				RewardsResidue:            0,
				RewardsRecalculationRound: 0,
			},
		},
		PrevTimestamp: 10,
		Totals:        ledgercore.AccountTotals{},
	}

	converted, err := stateDeltaToLedgerDelta(original, config.Consensus[protocol.ConsensusCurrentVersion], 25, 4)
	require.NoError(t, err)
	require.Equal(t, original.Accts.Len(), len(*converted.Accts.Accounts))
	expAccDelta := original.Accts.Accts[0]
	actAccDelta := (*converted.Accts.Accounts)[0]
	require.Equal(t, expAccDelta.Addr.String(), actAccDelta.Address)
	require.Equal(t, expAccDelta.Status.String(), actAccDelta.AccountData.Status)
	require.Equal(t, uint64(0), actAccDelta.AccountData.PendingRewards)
	require.Equal(t, len(original.Accts.AssetResources), len(*converted.Accts.Assets))
	expAssetDelta := original.Accts.AssetResources[0]
	actAssetDelta := (*converted.Accts.Assets)[0]
	require.Equal(t, uint64(expAssetDelta.Aidx), actAssetDelta.AssetIndex)
	require.Equal(t, expAssetDelta.Addr.String(), actAssetDelta.Address)
	require.Equal(t, expAssetDelta.Params.Deleted, actAssetDelta.AssetDeleted)
	require.Equal(t, expAssetDelta.Holding.Deleted, actAssetDelta.AssetHoldingDeleted)
	require.Equal(t, len(original.Accts.AppResources), len(*converted.Accts.Apps))
	expAppDelta := original.Accts.AppResources[0]
	actAppDelta := (*converted.Accts.Apps)[0]
	require.Equal(t, uint64(expAppDelta.Aidx), actAppDelta.AppIndex)
	require.Equal(t, expAppDelta.Addr.String(), actAppDelta.Address)
	require.Equal(t, expAppDelta.Params.Deleted, actAppDelta.AppDeleted)
	require.Equal(t, len(original.KvMods), len(*converted.KvMods))
	require.Equal(t, []uint8("box1"), *(*converted.KvMods)[0].Key)
	require.Equal(t, original.KvMods["box1"].Data, *(*converted.KvMods)[0].Value)
	require.Equal(t, txLease[:], (*converted.TxLeases)[0].Lease)
	require.Equal(t, poolAddr.String(), (*converted.TxLeases)[0].Sender)
	require.Equal(t, uint64(600), (*converted.TxLeases)[0].Expiration)
	require.Nil(t, converted.StateProofNext)
	require.Equal(t, uint64(10), *converted.PrevTimestamp)
	require.Equal(t, model.AccountTotals{}, *converted.Totals)
}
