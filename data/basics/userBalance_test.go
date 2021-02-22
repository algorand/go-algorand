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

package basics

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

func TestEmptyEncoding(t *testing.T) {
	var ub BalanceRecord
	require.Equal(t, 1, len(protocol.Encode(&ub)))
}

func TestRewards(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	accountAlgos := []MicroAlgos{{Raw: 0}, {Raw: 8000}, {Raw: 13000}, {Raw: 83000}}
	for _, accountAlgo := range accountAlgos {
		ad := AccountData{
			Status:             Online,
			MicroAlgos:         accountAlgo,
			RewardsBase:        100,
			RewardedMicroAlgos: MicroAlgos{Raw: 25},
		}

		levels := []uint64{uint64(0), uint64(1), uint64(30), uint64(3000)}
		for _, level := range levels {
			money, rewards := ad.Money(proto, ad.RewardsBase+level)
			require.Equal(t, money.Raw, ad.MicroAlgos.Raw+level*ad.MicroAlgos.RewardUnits(proto))
			require.Equal(t, rewards.Raw, ad.RewardedMicroAlgos.Raw+level*ad.MicroAlgos.RewardUnits(proto))
		}
	}
}

func TestWithUpdatedRewardsPanics(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	t.Run("AlgoPanic", func(t *testing.T) {
		paniced := false
		func() {
			defer func() {
				if err := recover(); err != nil {
					if strings.Contains(fmt.Sprintf("%v", err), "overflowed account balance when applying rewards") {
						paniced = true
					} else {
						panic(err)
					}
				}
			}()
			a := AccountData{
				Status:             Online,
				MicroAlgos:         MicroAlgos{Raw: ^uint64(0)},
				RewardedMicroAlgos: MicroAlgos{Raw: 0},
				RewardsBase:        0,
			}
			a.WithUpdatedRewards(proto, 100)
		}()
		require.Equal(t, true, paniced)
	})

	t.Run("RewardsOverflow", func(t *testing.T) {
		a := AccountData{
			Status:             Online,
			MicroAlgos:         MicroAlgos{Raw: 80000000},
			RewardedMicroAlgos: MicroAlgos{Raw: ^uint64(0)},
			RewardsBase:        0,
		}
		b := a.WithUpdatedRewards(proto, 100)
		require.Equal(t, 100*a.MicroAlgos.RewardUnits(proto)-1, b.RewardedMicroAlgos.Raw)
	})
}

func makeString(len int) string {
	s := ""
	for i := 0; i < len; i++ {
		s += string(byte(i))
	}
	return s
}

func TestEncodedAccountDataSize(t *testing.T) {
	oneTimeSecrets := crypto.GenerateOneTimeSignatureSecrets(0, 1)
	vrfSecrets := crypto.GenerateVRFSecrets()
	maxStateSchema := StateSchema{
		NumUint:      0x1234123412341234,
		NumByteSlice: 0x1234123412341234,
	}
	ad := AccountData{
		Status:             NotParticipating,
		MicroAlgos:         MicroAlgos{},
		RewardsBase:        0x1234123412341234,
		RewardedMicroAlgos: MicroAlgos{},
		VoteID:             oneTimeSecrets.OneTimeSignatureVerifier,
		SelectionID:        vrfSecrets.PK,
		VoteFirstValid:     Round(0x1234123412341234),
		VoteLastValid:      Round(0x1234123412341234),
		VoteKeyDilution:    0x1234123412341234,
		AssetParams:        make(map[AssetIndex]AssetParams),
		Assets:             make(map[AssetIndex]AssetHolding),
		AppLocalStates:     make(map[AppIndex]AppLocalState),
		AppParams:          make(map[AppIndex]AppParams),
		TotalAppSchema:     maxStateSchema,
		AuthAddr:           Address(crypto.Hash([]byte{1, 2, 3, 4})),
	}

	// TODO after applications enabled: change back to protocol.ConsensusCurrentVersion
	currentConsensusParams := config.Consensus[protocol.ConsensusFuture]

	for assetCreatorAssets := 0; assetCreatorAssets < currentConsensusParams.MaxAssetsPerAccount; assetCreatorAssets++ {
		ap := AssetParams{
			Total:         0x1234123412341234,
			Decimals:      0x12341234,
			DefaultFrozen: true,
			UnitName:      makeString(currentConsensusParams.MaxAssetUnitNameBytes),
			AssetName:     makeString(currentConsensusParams.MaxAssetNameBytes),
			URL:           makeString(currentConsensusParams.MaxAssetURLBytes),
			Manager:       Address(crypto.Hash([]byte{1, byte(assetCreatorAssets)})),
			Reserve:       Address(crypto.Hash([]byte{2, byte(assetCreatorAssets)})),
			Freeze:        Address(crypto.Hash([]byte{3, byte(assetCreatorAssets)})),
			Clawback:      Address(crypto.Hash([]byte{4, byte(assetCreatorAssets)})),
		}
		copy(ap.MetadataHash[:], makeString(32))
		ad.AssetParams[AssetIndex(0x1234123412341234-assetCreatorAssets)] = ap
	}

	for assetHolderAssets := 0; assetHolderAssets < currentConsensusParams.MaxAssetsPerAccount; assetHolderAssets++ {
		ah := AssetHolding{
			Amount: 0x1234123412341234,
			Frozen: true,
		}
		ad.Assets[AssetIndex(0x1234123412341234-assetHolderAssets)] = ah
	}

	maxProg := []byte(makeString(currentConsensusParams.MaxAppProgramLen))
	maxGlobalState := make(TealKeyValue, currentConsensusParams.MaxGlobalSchemaEntries)
	maxLocalState := make(TealKeyValue, currentConsensusParams.MaxLocalSchemaEntries)
	maxValue := TealValue{
		Type:  TealBytesType,
		Bytes: makeString(currentConsensusParams.MaxAppBytesValueLen),
	}

	for globalKey := uint64(0); globalKey < currentConsensusParams.MaxGlobalSchemaEntries; globalKey++ {
		prefix := fmt.Sprintf("%d|", globalKey)
		padding := makeString(currentConsensusParams.MaxAppKeyLen - len(prefix))
		maxKey := prefix + padding
		maxGlobalState[maxKey] = maxValue
	}

	for localKey := uint64(0); localKey < currentConsensusParams.MaxLocalSchemaEntries; localKey++ {
		prefix := fmt.Sprintf("%d|", localKey)
		padding := makeString(currentConsensusParams.MaxAppKeyLen - len(prefix))
		maxKey := prefix + padding
		maxLocalState[maxKey] = maxValue
	}

	for appCreatorApps := 0; appCreatorApps < currentConsensusParams.MaxAppsCreated; appCreatorApps++ {
		ap := AppParams{
			ApprovalProgram:   maxProg,
			ClearStateProgram: maxProg,
			GlobalState:       maxGlobalState,
			StateSchemas: StateSchemas{
				LocalStateSchema:  maxStateSchema,
				GlobalStateSchema: maxStateSchema,
			},
		}
		ad.AppParams[AppIndex(0x1234123412341234-appCreatorApps)] = ap
	}

	for appHolderApps := 0; appHolderApps < currentConsensusParams.MaxAppsOptedIn; appHolderApps++ {
		ls := AppLocalState{
			KeyValue: maxLocalState,
			Schema:   maxStateSchema,
		}
		ad.AppLocalStates[AppIndex(0x1234123412341234-appHolderApps)] = ls
	}

	encoded, err := ad.MarshalMsg(nil)
	require.NoError(t, err)
	require.GreaterOrEqual(t, MaxEncodedAccountDataSize, len(encoded))
}

func TestEncodedAccountAllocationBounds(t *testing.T) {
	// ensure that all the supported protocols have value limits less or
	// equal to their corresponding codec allocbounds
	for protoVer, proto := range config.Consensus {
		if proto.MaxAssetsPerAccount > EncodedMaxAssetsPerAccount {
			require.Failf(t, "proto.MaxAssetsPerAccount > EncodedMaxAssetsPerAccount", "protocol version = %s", protoVer)
		}
		if proto.MaxAppsCreated > EncodedMaxAppParams {
			require.Failf(t, "proto.MaxAppsCreated > encodedMaxAppParams", "protocol version = %s", protoVer)
		}
		if proto.MaxAppsOptedIn > EncodedMaxAppLocalStates {
			require.Failf(t, "proto.MaxAppsOptedIn > encodedMaxAppLocalStates", "protocol version = %s", protoVer)
		}
		if proto.MaxLocalSchemaEntries > EncodedMaxKeyValueEntries {
			require.Failf(t, "proto.MaxLocalSchemaEntries > encodedMaxKeyValueEntries", "protocol version = %s", protoVer)
		}
		if proto.MaxGlobalSchemaEntries > EncodedMaxKeyValueEntries {
			require.Failf(t, "proto.MaxGlobalSchemaEntries > encodedMaxKeyValueEntries", "protocol version = %s", protoVer)
		}
	}
}
