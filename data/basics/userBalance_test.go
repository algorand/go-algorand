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
	accountAlgos := []MicroAlgos{MicroAlgos{Raw: 0}, MicroAlgos{Raw: 8000}, MicroAlgos{Raw: 13000}, MicroAlgos{Raw: 83000}}
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
		SpendingKey:        Address(crypto.Hash([]byte{1, 2, 3, 4})),
	}
	currentConsensusParams := config.Consensus[protocol.ConsensusCurrentVersion]

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

	encoded, err := ad.MarshalMsg(nil)
	require.NoError(t, err)
	require.Equal(t, MaxEncodedAccountDataSize, len(encoded))
}
