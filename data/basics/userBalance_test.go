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

package basics

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestEmptyEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)

	var ub BalanceRecord
	require.Equal(t, 1, len(protocol.Encode(&ub)))
}

func TestRewards(t *testing.T) {
	partitiontest.PartitionTest(t)

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
	partitiontest.PartitionTest(t)

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

func getSampleAccountData() AccountData {
	oneTimeSecrets := crypto.GenerateOneTimeSignatureSecrets(0, 1)
	vrfSecrets := crypto.GenerateVRFSecrets()
	var stateProofID merklesignature.Commitment
	crypto.RandBytes(stateProofID[:])

	return AccountData{
		Status:             NotParticipating,
		MicroAlgos:         MicroAlgos{},
		RewardsBase:        0x1234123412341234,
		RewardedMicroAlgos: MicroAlgos{},
		VoteID:             oneTimeSecrets.OneTimeSignatureVerifier,
		SelectionID:        vrfSecrets.PK,
		StateProofID:       stateProofID,
		VoteFirstValid:     Round(0x1234123412341234),
		VoteLastValid:      Round(0x1234123412341234),
		VoteKeyDilution:    0x1234123412341234,
		AssetParams:        make(map[AssetIndex]AssetParams),
		Assets:             make(map[AssetIndex]AssetHolding),
		AppLocalStates:     make(map[AppIndex]AppLocalState),
		AppParams:          make(map[AppIndex]AppParams),
		AuthAddr:           Address(crypto.Hash([]byte{1, 2, 3, 4})),
		IncentiveEligible:  true,
	}
}

func TestEncodedAccountAllocationBounds(t *testing.T) {
	partitiontest.PartitionTest(t)

	// ensure that all the supported protocols have value limits less or
	// equal to their corresponding codec allocbounds
	for protoVer, proto := range config.Consensus {
		if proto.MaxAssetsPerAccount > 0 && proto.MaxAssetsPerAccount > encodedMaxAssetsPerAccount {
			require.Failf(t, "proto.MaxAssetsPerAccount > encodedMaxAssetsPerAccount", "protocol version = %s", protoVer)
		}
		if proto.MaxAppsCreated > 0 && proto.MaxAppsCreated > EncodedMaxAppParams {
			require.Failf(t, "proto.MaxAppsCreated > encodedMaxAppParams", "protocol version = %s", protoVer)
		}
		if proto.MaxAppsOptedIn > 0 && proto.MaxAppsOptedIn > EncodedMaxAppLocalStates {
			require.Failf(t, "proto.MaxAppsOptedIn > encodedMaxAppLocalStates", "protocol version = %s", protoVer)
		}
		if proto.MaxLocalSchemaEntries > EncodedMaxKeyValueEntries {
			require.Failf(t, "proto.MaxLocalSchemaEntries > encodedMaxKeyValueEntries", "protocol version = %s", protoVer)
		}
		if proto.MaxGlobalSchemaEntries > EncodedMaxKeyValueEntries {
			require.Failf(t, "proto.MaxGlobalSchemaEntries > encodedMaxKeyValueEntries", "protocol version = %s", protoVer)
		}
		// There is no protocol limit to the number of Boxes per account, so that allocbound is not checked.
	}
}

func TestAppIndexHashing(t *testing.T) {
	partitiontest.PartitionTest(t)

	i := AppIndex(12)
	prefix, buf := i.ToBeHashed()
	require.Equal(t, protocol.HashID("appID"), prefix)
	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c}, buf)

	i = AppIndex(12 << 16)
	prefix, buf = i.ToBeHashed()
	require.Equal(t, protocol.HashID("appID"), prefix)
	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00}, buf)

	// test value created with:
	// python -c "import algosdk.encoding as e; print(e.encode_address(e.checksum(b'appID'+($APPID).to_bytes(8, 'big'))))"
	i = AppIndex(77)
	require.Equal(t, "PCYUFPA2ZTOYWTP43MX2MOX2OWAIAXUDNC2WFCXAGMRUZ3DYD6BWFDL5YM", i.Address().String())
}

func TestOnlineAccountData(t *testing.T) {
	partitiontest.PartitionTest(t)

	ad := getSampleAccountData()
	ad.MicroAlgos.Raw = 1000000
	ad.Status = Offline

	oad := ad.OnlineAccountData()
	require.Empty(t, oad)

	ad.Status = Online
	oad = ad.OnlineAccountData()
	require.Equal(t, ad.MicroAlgos, oad.MicroAlgosWithRewards)
	require.Equal(t, ad.VoteID, oad.VoteID)
	require.Equal(t, ad.SelectionID, oad.SelectionID)
	require.Equal(t, ad.IncentiveEligible, oad.IncentiveEligible)
}
