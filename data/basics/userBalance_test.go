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

package basics

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

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

	const unitSize = 1_000_000
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
			money := func(u AccountData, rewardsLevel uint64) (balance MicroAlgos, rewards MicroAlgos) {
				u = u.WithUpdatedRewards(unitSize, rewardsLevel)
				return u.MicroAlgos, u.RewardedMicroAlgos
			}
			balance, rewards := money(ad, ad.RewardsBase+level)
			require.Equal(t, balance.Raw, ad.MicroAlgos.Raw+level*ad.MicroAlgos.RewardUnits(unitSize))
			require.Equal(t, rewards.Raw, ad.RewardedMicroAlgos.Raw+level*ad.MicroAlgos.RewardUnits(unitSize))
		}
	}
}

func TestWithUpdatedRewardsPanics(t *testing.T) {
	partitiontest.PartitionTest(t)

	const unitSize = 1_000_000
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
			a.WithUpdatedRewards(unitSize, 100)
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
		b := a.WithUpdatedRewards(unitSize, 100)
		require.Equal(t, 100*a.MicroAlgos.RewardUnits(unitSize)-1, b.RewardedMicroAlgos.Raw)
	})
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
