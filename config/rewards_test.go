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

package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestRewards(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := Consensus[protocol.ConsensusCurrentVersion]
	accountAlgos := []basics.MicroAlgos{{Raw: 0}, {Raw: 8000}, {Raw: 13000}, {Raw: 83000}}
	for _, accountAlgo := range accountAlgos {
		ad := basics.AccountData{
			Status:             basics.Online,
			MicroAlgos:         accountAlgo,
			RewardsBase:        100,
			RewardedMicroAlgos: basics.MicroAlgos{Raw: 25},
		}

		levels := []uint64{uint64(0), uint64(1), uint64(30), uint64(3000)}
		for _, level := range levels {
			money, rewards := proto.Money(ad, ad.RewardsBase+level)
			require.Equal(t, money.Raw, ad.MicroAlgos.Raw+level*proto.RewardUnits(ad.MicroAlgos))
			require.Equal(t, rewards.Raw, ad.RewardedMicroAlgos.Raw+level*proto.RewardUnits(ad.MicroAlgos))
		}
	}
}

func TestWithUpdatedRewardsPanics(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := Consensus[protocol.ConsensusCurrentVersion]
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
			a := basics.AccountData{
				Status:             basics.Online,
				MicroAlgos:         basics.MicroAlgos{Raw: ^uint64(0)},
				RewardedMicroAlgos: basics.MicroAlgos{Raw: 0},
				RewardsBase:        0,
			}
			proto.WithUpdatedRewards(a, 100)
		}()
		require.Equal(t, true, paniced)
	})

	t.Run("RewardsOverflow", func(t *testing.T) {
		a := basics.AccountData{
			Status:             basics.Online,
			MicroAlgos:         basics.MicroAlgos{Raw: 80000000},
			RewardedMicroAlgos: basics.MicroAlgos{Raw: ^uint64(0)},
			RewardsBase:        0,
		}
		b := proto.WithUpdatedRewards(a, 100)
		require.Equal(t, 100*proto.RewardUnits(a.MicroAlgos)-1, b.RewardedMicroAlgos.Raw)
	})
}
