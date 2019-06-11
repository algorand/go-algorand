// Copyright (C) 2019 Algorand, Inc.
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
