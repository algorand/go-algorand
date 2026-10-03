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

package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestIsPartkeyRegistered(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	key := model.AccountParticipation{
		SelectionParticipationKey: []byte{1, 2, 3},
		VoteParticipationKey:      []byte{4, 5, 6},
		VoteFirstValid:            10,
		VoteLastValid:             1000,
		VoteKeyDilution:           100,
	}
	part := model.ParticipationKey{Key: key}

	require.False(t, isPartkeyRegistered(model.Account{}, part))

	registered := key
	require.True(t, isPartkeyRegistered(model.Account{Participation: &registered}, part))

	mutations := map[string]func(p *model.AccountParticipation){
		"selection key": func(p *model.AccountParticipation) { p.SelectionParticipationKey = []byte{9} },
		"vote key":      func(p *model.AccountParticipation) { p.VoteParticipationKey = []byte{9} },
		"first valid":   func(p *model.AccountParticipation) { p.VoteFirstValid++ },
		"last valid":    func(p *model.AccountParticipation) { p.VoteLastValid++ },
		"key dilution":  func(p *model.AccountParticipation) { p.VoteKeyDilution++ },
	}
	for name, mutate := range mutations {
		other := key
		mutate(&other)
		require.False(t, isPartkeyRegistered(model.Account{Participation: &other}, part), name)
	}
}

func TestApplyFeeAndTip(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("default fee is preserved when flag is not changed", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().Uint64("fee", 0, "")
		tx := transactions.Transaction{
			Header: transactions.Header{
				Fee: basics.MicroAlgos{Raw: 1000},
			},
		}
		applyFeeAndTip(&tx, cmd, libgoal.Client{})
		require.Equal(t, uint64(1000), tx.Fee.Raw)
	})

	t.Run("explicit zero fee overrides suggested fee", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().Uint64("fee", 0, "")
		err := cmd.Flags().Set("fee", "0")
		require.NoError(t, err)

		tx := transactions.Transaction{
			Header: transactions.Header{
				Fee: basics.MicroAlgos{Raw: 1000},
			},
		}
		applyFeeAndTip(&tx, cmd, libgoal.Client{})
		require.Equal(t, uint64(0), tx.Fee.Raw)
	})

	t.Run("explicit non-zero fee overrides suggested fee", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().Uint64("fee", 0, "")
		err := cmd.Flags().Set("fee", "2500")
		require.NoError(t, err)

		tx := transactions.Transaction{
			Header: transactions.Header{
				Fee: basics.MicroAlgos{Raw: 1000},
			},
		}
		applyFeeAndTip(&tx, cmd, libgoal.Client{})
		require.Equal(t, uint64(2500), tx.Fee.Raw)
	})

	t.Run("explicit fee and tip are combined", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().Uint64("fee", 0, "")
		cmd.Flags().Uint64("tip", 0, "")
		err := cmd.Flags().Set("fee", "1000")
		require.NoError(t, err)
		err = cmd.Flags().Set("tip", "500")
		require.NoError(t, err)

		tx := transactions.Transaction{
			Header: transactions.Header{
				Fee: basics.MicroAlgos{Raw: 2000},
			},
		}
		applyFeeAndTip(&tx, cmd, libgoal.Client{})
		require.Equal(t, uint64(1500), tx.Fee.Raw)
	})

	t.Run("tip added to suggested fee when fee flag is not set", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().Uint64("fee", 0, "")
		cmd.Flags().Uint64("tip", 0, "")
		err := cmd.Flags().Set("tip", "300")
		require.NoError(t, err)

		tx := transactions.Transaction{
			Header: transactions.Header{
				Fee: basics.MicroAlgos{Raw: 1000},
			},
		}
		applyFeeAndTip(&tx, cmd, libgoal.Client{})
		require.Equal(t, uint64(1300), tx.Fee.Raw)
	})

	t.Run("fallback explicitFee used when cmd is nil", func(t *testing.T) {
		tx := transactions.Transaction{
			Header: transactions.Header{
				Fee: basics.MicroAlgos{Raw: 1000},
			},
		}
		applyFeeAndTip(&tx, nil, libgoal.Client{}, 3000)
		require.Equal(t, uint64(3000), tx.Fee.Raw)
	})
}

