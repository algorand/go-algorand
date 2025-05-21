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

package testing

import (
	gotesting "testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// CalculateNewRoundAccountTotals calculates the accounts totals for a given round
func CalculateNewRoundAccountTotals(t *gotesting.T, newRoundDeltas ledgercore.AccountDeltas, newRoundRewardLevel uint64, newRoundConsensusParams config.ConsensusParams, prevRoundBalances map[basics.Address]basics.AccountData, prevRoundTotals ledgercore.AccountTotals) (newTotals ledgercore.AccountTotals) {
	newTotals = prevRoundTotals
	var ot basics.OverflowTracker
	newTotals.ApplyRewards(newRoundRewardLevel, &ot)
	for i := 0; i < newRoundDeltas.Len(); i++ {
		addr, ad := newRoundDeltas.GetByIdx(i)
		prevBal := ledgercore.ToAccountData(prevRoundBalances[addr])
		newTotals.DelAccount(newRoundConsensusParams, prevBal, &ot)
		newTotals.AddAccount(newRoundConsensusParams, ad, &ot)
	}
	require.False(t, ot.Overflowed)
	return
}
