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

package internal

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// Test that preloading data in cow base works as expected.
func TestSaveResourcesInCowBase(t *testing.T) {
	partitiontest.PartitionTest(t)

	var address basics.Address
	_, err := rand.Read(address[:])
	require.NoError(t, err)

	genesisInitState, _, _ := ledgertesting.GenesisWithProto(10, protocol.ConsensusFuture)

	genesisBalances := bookkeeping.GenesisBalances{
		Balances:    genesisInitState.Accounts,
		FeeSink:     testSinkAddr,
		RewardsPool: testPoolAddr,
		Timestamp:   0,
	}
	l := newTestLedger(t, genesisBalances)

	newBlock := bookkeeping.MakeBlock(l.blocks[0].BlockHeader)

	eval, err := l.StartEvaluator(newBlock.BlockHeader, 0, 0)

	require.NoError(t, err)
	resources := EvalForIndexerResources{
		Accounts: map[basics.Address]*basics.AccountData{
			address: {
				MicroAlgos: basics.MicroAlgos{Raw: 5},
			},
		},
		Creators: map[Creatable]ledgercore.FoundAddress{
			{cindex: basics.CreatableIndex(6), ctype: basics.AssetCreatable}: {Address: address, Exists: true},
			{cindex: basics.CreatableIndex(6), ctype: basics.AppCreatable}:   {Address: address, Exists: false},
		},
	}

	eval.SaveResourcesInCowBase(resources)
	base := eval.state.lookupParent.(*roundCowBase)
	{
		accountData, err := base.lookup(address)
		require.NoError(t, err)
		assert.Equal(t, basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 5}}, accountData)
	}
	{
		address, found, err :=
			base.getCreator(basics.CreatableIndex(6), basics.AssetCreatable)
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, address, address)
	}
	{
		_, found, err :=
			base.getCreator(basics.CreatableIndex(6), basics.AppCreatable)
		require.NoError(t, err)
		require.False(t, found)
	}
}
