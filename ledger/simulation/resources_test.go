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

package simulation

import (
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestAppAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto := config.Consensus[protocol.ConsensusFuture]
	txns := make([]transactions.SignedTxnWithAD, 1)
	txns[0].Txn.Type = protocol.ApplicationCallTx
	ep := logic.NewAppEvalParams(txns, &proto, nil)

	appID := basics.AppIndex(12345)
	appAccount := appID.Address()

	for _, globalSharing := range []bool{false, true} {
		groupAssignment := makeGroupResourceTracker(txns, &proto)
		var resources *ResourceTracker
		if globalSharing {
			resources = &groupAssignment.globalResources
		} else {
			resources = &groupAssignment.localTxnResources[0]
		}

		require.Empty(t, resources.Apps)
		require.Empty(t, resources.Accounts)

		require.False(t, groupAssignment.hasApp(appID, globalSharing, 0))
		require.False(t, groupAssignment.hasAccount(appAccount, ep, 7, globalSharing, 0))

		require.True(t, groupAssignment.addAccount(appAccount, globalSharing, 0))

		require.Empty(t, resources.Apps)
		require.Equal(t, map[basics.Address]struct{}{
			appAccount: {},
		}, resources.Accounts)

		require.False(t, groupAssignment.hasApp(appID, globalSharing, 0))
		require.True(t, groupAssignment.hasAccount(appAccount, ep, 7, globalSharing, 0))

		require.True(t, groupAssignment.addApp(appID, ep, 7, globalSharing, 0))

		require.Equal(t, map[basics.AppIndex]struct{}{
			appID: {},
		}, resources.Apps)
		require.Empty(t, resources.Accounts)

		require.True(t, groupAssignment.hasApp(appID, globalSharing, 0))
		require.True(t, groupAssignment.hasAccount(appAccount, ep, 7, globalSharing, 0))

		require.False(t, groupAssignment.hasAccount(appAccount, ep, 6, globalSharing, 0))
	}
}

func TestGlobalVsLocalResources(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto := config.Consensus[protocol.ConsensusFuture]
	txns := make([]transactions.SignedTxnWithAD, 3)
	txns[0].Txn.Type = protocol.ApplicationCallTx
	txns[1].Txn.Type = protocol.ApplicationCallTx
	txns[2].Txn.Type = protocol.ApplicationCallTx
	ep := logic.NewAppEvalParams(txns, &proto, nil)

	// For this test, we assume only the txn at index 1 supports group sharing.

	t.Run("accounts", func(t *testing.T) {
		account1 := basics.Address{1, 1, 1}
		account2 := basics.Address{2, 2, 2}

		groupAssignment := makeGroupResourceTracker(txns, &proto)

		require.Empty(t, groupAssignment.globalResources.Accounts)
		require.Empty(t, groupAssignment.localTxnResources[0].Accounts)
		require.Empty(t, groupAssignment.localTxnResources[1].Accounts)
		require.Empty(t, groupAssignment.localTxnResources[2].Accounts)

		require.True(t, groupAssignment.addAccount(account1, false, 0))

		// account1 should be present in txn 0's local assignment
		require.Empty(t, groupAssignment.globalResources.Accounts)
		require.Equal(t, map[basics.Address]struct{}{
			account1: {},
		}, groupAssignment.localTxnResources[0].Accounts)
		require.Empty(t, groupAssignment.localTxnResources[1].Accounts)
		require.Empty(t, groupAssignment.localTxnResources[2].Accounts)

		// Txn 1, which used global resources, can see account1
		require.True(t, groupAssignment.hasAccount(account1, ep, 7, true, 1))

		require.True(t, groupAssignment.addAccount(account2, true, 1))

		// account2 should be present in the global assignment
		require.Equal(t, map[basics.Address]struct{}{
			account2: {},
		}, groupAssignment.globalResources.Accounts)
		require.Equal(t, map[basics.Address]struct{}{
			account1: {},
		}, groupAssignment.localTxnResources[0].Accounts)
		require.Empty(t, groupAssignment.localTxnResources[1].Accounts)
		require.Empty(t, groupAssignment.localTxnResources[2].Accounts)

		// Txn 2, which does not use global resources, cannot see either account
		require.False(t, groupAssignment.hasAccount(account1, ep, 7, false, 2))
		require.False(t, groupAssignment.hasAccount(account2, ep, 7, false, 2))

		require.True(t, groupAssignment.addAccount(account1, false, 2))

		// account1 should be present in txn 2's local assignment
		require.Equal(t, map[basics.Address]struct{}{
			account2: {},
		}, groupAssignment.globalResources.Accounts)
		require.Equal(t, map[basics.Address]struct{}{
			account1: {},
		}, groupAssignment.localTxnResources[0].Accounts)
		require.Empty(t, groupAssignment.localTxnResources[1].Accounts)
		require.Equal(t, map[basics.Address]struct{}{
			account1: {},
		}, groupAssignment.localTxnResources[2].Accounts)

		require.True(t, groupAssignment.addAccount(account2, false, 2))

		// account2 gets moved from the global assignment to the local assignment of txn 2
		require.Empty(t, groupAssignment.globalResources.Accounts)
		require.Equal(t, map[basics.Address]struct{}{
			account1: {},
		}, groupAssignment.localTxnResources[0].Accounts)
		require.Empty(t, groupAssignment.localTxnResources[1].Accounts)
		require.Equal(t, map[basics.Address]struct{}{
			account1: {},
			account2: {},
		}, groupAssignment.localTxnResources[2].Accounts)
	})

	t.Run("assets", func(t *testing.T) {
		asset1 := basics.AssetIndex(100)
		asset2 := basics.AssetIndex(200)

		groupAssignment := makeGroupResourceTracker(txns, &proto)

		require.Empty(t, groupAssignment.globalResources.Assets)
		require.Empty(t, groupAssignment.localTxnResources[0].Assets)
		require.Empty(t, groupAssignment.localTxnResources[1].Assets)
		require.Empty(t, groupAssignment.localTxnResources[2].Assets)

		require.True(t, groupAssignment.addAsset(asset1, false, 0))

		// asset1 should be present in txn 0's local assignment
		require.Empty(t, groupAssignment.globalResources.Assets)
		require.Equal(t, map[basics.AssetIndex]struct{}{
			asset1: {},
		}, groupAssignment.localTxnResources[0].Assets)
		require.Empty(t, groupAssignment.localTxnResources[1].Assets)
		require.Empty(t, groupAssignment.localTxnResources[2].Assets)

		// Txn 1, which used global resources, can see asset1
		require.True(t, groupAssignment.hasAsset(asset1, true, 1))

		require.True(t, groupAssignment.addAsset(asset2, true, 1))

		// asset2 should be present in the global assignment
		require.Equal(t, map[basics.AssetIndex]struct{}{
			asset2: {},
		}, groupAssignment.globalResources.Assets)
		require.Equal(t, map[basics.AssetIndex]struct{}{
			asset1: {},
		}, groupAssignment.localTxnResources[0].Assets)
		require.Empty(t, groupAssignment.localTxnResources[1].Assets)
		require.Empty(t, groupAssignment.localTxnResources[2].Assets)

		// Txn 2, which does not use global resources, cannot see either asset
		require.False(t, groupAssignment.hasAsset(asset1, false, 2))
		require.False(t, groupAssignment.hasAsset(asset2, false, 2))

		require.True(t, groupAssignment.addAsset(asset1, false, 2))

		// asset1 should be present in txn 2's local assignment
		require.Equal(t, map[basics.AssetIndex]struct{}{
			asset2: {},
		}, groupAssignment.globalResources.Assets)
		require.Equal(t, map[basics.AssetIndex]struct{}{
			asset1: {},
		}, groupAssignment.localTxnResources[0].Assets)
		require.Empty(t, groupAssignment.localTxnResources[1].Assets)
		require.Equal(t, map[basics.AssetIndex]struct{}{
			asset1: {},
		}, groupAssignment.localTxnResources[2].Assets)

		require.True(t, groupAssignment.addAsset(asset2, false, 2))

		// asset2 gets moved from the global assignment to the local assignment of txn 2
		require.Empty(t, groupAssignment.globalResources.Assets)
		require.Equal(t, map[basics.AssetIndex]struct{}{
			asset1: {},
		}, groupAssignment.localTxnResources[0].Assets)
		require.Empty(t, groupAssignment.localTxnResources[1].Assets)
		require.Equal(t, map[basics.AssetIndex]struct{}{
			asset1: {},
			asset2: {},
		}, groupAssignment.localTxnResources[2].Assets)
	})

	t.Run("apps", func(t *testing.T) {
		app1 := basics.AppIndex(100)
		app2 := basics.AppIndex(200)

		groupAssignment := makeGroupResourceTracker(txns, &proto)

		require.Empty(t, groupAssignment.globalResources.Apps)
		require.Empty(t, groupAssignment.localTxnResources[0].Apps)
		require.Empty(t, groupAssignment.localTxnResources[1].Apps)
		require.Empty(t, groupAssignment.localTxnResources[2].Apps)

		require.True(t, groupAssignment.addApp(app1, ep, 7, false, 0))

		// app1 should be present in txn 0's local assignment
		require.Empty(t, groupAssignment.globalResources.Apps)
		require.Equal(t, map[basics.AppIndex]struct{}{
			app1: {},
		}, groupAssignment.localTxnResources[0].Apps)
		require.Empty(t, groupAssignment.localTxnResources[1].Apps)
		require.Empty(t, groupAssignment.localTxnResources[2].Apps)

		// Txn 1, which used global resources, can see app1
		require.True(t, groupAssignment.hasApp(app1, true, 1))

		require.True(t, groupAssignment.addApp(app2, ep, 7, true, 1))

		// app2 should be present in the global assignment
		require.Equal(t, map[basics.AppIndex]struct{}{
			app2: {},
		}, groupAssignment.globalResources.Apps)
		require.Equal(t, map[basics.AppIndex]struct{}{
			app1: {},
		}, groupAssignment.localTxnResources[0].Apps)
		require.Empty(t, groupAssignment.localTxnResources[1].Apps)
		require.Empty(t, groupAssignment.localTxnResources[2].Apps)

		// Txn 2, which does not use global resources, cannot see either app
		require.False(t, groupAssignment.hasApp(app1, false, 2))
		require.False(t, groupAssignment.hasApp(app2, false, 2))

		require.True(t, groupAssignment.addApp(app1, ep, 7, false, 2))

		// app1 should be present in txn 2's local assignment
		require.Equal(t, map[basics.AppIndex]struct{}{
			app2: {},
		}, groupAssignment.globalResources.Apps)
		require.Equal(t, map[basics.AppIndex]struct{}{
			app1: {},
		}, groupAssignment.localTxnResources[0].Apps)
		require.Empty(t, groupAssignment.localTxnResources[1].Apps)
		require.Equal(t, map[basics.AppIndex]struct{}{
			app1: {},
		}, groupAssignment.localTxnResources[2].Apps)

		require.True(t, groupAssignment.addApp(app2, ep, 7, false, 2))

		// app2 gets moved from the global assignment to the local assignment of txn 2
		require.Empty(t, groupAssignment.globalResources.Apps)
		require.Equal(t, map[basics.AppIndex]struct{}{
			app1: {},
		}, groupAssignment.localTxnResources[0].Apps)
		require.Empty(t, groupAssignment.localTxnResources[1].Apps)
		require.Equal(t, map[basics.AppIndex]struct{}{
			app1: {},
			app2: {},
		}, groupAssignment.localTxnResources[2].Apps)
	})
}
