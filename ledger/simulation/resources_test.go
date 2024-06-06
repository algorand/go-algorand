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
	"github.com/algorand/go-algorand/ledger/ledgercore"
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

func TestPopulatorWithLocalResources(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	txns := make([]transactions.SignedTxnWithAD, 1)
	txns[0].Txn.Type = protocol.ApplicationCallTx

	populator := MakeResourcePopulator(txns)

	proto := config.Consensus[protocol.ConsensusFuture]
	groupTracker := makeGroupResourceTracker(txns, &proto)

	// Note we don't need to test a box here since it will never be a local txn resource
	addr := basics.Address{1, 1, 1}
	app := basics.AppIndex(12345)
	asset := basics.AssetIndex(12345)

	groupTracker.localTxnResources[0].Accounts = make(map[basics.Address]struct{})
	groupTracker.localTxnResources[0].Assets = make(map[basics.AssetIndex]struct{})
	groupTracker.localTxnResources[0].Apps = make(map[basics.AppIndex]struct{})

	groupTracker.localTxnResources[0].Accounts[addr] = struct{}{}
	groupTracker.localTxnResources[0].Assets[asset] = struct{}{}
	groupTracker.localTxnResources[0].Apps[app] = struct{}{}

	err := populator.populateResources(groupTracker)
	require.NoError(t, err)

	require.Equal(
		t,
		PopulatedArrays{
			Assets:   []basics.AssetIndex{asset},
			Apps:     []basics.AppIndex{app},
			Accounts: []basics.Address{addr},
			Boxes:    []logic.BoxRef{},
		},
		populator.TxnResources[0].getPopulatedArrays(),
	)
}

func TestPopulatorWithGlobalResources(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	txns := make([]transactions.SignedTxnWithAD, 2)
	txns[0].Txn.Type = protocol.ApplicationCallTx
	txns[1].Txn.Type = protocol.ApplicationCallTx

	app1 := basics.AppIndex(1)
	txns[1].Txn.ApplicationID = app1

	populator := MakeResourcePopulator(txns)

	proto := config.Consensus[protocol.ConsensusFuture]
	groupTracker := makeGroupResourceTracker(txns, &proto)

	// Resources that will go in the first transaction
	addr2 := basics.Address{2}
	app3 := basics.AppIndex(3)
	asset4 := basics.AssetIndex(4)
	app5 := basics.AppIndex(5)
	box5 := logic.BoxRef{App: app5, Name: "box"}
	addr6 := basics.Address{6}
	asa7 := basics.AssetIndex(7)

	// Resources that will go in the second transaction
	box1 := logic.BoxRef{App: app1, Name: "box"}
	app1Addr := app1.Address()
	asa8 := basics.AssetIndex(8)
	addr9 := basics.Address{9}

	// Holdings
	holding6_7 := ledgercore.AccountAsset{Address: addr6, Asset: asa7}
	holding1_8 := ledgercore.AccountAsset{Address: app1Addr, Asset: asa8}
	holding9_8 := ledgercore.AccountAsset{Address: addr9, Asset: asa8}

	groupTracker.globalResources.Accounts = make(map[basics.Address]struct{})
	groupTracker.globalResources.Assets = make(map[basics.AssetIndex]struct{})
	groupTracker.globalResources.Apps = make(map[basics.AppIndex]struct{})
	groupTracker.globalResources.Boxes = make(map[logic.BoxRef]uint64)
	groupTracker.globalResources.AssetHoldings = make(map[ledgercore.AccountAsset]struct{})

	groupTracker.globalResources.Accounts[addr2] = struct{}{}
	groupTracker.globalResources.Assets[asset4] = struct{}{}
	groupTracker.globalResources.Apps[app3] = struct{}{}
	groupTracker.globalResources.Boxes[box1] = 1
	groupTracker.globalResources.Boxes[box5] = 1
	groupTracker.globalResources.AssetHoldings[holding6_7] = struct{}{}
	groupTracker.globalResources.AssetHoldings[holding1_8] = struct{}{}
	groupTracker.globalResources.AssetHoldings[holding9_8] = struct{}{}

	err := populator.populateResources(groupTracker)
	require.NoError(t, err)

	pop0 := populator.TxnResources[0].getPopulatedArrays()
	pop1 := populator.TxnResources[1].getPopulatedArrays()

	require.ElementsMatch(t, pop0.Apps, []basics.AppIndex{app3, box5.App})
	require.ElementsMatch(t, pop0.Boxes, []logic.BoxRef{box5})
	require.ElementsMatch(t, pop0.Accounts, []basics.Address{addr2, holding6_7.Address})
	require.ElementsMatch(t, pop0.Assets, []basics.AssetIndex{asset4, holding6_7.Asset})

	// Txn 1 has all the resources that had partial requirements already in tnx 1
	require.ElementsMatch(t, pop1.Apps, []basics.AppIndex{})
	require.ElementsMatch(t, pop1.Boxes, []logic.BoxRef{box1})
	require.ElementsMatch(t, pop1.Accounts, []basics.Address{holding9_8.Address})
	require.ElementsMatch(t, pop1.Assets, []basics.AssetIndex{holding1_8.Asset})
}
