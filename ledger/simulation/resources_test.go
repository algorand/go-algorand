// Copyright (C) 2019-2023 Algorand, Inc.
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
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppAccounts(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto := config.Consensus[protocol.ConsensusFuture]
	txns := make([]transactions.SignedTxnWithAD, 1)
	txns[0].Txn.Type = protocol.ApplicationCallTx
	ep := logic.NewAppEvalParams(txns, &proto, &transactions.SpecialAddresses{})

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
	ep := logic.NewAppEvalParams(txns, &proto, &transactions.SpecialAddresses{})

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

func TestAssignResources(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testCases := []struct {
		name string

		txgroup         []transactions.SignedTxnWithAD
		globalResources ResourceTracker
		localResources  []ResourceTracker

		expectedExtraTxns int
		expectedError     string
	}{
		{
			name: "empty case",
		},
		{
			name: "single txn no unnamed",
			txgroup: []transactions.SignedTxnWithAD{
				txntest.Txn{
					Type: protocol.ApplicationCallTx,
				}.SignedTxnWithAD(),
			},
			localResources: []ResourceTracker{
				{},
			},
		},
		{
			name: "single txn one local unnamed account",
			txgroup: []transactions.SignedTxnWithAD{
				txntest.Txn{
					Type: protocol.ApplicationCallTx,
				}.SignedTxnWithAD(),
			},
			localResources: []ResourceTracker{
				{
					Accounts: map[basics.Address]struct{}{
						{1}: {},
					},
				},
			},
		},
		{
			name: "single txn max local unnamed accounts",
			txgroup: []transactions.SignedTxnWithAD{
				txntest.Txn{
					Type: protocol.ApplicationCallTx,
				}.SignedTxnWithAD(),
			},
			localResources: []ResourceTracker{
				{
					Accounts: map[basics.Address]struct{}{
						{1}: {},
						{2}: {},
						{3}: {},
						{4}: {},
					},
				},
			},
		},
		{
			name: "single txn too many local unnamed accounts",
			txgroup: []transactions.SignedTxnWithAD{
				txntest.Txn{
					Type: protocol.ApplicationCallTx,
				}.SignedTxnWithAD(),
			},
			localResources: []ResourceTracker{
				{
					Accounts: map[basics.Address]struct{}{
						{1}: {},
						{2}: {},
						{3}: {},
						{4}: {},
						{5}: {},
					},
				},
			},
			expectedError: "cannot assign account",
		},
		{
			name: "single txn one global unnamed account",
			txgroup: []transactions.SignedTxnWithAD{
				txntest.Txn{
					Type: protocol.ApplicationCallTx,
				}.SignedTxnWithAD(),
			},
			localResources: []ResourceTracker{
				{},
			},
			globalResources: ResourceTracker{
				Accounts: map[basics.Address]struct{}{
					{1}: {},
				},
			},
		},
		{
			name: "single txn max global unnamed accounts",
			txgroup: []transactions.SignedTxnWithAD{
				txntest.Txn{
					Type: protocol.ApplicationCallTx,
				}.SignedTxnWithAD(),
			},
			localResources: []ResourceTracker{
				{},
			},
			globalResources: ResourceTracker{
				Accounts: map[basics.Address]struct{}{
					{1}: {},
					{2}: {},
					{3}: {},
					{4}: {},
				},
			},
		},
		{
			name: "single txn max global unnamed accounts, 1 extra txn",
			txgroup: []transactions.SignedTxnWithAD{
				txntest.Txn{
					Type: protocol.ApplicationCallTx,
				}.SignedTxnWithAD(),
			},
			localResources: []ResourceTracker{
				{},
			},
			globalResources: ResourceTracker{
				Accounts: map[basics.Address]struct{}{
					{1}: {},
					{2}: {},
					{3}: {},
					{4}: {},
					{5}: {},
				},
			},
			expectedExtraTxns: 1,
		},
		{
			name: "single txn max global unnamed accounts, 2 extra txns",
			txgroup: []transactions.SignedTxnWithAD{
				txntest.Txn{
					Type: protocol.ApplicationCallTx,
				}.SignedTxnWithAD(),
			},
			localResources: []ResourceTracker{
				{},
			},
			globalResources: ResourceTracker{
				Accounts: map[basics.Address]struct{}{
					{1}: {},
					{2}: {},
					{3}: {},
					{4}: {},
					{5}: {},
					{6}: {},
					{7}: {},
					{8}: {},
					{9}: {},
				},
			},
			expectedExtraTxns: 2,
		},
		{
			name: "single txn max global unnamed accounts, 15 extra txns",
			txgroup: []transactions.SignedTxnWithAD{
				txntest.Txn{
					Type: protocol.ApplicationCallTx,
				}.SignedTxnWithAD(),
			},
			localResources: []ResourceTracker{
				{},
			},
			globalResources: ResourceTracker{
				Accounts: map[basics.Address]struct{}{
					{1}:  {},
					{2}:  {},
					{3}:  {},
					{4}:  {},
					{5}:  {},
					{6}:  {},
					{7}:  {},
					{8}:  {},
					{9}:  {},
					{10}: {},
					{11}: {},
					{12}: {},
					{13}: {},
					{14}: {},
					{15}: {},
					{16}: {},
					{17}: {},
					{18}: {},
					{19}: {},
					{20}: {},
					{21}: {},
					{22}: {},
					{23}: {},
					{24}: {},
					{25}: {},
					{26}: {},
					{27}: {},
					{28}: {},
					{29}: {},
					{30}: {},
					{31}: {},
					{32}: {},
					{33}: {},
					{34}: {},
					{35}: {},
					{36}: {},
					{37}: {},
					{38}: {},
					{39}: {},
					{40}: {},
					{41}: {},
					{42}: {},
					{43}: {},
					{44}: {},
					{45}: {},
					{46}: {},
					{47}: {},
					{48}: {},
					{49}: {},
					{50}: {},
					{51}: {},
					{52}: {},
					{53}: {},
					{54}: {},
					{55}: {},
					{56}: {},
					{57}: {},
					{58}: {},
					{59}: {},
					{60}: {},
					{61}: {},
					{62}: {},
					{63}: {},
					{64}: {},
				},
			},
			expectedExtraTxns: 15,
		},
	}

	proto := config.Consensus[protocol.ConsensusFuture]

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ep := logic.NewAppEvalParams(tc.txgroup, &proto, &transactions.SpecialAddresses{})
			tracker := groupResourceTracker{
				globalResources:   tc.globalResources,
				localTxnResources: tc.localResources,
			}
			txnAssignments, extraTxnAssignments, err := assignResources(ep, &tracker)
			if len(tc.expectedError) != 0 {
				require.ErrorContains(t, err, tc.expectedError)
				return
			}
			require.NoError(t, err)

			// The number of extra txns must match
			assert.Len(t, extraTxnAssignments, tc.expectedExtraTxns)

			// All local resources must be assigned to the corresponding txn
			for gi := range tc.localResources {
				for account := range tc.localResources[gi].Accounts {
					assert.Contains(t, txnAssignments[gi].Accounts, account)
				}
				for asset := range tc.localResources[gi].Assets {
					assert.Contains(t, txnAssignments[gi].Assets, asset)
				}
				for app := range tc.localResources[gi].Apps {
					assert.Contains(t, txnAssignments[gi].Apps, app)
				}
				assert.Empty(t, tc.localResources[gi].Boxes, "invalid test case")
				assert.Empty(t, tc.localResources[gi].AssetHoldings, "invalid test case")
				assert.Empty(t, tc.localResources[gi].AppLocals, "invalid test case")
			}

			// All global resources must be assigned anywhere in the group
			allAssignments := append(txnAssignments, extraTxnAssignments...)

			for account := range tc.globalResources.Accounts {
				found := false
				for _, assignment := range allAssignments {
					if _, ok := assignment.Accounts[account]; ok {
						found = true
						break
					}
				}
				assert.True(t, found, "account %s not found in assignments: %v", account, allAssignments)
			}
			for asset := range tc.globalResources.Assets {
				found := false
				for _, assignment := range allAssignments {
					if _, ok := assignment.Assets[asset]; ok {
						found = true
						break
					}
				}
				assert.True(t, found, "asset %d not found in assignments: %v", asset, allAssignments)
			}
			for app := range tc.globalResources.Apps {
				found := false
				for _, assignment := range allAssignments {
					if _, ok := assignment.Apps[app]; ok {
						found = true
						break
					}
				}
				assert.True(t, found, "app %d not found in assignments: %v", app, allAssignments)
			}
			for box := range tc.globalResources.Boxes {
				found := false
				for _, assignment := range allAssignments {
					if _, ok := assignment.Boxes[box]; ok {
						found = true
						break
					}
				}
				assert.True(t, found, "box (%d,%#x) not found in assignments: %v", box.App, box.Name, allAssignments)
			}
			for holding := range tc.globalResources.AssetHoldings {
				found := false
				for _, assignment := range allAssignments {
					_, assetOk := assignment.Assets[holding.Asset]
					_, accountOk := assignment.Accounts[holding.Address]
					if assetOk && accountOk {
						found = true
						break
					}
				}
				assert.True(t, found, "asset holding (%d,%s) not found in assignments: %v", holding.Asset, holding.Address, allAssignments)
			}
			for local := range tc.globalResources.AppLocals {
				found := false
				for _, assignment := range allAssignments {
					_, appOk := assignment.Apps[local.App]
					_, accountOk := assignment.Accounts[local.Address]
					if appOk && accountOk {
						found = true
						break
					}
				}
				assert.True(t, found, "app local (%d,%s) not found in assignments: %v", local.App, local.Address, allAssignments)
			}
		})
	}
}
