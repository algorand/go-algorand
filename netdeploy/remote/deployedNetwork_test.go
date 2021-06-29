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

package remote

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/testPartitioning"
)

func TestCreateSignedTx(t *testing.T) {
	testPartitioning.PartitionTest(t)

	var networkState netState
	networkState.nApplications = 2
	networkState.nAssets = 2
	networkState.nAccounts = 10
	networkState.roundTxnCnt = 4
	networkState.txnState = protocol.PaymentTx

	params := config.Consensus[protocol.ConsensusCurrentVersion]

	secretDst := keypair()
	src := basics.Address(secretDst.SignatureVerifier)

	//	create accounts
	sgtxns, _ := createSignedTx(src, basics.Round(1), params, &networkState)
	require.Equal(t, 4, len(sgtxns))
	require.Equal(t, protocol.AssetConfigTx, networkState.txnState)
	for _, sntx := range sgtxns {
		require.Equal(t, protocol.PaymentTx, sntx.Txn.Type)
	}

	initialAccounts := networkState.accounts

	//	should be creating assets next
	sgtxns, _ = createSignedTx(src, basics.Round(1), params, &networkState)
	accounts := networkState.accounts
	require.Equal(t, 2, len(sgtxns))
	require.Equal(t, protocol.ApplicationCallTx, networkState.txnState)
	require.Equal(t, uint64(0), networkState.nAssets)
	//	same accounts should be used
	require.Equal(t, initialAccounts[0], accounts[0])
	for _, sntx := range sgtxns {
		require.Equal(t, protocol.AssetConfigTx, sntx.Txn.Type)
	}

	//	should be creating applications next
	sgtxns, _ = createSignedTx(src, basics.Round(1), params, &networkState)
	require.Equal(t, 2, len(sgtxns))
	require.Equal(t, protocol.PaymentTx, networkState.txnState)
	require.Equal(t, uint64(0), networkState.nApplications)
	require.Equal(t, initialAccounts[0], accounts[0])
	for _, sntx := range sgtxns {
		require.Equal(t, protocol.ApplicationCallTx, sntx.Txn.Type)
	}

	//	create payment transactions for the remainder rounds
	sgtxns, _ = createSignedTx(src, basics.Round(1), params, &networkState)
	require.Equal(t, 4, len(sgtxns))
	require.Equal(t, protocol.PaymentTx, networkState.txnState)
	//new accounts should be created
	accounts = networkState.accounts
	require.NotEqual(t, initialAccounts[0], accounts[0])
	for _, sntx := range sgtxns {
		require.Equal(t, protocol.PaymentTx, sntx.Txn.Type)
	}

	//	assets per account should not exceed limit
	networkState.txnState = protocol.PaymentTx
	networkState.nAssets = 10
	networkState.nApplications = 10
	networkState.nAccounts = 1
	networkState.assetPerAcct = 0
	networkState.appsPerAcct = 0

	params.MaxAssetsPerAccount = 5
	//	create 1 account and try to create 6 assets for the account
	createSignedTx(src, basics.Round(1), params, &networkState)
	for i := 0; i < params.MaxAssetsPerAccount; i++ {
		createSignedTx(src, basics.Round(1), params, &networkState)
	}
	require.Equal(t, params.MaxAssetsPerAccount, networkState.assetPerAcct)
	//	txn state has changed to the next one
	require.Equal(t, protocol.ApplicationCallTx, networkState.txnState)

	params.MaxAppsCreated = 5
	networkState.appsPerAcct = 0
	//	try to create 6 apps for the account
	for i := 0; i < params.MaxAppsCreated; i++ {
		createSignedTx(src, basics.Round(1), params, &networkState)
	}
	require.Equal(t, params.MaxAppsCreated, networkState.appsPerAcct)
	//	txn state has changed to the next one
	require.Equal(t, protocol.PaymentTx, networkState.txnState)
}

func TestAccountsNeeded(t *testing.T) {
	testPartitioning.PartitionTest(t)

	params := config.Consensus[protocol.ConsensusCurrentVersion]
	params.MaxAppsCreated = 10
	params.MaxAssetsPerAccount = 20
	nAccounts := accountsNeeded(uint64(100), uint64(400), params)

	require.Equal(t, uint64(20), nAccounts)
}
