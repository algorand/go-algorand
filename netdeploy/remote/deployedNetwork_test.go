package remote

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

func Test_createSignedTx(t *testing.T) {
	var networkState netState
	networkState.nApplications = 2
	networkState.nAssets = 2
	networkState.nAccounts = 10
	networkState.roundTrxCnt = 4
	networkState.txState = protocol.PaymentTx

	params := config.Consensus[protocol.ConsensusCurrentVersion]

	secretDst := keypair()
	src := basics.Address(secretDst.SignatureVerifier)

	//create accounts
	sntxs, _ := createSignedTx(src, basics.Round(1), params, &networkState)
	require.Equal(t, 4, len(sntxs))
	require.Equal(t, protocol.AssetConfigTx, networkState.txState)
	for _, sntx := range sntxs {
		require.Equal(t, protocol.PaymentTx, sntx.Txn.Type)
	}

	initialAccounts := networkState.accounts

	//should be creating assets next
	sntxs, _ = createSignedTx(src, basics.Round(1), params, &networkState)
	accounts := networkState.accounts
	require.Equal(t, 2, len(sntxs))
	require.Equal(t, protocol.ApplicationCallTx, networkState.txState)
	require.Equal(t, uint64(0), networkState.nAssets)
	//same accounts should be used
	require.Equal(t, initialAccounts[0], accounts[0])
	for _, sntx := range sntxs {
		require.Equal(t, protocol.AssetConfigTx, sntx.Txn.Type)
	}

	//should be creating applications next
	sntxs, _ = createSignedTx(src, basics.Round(1), params, &networkState)
	require.Equal(t, 2, len(sntxs))
	require.Equal(t, protocol.PaymentTx, networkState.txState)
	require.Equal(t, uint64(0), networkState.nApplications)
	require.Equal(t, initialAccounts[0], accounts[0])
	for _, sntx := range sntxs {
		require.Equal(t, protocol.ApplicationCallTx, sntx.Txn.Type)
	}

	//	create payment transactions for the remainder rounds
	sntxs, _ = createSignedTx(src, basics.Round(1), params, &networkState)
	require.Equal(t, 4, len(sntxs))
	require.Equal(t, protocol.PaymentTx, networkState.txState)
	//new accounts should be created
	accounts = networkState.accounts
	require.NotEqual(t, initialAccounts[0], accounts[0])
	for _, sntx := range sntxs {
		require.Equal(t, protocol.PaymentTx, sntx.Txn.Type)
	}

	//	assets per account should not exceed limit
	networkState.txState = protocol.PaymentTx
	networkState.nAssets = 10
	networkState.nApplications = 10
	networkState.nAccounts = 1
	networkState.assetPerAcct = 0
	networkState.appsPerAcct = 0

	params.MaxAssetsPerAccount = 5
	//create 1 account and try to create 6 assets for the account
	createSignedTx(src, basics.Round(1), params, &networkState)
	for i := 0; i < 6; i++ {
		createSignedTx(src, basics.Round(1), params, &networkState)
	}
	require.Equal(t, 5, networkState.assetPerAcct)

	params.MaxAppsCreated = 5
	// try to create 6 apps for the account
	createSignedTx(src, basics.Round(1), params, &networkState)
	for i := 0; i < 6; i++ {
		createSignedTx(src, basics.Round(1), params, &networkState)
	}
	require.Equal(t, 5, networkState.appsPerAcct)
}

func Test_accountsNeeded(t *testing.T) {
	params := config.Consensus[protocol.ConsensusCurrentVersion]
	params.MaxAppsCreated = 10
	params.MaxAssetsPerAccount = 20
	nAccounts := accountsNeeded(uint64(100), uint64(400), params)

	require.Equal(t, uint64(20), nAccounts)
}
