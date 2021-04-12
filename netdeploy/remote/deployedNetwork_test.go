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
	secretDst := keypair()
	src := basics.Address(secretDst.SignatureVerifier)

	//create accounts
	sntxs := createSignedTx(src, basics.Round(1), protocol.ConsensusCurrentVersion, &networkState)
	require.Equal(t, 4, len(sntxs))
	require.Equal(t, protocol.AssetConfigTx, networkState.txState)
	for _, sntx := range sntxs {
		require.Equal(t, protocol.PaymentTx, sntx.Txn.Type)
	}

	//create assets
	sntxs = createSignedTx(src, basics.Round(1), protocol.ConsensusCurrentVersion, &networkState)
	require.Equal(t, 2, len(sntxs))
	require.Equal(t, protocol.ApplicationCallTx, networkState.txState)
	for _, sntx := range sntxs {
		require.Equal(t, protocol.AssetConfigTx, sntx.Txn.Type)
	}

	//create applications
	sntxs = createSignedTx(src, basics.Round(1), protocol.ConsensusCurrentVersion, &networkState)
	require.Equal(t, 2, len(sntxs))
	require.Equal(t, protocol.PaymentTx, networkState.txState)
	for _, sntx := range sntxs {
		require.Equal(t, protocol.ApplicationCallTx, sntx.Txn.Type)
	}

}

func Test_accountsNeeded(t *testing.T) {
	params := config.Consensus[protocol.ConsensusCurrentVersion]
	params.MaxAppsCreated = 10
	params.MaxAssetsPerAccount = 20
	nAccounts := accountsNeeded(uint64(100), uint64(400), params)

	require.Equal(t, uint64(20), nAccounts)
}
