// Check that devmode is functioning as designed.
package devmode

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestDevMode(t *testing.T) {
	partitiontest.PartitionTest(t)

	if testing.Short() {
		t.Skip()
	}

	t.Parallel()

	// Start devmode network, and make sure everything is primed by sending a transaction.
	var fixture fixtures.RestClientFixture
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "DevModeNetwork.json"))
	fixture.Start()
	sender, err := fixture.GetRichestAccount()
	require.NoError(t, err)
	key := crypto.GenerateSignatureSecrets(crypto.Seed{})
	receiver := basics.Address(key.SignatureVerifier)
	txn := fixture.SendMoneyAndWait(0, 100000, 1000, sender.Address, receiver.String(), "")
	firstRound := txn.ConfirmedRound + 1
	start := time.Now()

	// 2 transactions should be sent within one normal confirmation time.
	for i := uint64(0); i < 2; i++ {
		txn = fixture.SendMoneyAndWait(firstRound + i, 100000, 1000, sender.Address, receiver.String(), "")
		require.Equal(t, firstRound + i, txn.FirstRound)
	}
	require.True(t, time.Since(start) < 2 * time.Second, "Transactions should be quickly confirmed.")

	// Without transactions there should be no rounds even after a normal confirmation time.
	time.Sleep(10 * time.Second)
	status, err := fixture.LibGoalClient.Status()
	require.NoError(t, err)
	require.Equal(t, txn.ConfirmedRound, status.LastRound, "There should be no rounds without a transaction.")
}
