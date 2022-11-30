package participation

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// TestDeletePartKey tests that the deletepartkey subcommand works
func TestDeletePartKey(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Start devmode network and initialize things for the test.
	var fixture fixtures.RestClientFixture
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "DevModeOneWallet.json"))
	fixture.Start()
	defer fixture.Shutdown()
	sClient := fixture.GetLibGoalClientForNamedNode("Node")

	partKeyResponse, err := sClient.GetParticipationKeys()
	require.NoError(t, err)
	numberOfPartKeys := len(partKeyResponse)
	require.True(t, numberOfPartKeys > 0)
	participationID := partKeyResponse[0].Id
	deleteResponse, err := sClient.RemoveParticipationKey(participationID)
	require.NoError(t, err)
	// Expect null response
	require.Equal(t, deleteResponse.Id, "")

	newPartKeyResponse, err := sClient.GetParticipationKeys()
	require.NoError(t, err)
	newNumberOfPartKeys := len(newPartKeyResponse)
	require.True(t, newNumberOfPartKeys < numberOfPartKeys)

}
