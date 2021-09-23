package upgrades

import (
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/stretchr/testify/require"
)

func TestKeysWithoutStateProofKeyCannotRegister(t *testing.T) {
	a := require.New(fixtures.SynchronizedTest(t))

	consensus := generateFastUpgradeConsensus()

	// TODO: set inside concensus file!
	consensus[consensusTestFastUpgrade(protocol.ConsensusV29)].
		ApprovedUpgrades[consensusTestFastUpgrade(protocol.ConsensusFuture)] = 0

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesWithoutStateProofPartkeys.json"))
	defer fixture.Shutdown()
	c := fixture.LibGoalClient

	verifyAccountsCanSendMoneyAcrossUpgrade(c, a, &fixture)

	// now we are certain the system is set in the next version.

	client1 := fixture.GetLibGoalClientForNamedNode("Node")

	wh1, err := client1.GetUnencryptedWalletHandle()
	a.NoError(err)

	accountList, err := client1.ListAddresses(wh1)
	a.NoError(err)

	partKey, db, err := client1.GenParticipationKeys(accountList[0], 1, 1000*5, 1000)
	a.NoError(err)

	_, _ = partKey, db
	partKey.GenerateRegistrationTransaction()
}
