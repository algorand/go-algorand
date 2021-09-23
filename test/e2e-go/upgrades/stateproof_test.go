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

	//defer fixture.Shutdown()
	//
	//c := fixture.LibGoalClient
	//
	//// upgrading the consensus version
	//testAccountsCanSendMoneyAcrossUpgrade(c, a, &fixture)
	//
	//// now we are certain the system is set in the next version.
	//
	//nodeclient := fixture.GetLibGoalClientForNamedNode("Node")
	////
	//wallet, err := nodeclient.GetUnencryptedWalletHandle()
	//a.NoError(err)
	//
	//cls, err := c.ListAddresses(wallet)
	//a.NoError(err)
	//
	//key, path, err := c.GenParticipationKeys(cls[0], 0, 1000000, 10000)
	//a.NoError(err)
	//_, _ = key, path
	//log.Println(cls)
}
