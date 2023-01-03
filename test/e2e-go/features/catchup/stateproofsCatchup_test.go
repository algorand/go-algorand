package catchup

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/nodecontrol"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func applyCatchpointStateProofConsensusChanges(consensusParams *config.ConsensusParams) {
	// we decrease the StateProofStrengthTarget creating a "weak cert" to allow state proofs to be generated when the
	// signed weight and proven weight are very close to each other.
	consensusParams.StateProofStrengthTarget = 4
	consensusParams.StateProofInterval = 8
	consensusParams.StateProofVotersLookback = 2
	consensusParams.StateProofStrengthTarget = 256
	consensusParams.EnableStateProofKeyregCheck = true
	consensusParams.StateProofUseTrackerVerification = true
}

func TestReloadLedger(t *testing.T) {
	partitiontest.PartitionTest(t)
	// TODO: Why?
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	a := require.New(fixtures.SynchronizedTest(t))

	configurableConsensus := make(config.ConsensusProtocols)
	consensusVersion := protocol.ConsensusVersion("catchpointtestingprotocol")
	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]

	applyCatchpointStateProofConsensusChanges(&consensusParams)
	applyCatchpointConsensusChanges(&consensusParams)
	// Weight threshold allows creation of state proofs using the primary node and at least one other node.
	consensusParams.StateProofWeightThreshold = (1 << 32) * 85 / 100

	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		// amd64 and arm64 platforms are generally quite capable, so accelerate the round times to make the test run faster.
		consensusParams.AgreementFilterTimeoutPeriod0 = 1 * time.Second
		consensusParams.AgreementFilterTimeout = 1 * time.Second
	}

	configurableConsensus[consensusVersion] = consensusParams
	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "StateProofCatchpointCatchupTestNetwork.json"))

	const catchpointInterval = 4
	primaryNode, primaryEC := startCatchpointGeneratingNode(a, &fixture, "Primary", catchpointInterval)
	defer primaryEC.Print()
	defer primaryNode.StopAlgod()
	primaryNodeRestClient := fixture.GetAlgodClientForController(primaryNode)
	primaryNodeAddr, err := primaryNode.GetListeningAddress()
	a.NoError(err)

	normalNode, normalNodeEC := startCatchpointNormalNode(a, &fixture, "Node1", primaryNodeAddr)
	defer normalNodeEC.Print()
	defer normalNode.StopAlgod()

	usingNode, wp, usingNodeEC := startCatchpointUsingNode(a, &fixture, "Node2", primaryNodeAddr)
	defer usingNodeEC.Print()
	defer wp.Close()
	defer usingNode.StopAlgod()
	usingNodeRestClient := fixture.GetAlgodClientForController(usingNode)

	targetCatchpointRound := getFirstCatchpointRound(&consensusParams, catchpointInterval)

	catchpointLabel, err := fixture.ClientWaitForCatchpoint(primaryNodeRestClient, targetCatchpointRound)
	a.NoError(err)

	_, err = usingNodeRestClient.Catchup(catchpointLabel)
	a.NoError(err)

	err = fixture.ClientWaitForRoundWithTimeout(usingNodeRestClient, uint64(targetCatchpointRound)+1)
	a.NoError(err)

	normalNode.StopAlgod()
	usingNode.StopAlgod()

	_, err = usingNode.StartAlgod(nodecontrol.AlgodStartArgs{
		PeerAddress:       primaryNodeAddr,
		ListenIP:          "",
		RedirectOutput:    true,
		RunUnderHost:      false,
		TelemetryOverride: "",
	})
	usingNodeRestClient = fixture.GetAlgodClientForController(usingNode)

	targetRound := targetCatchpointRound + basics.Round(consensusParams.StateProofInterval*4)
	err = fixture.ClientWaitForRoundWithTimeout(usingNodeRestClient, uint64(targetRound))
	a.NoError(err)

	client := fixture.GetLibGoalClientForNamedNode("Primary")
	block, err := client.BookkeepingBlock(uint64(targetRound))
	a.NoError(err)
	// TODO: Not hardcoded
	a.Equal(basics.Round(56), block.StateProofTracking[protocol.StateProofBasic].StateProofNextRound)
}
