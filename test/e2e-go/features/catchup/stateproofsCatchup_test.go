package catchup

import (
	"path/filepath"
	"testing"

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
	consensusParams.EnableStateProofKeyregCheck = true
	consensusParams.StateProofUseTrackerVerification = true
}

func TestStateproofInReplayCatchpoint(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	a := require.New(fixtures.SynchronizedTest(t))

	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]
	applyCatchpointConsensusChanges(&consensusParams)
	applyCatchpointStateProofConsensusChanges(&consensusParams)
	consensusParams.StateProofInterval = 8

	// The small size of the network means we can expect extremely fast state proofs to be generated, which means
	// they should be generated one round after the proven interval's last attested round.
	firstExpectedStateProofRound := basics.Round(consensusParams.StateProofInterval*2 + 1)
	catchpointRound := getFirstCatchpointRound(&consensusParams)
	
	dbRoundAfterCatchpoint := catchpointRound - basics.Round(consensusParams.MaxBalLookback)
	firstReplayRound := dbRoundAfterCatchpoint + 1

	closestCatchpointVoters := catchpointRound.RoundDownToMultipleOf(basics.Round(consensusParams.StateProofInterval))
	expectedStateProofRound := closestCatchpointVoters + 1

	a.True(expectedStateProofRound >= firstExpectedStateProofRound)
	a.True(expectedStateProofRound >= firstReplayRound && expectedStateProofRound <= catchpointRound, "No state proof message expected between rounds"+
		" %d and %d, which define the replay range. Modify the consensus parameters to resolve this.", dbRoundAfterCatchpoint, catchpointRound)

	testBasicCatchpointCatchup(t, &consensusParams)
}

func TestSendSigsAfterCatchpointCatchup(t *testing.T) {
	partitiontest.PartitionTest(t)
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

	// We must restart the usingNode to stop it from sending messages to the web proxy, allowing it
	// to send signatures to the primary node.
	usingNode.StopAlgod()
	_, err = usingNode.StartAlgod(nodecontrol.AlgodStartArgs{
		PeerAddress:       primaryNodeAddr,
		ListenIP:          "",
		RedirectOutput:    true,
		RunUnderHost:      false,
		TelemetryOverride: "",
		ExitErrorCallback: usingNodeEC.nodeExitWithError,
	})
	usingNodeRestClient = fixture.GetAlgodClientForController(usingNode)

	normalNode.StopAlgod()

	// We wait until we know for sure that we're in a round that contains a state proof signed
	// by the usingNode.
	targetRound := targetCatchpointRound + basics.Round(consensusParams.StateProofInterval)
	err = fixture.ClientWaitForRoundWithTimeout(usingNodeRestClient, uint64(targetRound))
	a.NoError(err)

	expectedStateProofRound := targetRound.RoundDownToMultipleOf(basics.Round(consensusParams.StateProofInterval))
	client := fixture.GetLibGoalClientForNamedNode("Primary")
	block, err := client.BookkeepingBlock(uint64(targetRound))
	a.NoError(err)
	a.Equal(expectedStateProofRound, block.StateProofTracking[protocol.StateProofBasic].StateProofNextRound)
}
