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

package catchup

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/libgoal"
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

func getStateProofNextRound(a *require.Assertions, goalClient *libgoal.Client, round basics.Round) basics.Round {
	block, err := goalClient.BookkeepingBlock(uint64(round))
	a.NoError(err)
	return block.StateProofTracking[protocol.StateProofBasic].StateProofNextRound
}

func TestStateProofInReplayCatchpoint(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	// TODO: Reenable short
	//if testing.Short() {
	//	t.Skip()
	//}
	a := require.New(fixtures.SynchronizedTest(t))

	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]
	applyCatchpointConsensusChanges(&consensusParams)
	applyCatchpointStateProofConsensusChanges(&consensusParams)

	fixture := getFixture(&consensusParams)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "CatchpointCatchupTestNetwork.json"))

	primaryNode, primaryNodeRestClient, primaryErrorsCollector := startCatchpointGeneratingNode(a, fixture, "Primary")
	defer primaryErrorsCollector.Print()
	defer primaryNode.StopAlgod()

	primaryNodeAddr, err := primaryNode.GetListeningAddress()
	a.NoError(err)

	usingNode, usingNodeRestClient, wp, usingNodeErrorsCollector := startCatchpointUsingNode(a, fixture, "Node", primaryNodeAddr)
	defer usingNodeErrorsCollector.Print()
	defer wp.Close()
	defer usingNode.StopAlgod()

	targetCatchpointRound := getFirstCatchpointRound(&consensusParams)

	catchpointLabel, err := waitForCatchpointGeneration(fixture, primaryNodeRestClient, targetCatchpointRound)
	a.NoError(err)

	_, err = usingNodeRestClient.Catchup(catchpointLabel)
	a.NoError(err)

	err = fixture.ClientWaitForRoundWithTimeout(usingNodeRestClient, uint64(targetCatchpointRound+1))
	a.NoError(err)

	primaryLibGoal := fixture.GetLibGoalClientFromNodeController(primaryNode)

	dbRoundAfterCatchpoint := targetCatchpointRound - basics.Round(consensusParams.MaxBalLookback)
	a.True(getStateProofNextRound(a, &primaryLibGoal, dbRoundAfterCatchpoint) > getStateProofNextRound(a, &primaryLibGoal, targetCatchpointRound),
		"No state proof transaction in replay, rounds were %d to %d", dbRoundAfterCatchpoint+1, targetCatchpointRound)
}

func TestStateProofAfterCatchpoint(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	// TODO: Reenable short
	//if testing.Short() {
	//	t.Skip()
	//}
	a := require.New(fixtures.SynchronizedTest(t))

	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]
	applyCatchpointConsensusChanges(&consensusParams)
	applyCatchpointStateProofConsensusChanges(&consensusParams)
	consensusParams.StateProofInterval = 16
	fixture := getFixture(&consensusParams)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "CatchpointCatchupTestNetwork.json"))

	primaryNode, primaryNodeRestClient, primaryErrorsCollector := startCatchpointGeneratingNode(a, fixture, "Primary")
	defer primaryErrorsCollector.Print()
	defer primaryNode.StopAlgod()

	primaryNodeAddr, err := primaryNode.GetListeningAddress()
	a.NoError(err)

	usingNode, usingNodeRestClient, wp, usingNodeErrorsCollector := startCatchpointUsingNode(a, fixture, "Node", primaryNodeAddr)
	defer usingNodeErrorsCollector.Print()
	defer wp.Close()
	defer usingNode.StopAlgod()

	targetCatchpointRound := getFirstCatchpointRound(&consensusParams)

	catchpointLabel, err := waitForCatchpointGeneration(fixture, primaryNodeRestClient, targetCatchpointRound)
	a.NoError(err)

	_, err = usingNodeRestClient.Catchup(catchpointLabel)
	a.NoError(err)

	roundAfterSPGeneration := targetCatchpointRound.RoundUpToMultipleOf(basics.Round(consensusParams.StateProofInterval)) +
		basics.Round(consensusParams.StateProofInterval/2)
	err = fixture.ClientWaitForRoundWithTimeout(usingNodeRestClient, uint64(roundAfterSPGeneration))
	a.NoError(err)

	primaryLibGoal := fixture.GetLibGoalClientFromNodeController(primaryNode)

	dbRoundAfterCatchpoint := targetCatchpointRound - basics.Round(consensusParams.MaxBalLookback)
	firstReplayRound := dbRoundAfterCatchpoint + 1
	currentCoveredLastAttestedRound := getStateProofNextRound(a, &primaryLibGoal, roundAfterSPGeneration).SubSaturate(basics.Round(consensusParams.StateProofInterval))
	votersRound := currentCoveredLastAttestedRound.SubSaturate(basics.Round(consensusParams.StateProofInterval))

	// We do this to make sure the verification data came from the tracker.
	a.True(votersRound < firstReplayRound)
	a.True(currentCoveredLastAttestedRound > targetCatchpointRound)
}

func TestSendSigsAfterCatchpointCatchup(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	// TODO: Reenable short
	//if testing.Short() {
	//	t.Skip()
	//}
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

	primaryNode, primaryNodeRestClient, primaryEC := startCatchpointGeneratingNode(a, &fixture, "Primary")
	defer primaryEC.Print()
	defer primaryNode.StopAlgod()
	primaryNodeAddr, err := primaryNode.GetListeningAddress()
	a.NoError(err)

	normalNode, normalNodeEC := startCatchpointNormalNode(a, &fixture, "Node1", primaryNodeAddr)
	defer normalNodeEC.Print()
	defer normalNode.StopAlgod()

	usingNode, usingNodeRestClient, wp, usingNodeEC := startCatchpointUsingNode(a, &fixture, "Node2", primaryNodeAddr)
	defer usingNodeEC.Print()
	defer wp.Close()
	defer usingNode.StopAlgod()

	targetCatchpointRound := getFirstCatchpointRound(&consensusParams)

	catchpointLabel, err := waitForCatchpointGeneration(&fixture, primaryNodeRestClient, targetCatchpointRound)
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
	client := fixture.GetLibGoalClientFromNodeController(primaryNode)
	block, err := client.BookkeepingBlock(uint64(targetRound))
	a.NoError(err)
	a.Equal(expectedStateProofRound, block.StateProofTracking[protocol.StateProofBasic].StateProofNextRound)
}
