// Copyright (C) 2019-2024 Algorand, Inc.
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
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
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
	// Overview of this test:
	// Configure consensus to generate a state proof in the target catchpoint's replay rounds.
	// i.e the node will have to "replay" the state proof transaction after fast catchup.
	// Start a two-node network (primary has 100%, using has 0%)
	// create a web proxy, have the using node use it as a peer, blocking all requests for round #2 and allowing everything else
	// (This disables the node's ability to use regular catchup)
	// Let it run until the first usable catchpoint, as computed in getFirstCatchpointRound, is generated.
	// instruct the using node to fast catchup.
	// wait until the using node is caught up to catchpointRound+1, skipping the "impossible" hole of round #2.
	// Verify that the blocks replayed to the using node contained a state proof transaction.
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}

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

	catchpointLabel := waitForCatchpointGeneration(t, fixture, primaryNodeRestClient, targetCatchpointRound)

	_, err = usingNodeRestClient.Catchup(catchpointLabel, 0)
	a.NoError(err)

	// waiting for fastcatchup to start
	attempt := 0
	const sleepTime = 1 * time.Millisecond // too large duration makes catchup to complete
	const maxAttempts = 500
	for {
		status, err := usingNodeRestClient.Status()
		a.NoError(err)
		if status.Catchpoint != nil && len(*status.Catchpoint) > 0 {
			t.Logf("Fast catchup from %d to %s is in progress", status.LastRound, *status.Catchpoint)
			break
		}
		if attempt > maxAttempts {
			a.FailNow("Failed to start fast catchup in %d seconds", sleepTime*maxAttempts/1000)
		}
		time.Sleep(sleepTime)
		attempt++
	}

	// wait for fastcatchup to complete and the node is synced
	err = fixture.ClientWaitForRoundWithTimeout(usingNodeRestClient, uint64(targetCatchpointRound+1))
	a.NoError(err)

	primaryLibGoal := fixture.GetLibGoalClientFromNodeController(primaryNode)

	dbRoundAfterCatchpoint := targetCatchpointRound - basics.Round(consensusParams.MaxBalLookback)
	a.True(getStateProofNextRound(a, &primaryLibGoal, dbRoundAfterCatchpoint) < getStateProofNextRound(a, &primaryLibGoal, targetCatchpointRound),
		"No state proof transaction in replay, rounds were %d to %d", dbRoundAfterCatchpoint+1, targetCatchpointRound)
}

func TestStateProofAfterCatchpoint(t *testing.T) {
	// Overview of this test:
	// Configure consensus to generate a state proof transaction after the target catchpoint round, with voters from before
	// the target state proof round.
	// Start a two-node network (primary has 100%, using has 0%)
	// create a web proxy, have the using node use it as a peer, blocking all requests for round #2. ( and allowing everything else )
	// Let it run until the first usable catchpoint, as computed in getFirstCatchpointRound, is generated.
	// instruct the using node to catchpoint catchup from the proxy.
	// wait until the using node is caught up to catchpointRound+1, skipping the "impossible" hole of round #2 and
	// participating in consensus.
	// Wait until the next state proof has most likely been generated.
	// Verify that the state proof's voters data came from the state proof tracker and that the state proof transaction
	// itself happened after catchpoint catchup was completed.
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
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

	catchpointLabel := waitForCatchpointGeneration(t, fixture, primaryNodeRestClient, targetCatchpointRound)

	_, err = usingNodeRestClient.Catchup(catchpointLabel, 0)
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
	// Overview of this test:
	// Start a three-node network (primary has 80%, using has 10% and normal has 10%).
	// Configure consensus to require the primary node and at least on other node to generate state proofs.
	// Start the primary node and a normal node and wait for the network to reach round 3.
	// We remove block number 2 from primary database, this will prevent node2 from catching up and force it to use fast-catchup
	// Let it run until the first usable catchpoint, as computed in getFirstCatchpointRound, is generated.
	// Run Node2
	// wait until the using node is caught up to catchpointRound+1, skipping the "impossible" hole of round #2 and
	// participating in consensus.
	// Stop the normal node.
	// Verify that a state proof transaction on which the normal node could not have signed is accepted.
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
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "ThreeNodesWithRichAcct.json"))

	primaryNode, primaryNodeRestClient, primaryEC := startCatchpointGeneratingNode(a, &fixture, "Primary")
	defer primaryEC.Print()
	defer primaryNode.StopAlgod()
	primaryNodeAddr, err := primaryNode.GetListeningAddress()
	a.NoError(err)

	err = fixture.ClientWaitForRoundWithTimeout(primaryNodeRestClient, 3)
	a.NoError(err)

	normalNode, normalNodeRestClient, normalNodeEC := startCatchpointNormalNode(a, &fixture, "Node1", primaryNodeAddr)
	defer normalNodeEC.Print()
	defer normalNode.StopAlgod()

	err = fixture.ClientWaitForRoundWithTimeout(normalNodeRestClient, 3)
	a.NoError(err)

	// at this point PrimaryNode and Node1 would pass round 3. Before running Node2 we remove block 2 from Primary database.
	// this will force Node2 to use fastcatchup
	primNodeGenDir, err := primaryNode.GetGenesisDir()
	a.NoError(err)
	acc, err := db.MakeAccessor(filepath.Join(primNodeGenDir, "ledger.block.sqlite"), false, false)
	require.NoError(t, err)
	err = acc.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.Exec("delete from blocks where rnd =2 ")
		return err
	})
	require.NoError(t, err)
	acc.Close()

	usingNode, usingNodeRestClient, usingNodeEC := startCatchpointNormalNode(a, &fixture, "Node2", primaryNodeAddr)
	defer usingNodeEC.Print()
	defer usingNode.StopAlgod()

	targetCatchpointRound := getFirstCatchpointRound(&consensusParams)

	catchpointLabel := waitForCatchpointGeneration(t, &fixture, primaryNodeRestClient, targetCatchpointRound)
	_, err = usingNodeRestClient.Catchup(catchpointLabel, 0)
	a.NoError(err)

	err = fixture.ClientWaitForRoundWithTimeout(usingNodeRestClient, uint64(targetCatchpointRound)+1)
	a.NoError(err)

	lastNormalRound, err := fixture.GetLibGoalClientFromNodeController(normalNode).CurrentRound()
	a.NoError(err)
	normalNode.StopAlgod()

	// We wait until we know for sure that we're in a round that contains a state proof signed
	// by the usingNode. we give the test 2*basics.Round(consensusParams.StateProofInterval) worth of time
	// to prevent it from being flaky, since receiving signatures from the newly caught up node might take a while.
	lastNormalNodeSignedRound := basics.Round(lastNormalRound).RoundDownToMultipleOf(basics.Round(consensusParams.StateProofInterval))
	lastNormalNextStateProofRound := lastNormalNodeSignedRound + basics.Round(consensusParams.StateProofInterval)
	targetRound := lastNormalNextStateProofRound + basics.Round(consensusParams.StateProofInterval*2)
	err = fixture.ClientWaitForRoundWithTimeout(usingNodeRestClient, uint64(targetRound))
	a.NoError(err)

	primaryClient := fixture.GetLibGoalClientFromNodeController(primaryNode)
	spNextRound := getStateProofNextRound(a, &primaryClient, targetRound)
	a.True(spNextRound > lastNormalNextStateProofRound)
}
