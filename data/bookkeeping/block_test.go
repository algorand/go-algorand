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

package bookkeeping

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

var delegatesMoney = basics.MicroAlgos{Raw: 1000 * 1000 * 1000}

var proto1 = protocol.ConsensusVersion("Test1")
var proto2 = protocol.ConsensusVersion("Test2")
var proto3 = protocol.ConsensusVersion("Test3")
var protoUnsupported = protocol.ConsensusVersion("TestUnsupported")
var protoDelay = protocol.ConsensusVersion("TestDelay")

func init() {
	params1 := config.Consensus[protocol.ConsensusCurrentVersion]
	params1.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{
		proto2: 0,
	}
	params1.MinUpgradeWaitRounds = 0
	params1.MaxUpgradeWaitRounds = 0
	config.Consensus[proto1] = params1

	params2 := config.Consensus[protocol.ConsensusCurrentVersion]
	params2.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	params2.Bonus.BaseAmount = 5_000_000
	params2.Bonus.DecayInterval = 1_000_000
	config.Consensus[proto2] = params2

	paramsDelay := config.Consensus[protocol.ConsensusCurrentVersion]
	paramsDelay.MinUpgradeWaitRounds = 3
	paramsDelay.MaxUpgradeWaitRounds = 7
	paramsDelay.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{
		proto1: 5,
	}
	config.Consensus[protoDelay] = paramsDelay
}

func TestUpgradeVote(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	s := UpgradeState{
		CurrentProtocol: proto1,
	}

	// Check that applyUpgradeVote correctly verifies validity of the UpgradeVote
	s1, err := s.applyUpgradeVote(basics.Round(1), UpgradeVote{})
	require.Equal(t, err, nil)
	require.Equal(t, s1, s)

	_, err = s.applyUpgradeVote(basics.Round(1), UpgradeVote{UpgradeApprove: true})
	require.NotEqual(t, err, nil)

	_, err = s.applyUpgradeVote(basics.Round(1), UpgradeVote{UpgradePropose: proto2})
	require.Equal(t, err, nil)

	s = UpgradeState{
		CurrentProtocol:        proto1,
		NextProtocol:           proto2,
		NextProtocolApprovals:  config.Consensus[protocol.ConsensusCurrentVersion].UpgradeThreshold - 1,
		NextProtocolVoteBefore: basics.Round(20),
		NextProtocolSwitchOn:   basics.Round(30),
	}

	// Check that applyUpgradeVote rejects concurrent proposal
	_, err = s.applyUpgradeVote(basics.Round(1), UpgradeVote{UpgradePropose: proto3})
	require.NotEqual(t, err, nil)

	// Check that applyUpgradeVote allows votes before deadline and rejects votes after deadline
	s1, err = s.applyUpgradeVote(basics.Round(1), UpgradeVote{UpgradeApprove: true})
	require.Equal(t, err, nil)
	s1.NextProtocolApprovals--
	require.Equal(t, s1, s)

	_, err = s.applyUpgradeVote(basics.Round(20), UpgradeVote{UpgradeApprove: true})
	require.NotEqual(t, err, nil)

	// Check that the proposal gets rejected without sufficient votes
	s1, err = s.applyUpgradeVote(basics.Round(20), UpgradeVote{})
	require.NoError(t, err)
	require.Equal(t, s1.NextProtocol, protocol.ConsensusVersion(""))
	require.Equal(t, s1.NextProtocolApprovals, uint64(0))
	require.Equal(t, s1.NextProtocolVoteBefore, basics.Round(0))
	require.Equal(t, s1.NextProtocolSwitchOn, basics.Round(0))

	// Check that proposal gets approved with sufficient votes
	s.NextProtocolApprovals++
	s1, err = s.applyUpgradeVote(basics.Round(20), UpgradeVote{})
	require.NoError(t, err)
	require.Equal(t, s1.NextProtocol, proto2)

	// Check that proposal gets applied
	s1, err = s.applyUpgradeVote(basics.Round(30), UpgradeVote{})
	require.NoError(t, err)
	require.Equal(t, s1.CurrentProtocol, proto2)
	require.Equal(t, s1.NextProtocol, protocol.ConsensusVersion(""))
	require.Equal(t, s1.NextProtocolApprovals, uint64(0))
	require.Equal(t, s1.NextProtocolVoteBefore, basics.Round(0))
	require.Equal(t, s1.NextProtocolSwitchOn, basics.Round(0))
}

func TestUpgradeVariableDelay(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	s := UpgradeState{
		CurrentProtocol: protoDelay,
	}

	_, err := s.applyUpgradeVote(basics.Round(10), UpgradeVote{UpgradePropose: proto1, UpgradeDelay: 2})
	require.Error(t, err, "accepted upgrade vote with delay less than MinUpgradeWaitRounds")

	_, err = s.applyUpgradeVote(basics.Round(10), UpgradeVote{UpgradePropose: proto1, UpgradeDelay: 8})
	require.Error(t, err, "accepted upgrade vote with delay more than MaxUpgradeWaitRounds")

	_, err = s.applyUpgradeVote(basics.Round(10), UpgradeVote{UpgradePropose: proto1, UpgradeDelay: 5})
	require.NoError(t, err, "did not accept upgrade vote with in-bounds delay")

	_, err = s.applyUpgradeVote(basics.Round(10), UpgradeVote{UpgradePropose: proto1, UpgradeDelay: 3})
	require.NoError(t, err, "did not accept upgrade vote with minimal delay")

	_, err = s.applyUpgradeVote(basics.Round(10), UpgradeVote{UpgradePropose: proto1, UpgradeDelay: 7})
	require.NoError(t, err, "did not accept upgrade vote with maximal delay")

	_, err = s.applyUpgradeVote(basics.Round(10), UpgradeVote{UpgradePropose: proto1, UpgradeDelay: 0})
	require.Error(t, err, "accepted upgrade vote with zero (below minimal) delay")
}

func TestMakeBlockUpgrades(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var b Block
	b.BlockHeader.GenesisID = t.Name()
	b.CurrentProtocol = proto1
	b.BlockHeader.GenesisID = "test"
	crypto.RandBytes(b.BlockHeader.GenesisHash[:])

	b1 := MakeBlock(b.BlockHeader)
	err := b1.PreCheck(b.BlockHeader)
	require.NoError(t, err)
	require.Equal(t, b1.NextProtocol, proto2)

	b2 := MakeBlock(b1.BlockHeader)
	err = b2.PreCheck(b1.BlockHeader)
	require.NoError(t, err)
	require.Equal(t, b2.UpgradePropose, protocol.ConsensusVersion(""))
	require.Equal(t, b2.UpgradeApprove, true)

	b1.NextProtocol = proto3
	b3 := MakeBlock(b1.BlockHeader)
	err = b3.PreCheck(b1.BlockHeader)
	require.NoError(t, err)
	require.Equal(t, b3.UpgradePropose, protocol.ConsensusVersion(""))
	require.Equal(t, b3.UpgradeApprove, false)

	var bd Block
	bd.BlockHeader.GenesisID = t.Name()
	bd.CurrentProtocol = protoDelay
	bd.BlockHeader.GenesisID = "test"
	crypto.RandBytes(bd.BlockHeader.GenesisHash[:])

	bd1 := MakeBlock(bd.BlockHeader)
	err = bd1.PreCheck(bd.BlockHeader)
	require.NoError(t, err)
	require.Equal(t, bd1.UpgradePropose, proto1)
	require.Equal(t, bd1.UpgradeApprove, true)
	require.Equal(t, bd1.UpgradeDelay, basics.Round(5))
	require.Equal(t, bd1.NextProtocol, proto1)
	require.Equal(t, bd1.NextProtocolSwitchOn-bd1.NextProtocolVoteBefore, basics.Round(5))

	bd2 := MakeBlock(bd1.BlockHeader)
	err = bd2.PreCheck(bd1.BlockHeader)
	require.NoError(t, err)
	require.Equal(t, bd2.UpgradePropose, protocol.ConsensusVersion(""))
	require.Equal(t, bd2.UpgradeApprove, true)
	require.Equal(t, bd2.UpgradeDelay, basics.Round(0))
	require.Equal(t, bd2.NextProtocol, proto1)
	require.Equal(t, bd2.NextProtocolSwitchOn-bd2.NextProtocolVoteBefore, basics.Round(5))
}

func TestBlockUnsupported(t *testing.T) { //nolint:paralleltest // Not parallel because it modifies config.Consensus
	partitiontest.PartitionTest(t)
	// t.Parallel() not parallel because it modifies config.Consensus

	var b Block
	b.CurrentProtocol = protoUnsupported

	// Temporarily "support" protoUnsupported
	config.Consensus[protoUnsupported] = config.Consensus[proto2]
	b1 := MakeBlock(b.BlockHeader)
	delete(config.Consensus, protoUnsupported)

	err := b1.PreCheck(b.BlockHeader)
	require.ErrorContains(t, err, "protocol TestUnsupported not supported")
}

func TestTime(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var prev Block
	prev.BlockHeader.GenesisID = t.Name()
	prev.CurrentProtocol = proto1
	prev.BlockHeader.GenesisID = "test"
	crypto.RandBytes(prev.BlockHeader.GenesisHash[:])
	proto := config.Consensus[prev.CurrentProtocol]

	startTime := time.Now().Unix()
	if startTime == 0 {
		startTime++
	}

	prev.TimeStamp = startTime
	b := MakeBlock(prev.BlockHeader)
	require.True(t, b.TimeStamp-startTime <= 1)

	require.NoError(t, b.PreCheck(prev.BlockHeader))

	b.TimeStamp = prev.TimeStamp - 1
	require.ErrorContains(t, b.PreCheck(prev.BlockHeader), "bad timestamp")
	b.TimeStamp = prev.TimeStamp + proto.MaxTimestampIncrement
	require.NoError(t, b.PreCheck(prev.BlockHeader))
	b.TimeStamp = prev.TimeStamp + proto.MaxTimestampIncrement + 1
	require.ErrorContains(t, b.PreCheck(prev.BlockHeader), "bad timestamp")
}

func TestBonus(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var prev Block
	prev.CurrentProtocol = proto1
	prev.BlockHeader.GenesisID = t.Name()
	crypto.RandBytes(prev.BlockHeader.GenesisHash[:])

	b := MakeBlock(prev.BlockHeader)
	require.NoError(t, b.PreCheck(prev.BlockHeader))

	// proto1 has no bonuses
	b.Bonus.Raw++
	require.ErrorContains(t, b.PreCheck(prev.BlockHeader), "bad bonus: {1} != {0}")

	prev.CurrentProtocol = proto2
	prev.Bonus = basics.Algos(5)
	b = MakeBlock(prev.BlockHeader)
	require.NoError(t, b.PreCheck(prev.BlockHeader))

	b.Bonus.Raw++
	require.ErrorContains(t, b.PreCheck(prev.BlockHeader), "bad bonus: {5000001} != {5000000}")

	prev.BlockHeader.Round = 10_000_000 - 1
	b = MakeBlock(prev.BlockHeader)
	require.NoError(t, b.PreCheck(prev.BlockHeader))

	// since current block is 0 mod decayInterval, bonus goes down to 4,950,000
	b.Bonus.Raw++
	require.ErrorContains(t, b.PreCheck(prev.BlockHeader), "bad bonus: {4950001} != {4950000}")
}

func TestRewardsLevel(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var buf bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&buf)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	var prev Block
	prev.RewardsLevel = 1
	prev.RewardsRate = 10

	rewardUnits := uint64(10)
	state := prev.NextRewardsState(prev.Round()+1, proto, basics.MicroAlgos{}, rewardUnits, log)
	require.Equal(t, uint64(2), state.RewardsLevel)
	require.Equal(t, uint64(0), state.RewardsResidue)

	assert.Zero(t, buf.Len())
}

func TestRewardsLevelWithResidue(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var buf bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&buf)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var prev Block
	prev.RewardsLevel = 1
	prev.RewardsResidue = 99
	prev.RewardsRate = 1

	rewardUnits := uint64(10)
	state := prev.NextRewardsState(prev.Round()+1, proto, basics.MicroAlgos{}, rewardUnits, log)
	require.Equal(t, uint64(11), state.RewardsLevel)
	require.Equal(t, uint64(0), state.RewardsResidue)

	assert.Zero(t, buf.Len())
}

func TestRewardsLevelNoUnits(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var buf bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&buf)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var prev Block
	prev.RewardsLevel = 1
	prev.RewardsResidue = 2

	rewardUnits := uint64(0)
	state := prev.NextRewardsState(prev.Round()+1, proto, basics.MicroAlgos{}, rewardUnits, log)
	require.Equal(t, prev.RewardsLevel, state.RewardsLevel)
	require.Equal(t, prev.RewardsResidue, state.RewardsResidue)

	assert.Zero(t, buf.Len())
}

func TestTinyLevel(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var buf bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&buf)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var prev Block
	unitsInAlgos := uint64(1000 * 1000)
	prev.RewardsRate = 10 * unitsInAlgos
	algosInSystem := uint64(1000 * 1000 * 1000)
	rewardUnits := algosInSystem * unitsInAlgos / proto.RewardUnit
	state := prev.NextRewardsState(prev.Round()+1, proto, basics.MicroAlgos{}, rewardUnits, log)
	require.True(t, state.RewardsLevel > 0 || state.RewardsResidue > 0)

	assert.Zero(t, buf.Len())
}

func TestRewardsRate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var buf bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&buf)

	var prev Block
	prev.RewardsLevel = 1
	prev.RewardsRate = 10
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	// next round should NOT refresh
	prev.BlockHeader.Round = basics.Round(proto.RewardsRateRefreshInterval)
	prev.BlockHeader.RewardsRecalculationRound = prev.BlockHeader.Round
	incentivePoolBalance := basics.MicroAlgos{Raw: 1000 * uint64(proto.RewardsRateRefreshInterval)}

	// make sure that RewardsRate stays the same
	state := prev.NextRewardsState(prev.Round()+1, proto, incentivePoolBalance, 0, log)
	require.Equal(t, prev.RewardsRate, state.RewardsRate)
	require.Equal(t, prev.BlockHeader.RewardsRecalculationRound, state.RewardsRecalculationRound)

	assert.Zero(t, buf.Len())
}

func TestRewardsRateRefresh(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var buf bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&buf)

	var prev Block
	prev.RewardsLevel = 1
	prev.RewardsRate = 10
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	// next round SHOULD refresh
	prev.BlockHeader.Round = basics.Round(proto.RewardsRateRefreshInterval - 1)
	prev.BlockHeader.RewardsRecalculationRound = prev.Round() + 1
	incentivePoolBalance := basics.MicroAlgos{Raw: 1000 * uint64(proto.RewardsRateRefreshInterval)}
	// make sure that RewardsRate was recomputed
	nextRound := prev.Round() + 1
	state := prev.NextRewardsState(nextRound, proto, incentivePoolBalance, 0, log)
	require.Equal(t, (incentivePoolBalance.Raw-proto.MinBalance)/uint64(proto.RewardsRateRefreshInterval), state.RewardsRate)
	require.Equal(t, nextRound+basics.Round(proto.RewardsRateRefreshInterval), state.RewardsRecalculationRound)

	assert.Zero(t, buf.Len())
}

func TestEncodeDecodeSignedTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var b Block
	b.BlockHeader.GenesisID = "foo"
	crypto.RandBytes(b.BlockHeader.GenesisHash[:])
	b.CurrentProtocol = protocol.ConsensusFuture

	var tx transactions.SignedTxn
	tx.Txn.GenesisID = b.BlockHeader.GenesisID
	tx.Txn.GenesisHash = b.BlockHeader.GenesisHash

	txib, err := b.EncodeSignedTxn(tx, transactions.ApplyData{})
	require.NoError(t, err)

	t2, _, err := b.DecodeSignedTxn(txib)
	require.NoError(t, err)
	require.Equal(t, tx, t2)
}

func TestEncodeMalformedSignedTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var b Block
	b.BlockHeader.GenesisID = "foo"
	b.BlockHeader.CurrentProtocol = protocol.ConsensusCurrentVersion
	crypto.RandBytes(b.BlockHeader.GenesisHash[:])

	var tx transactions.SignedTxn
	tx.Txn.GenesisID = b.BlockHeader.GenesisID
	tx.Txn.GenesisHash = b.BlockHeader.GenesisHash

	_, err := b.EncodeSignedTxn(tx, transactions.ApplyData{})
	require.NoError(t, err)

	tx.Txn.GenesisID = "bar"
	_, err = b.EncodeSignedTxn(tx, transactions.ApplyData{})
	require.Error(t, err)

	tx.Txn.GenesisID = b.BlockHeader.GenesisID
	crypto.RandBytes(tx.Txn.GenesisHash[:])
	_, err = b.EncodeSignedTxn(tx, transactions.ApplyData{})
	require.Error(t, err)
}

func TestDecodeMalformedSignedTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var b Block
	b.BlockHeader.GenesisID = "foo"
	b.BlockHeader.CurrentProtocol = protocol.ConsensusCurrentVersion
	crypto.RandBytes(b.BlockHeader.GenesisHash[:])

	var txib1 transactions.SignedTxnInBlock
	txib1.SignedTxn.Txn.GenesisID = b.BlockHeader.GenesisID
	_, _, err := b.DecodeSignedTxn(txib1)
	require.Error(t, err)

	var txib2 transactions.SignedTxnInBlock
	txib2.SignedTxn.Txn.GenesisHash = b.BlockHeader.GenesisHash
	_, _, err = b.DecodeSignedTxn(txib2)
	require.Error(t, err)
}

// TestInitialRewardsRateCalculation perform positive and negative testing for the InitialRewardsRateCalculation fix by
// running the rounds in the same way eval() is executing them over RewardsRateRefreshInterval rounds.
func TestInitialRewardsRateCalculation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]
	consensusParams.RewardsCalculationFix = false

	runTest := func() bool {
		var buf bytes.Buffer
		log := logging.NewLogger()
		log.SetOutput(&buf)

		incentivePoolBalance := uint64(125000000000000)
		totalRewardUnits := uint64(10000000000)
		require.GreaterOrEqual(t, incentivePoolBalance, consensusParams.MinBalance)

		curRewardsState := RewardsState{
			RewardsLevel:              0,
			RewardsResidue:            0,
			RewardsRecalculationRound: basics.Round(consensusParams.RewardsRateRefreshInterval),
		}
		if consensusParams.InitialRewardsRateCalculation {
			curRewardsState.RewardsRate = basics.SubSaturate(incentivePoolBalance, consensusParams.MinBalance) / uint64(consensusParams.RewardsRateRefreshInterval)
		} else {
			curRewardsState.RewardsRate = incentivePoolBalance / uint64(consensusParams.RewardsRateRefreshInterval)
		}
		for rnd := 1; rnd < int(consensusParams.RewardsRateRefreshInterval+2); rnd++ {
			nextRewardState := curRewardsState.NextRewardsState(basics.Round(rnd), consensusParams, basics.MicroAlgos{Raw: incentivePoolBalance}, totalRewardUnits, log)
			// adjust the incentive pool balance
			var ot basics.OverflowTracker

			// get number of rewards per unit
			rewardsPerUnit := ot.Sub(nextRewardState.RewardsLevel, curRewardsState.RewardsLevel)
			require.False(t, ot.Overflowed)

			// subtract the total dispersed funds from the pool balance
			incentivePoolBalance = ot.Sub(incentivePoolBalance, ot.Mul(totalRewardUnits, rewardsPerUnit))
			require.False(t, ot.Overflowed)

			// make sure the pool retain at least the min balance
			ot.Sub(incentivePoolBalance, consensusParams.MinBalance)
			if ot.Overflowed {
				return false
			}

			// prepare for the next iteration
			curRewardsState = nextRewardState
		}

		assert.Zero(t, buf.Len())
		return true
	}

	// test expected failuire
	consensusParams.InitialRewardsRateCalculation = false
	require.False(t, runTest())

	// test expected success
	consensusParams.InitialRewardsRateCalculation = true
	require.True(t, runTest())
}

func performRewardsRateCalculation(
	t *testing.T, consensusParams config.ConsensusParams,
	curRewardsState RewardsState,
	incentivePoolBalance uint64, totalRewardUnits uint64, startingRound uint64, overspends bool, logs bool) {
	var buf bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&buf)
	defer func() {
		require.Equal(t, logs, buf.Len() != 0)
	}()

	require.GreaterOrEqual(t, incentivePoolBalance, consensusParams.MinBalance)

	for rnd := startingRound; rnd < startingRound+uint64(consensusParams.RewardsRateRefreshInterval)*3; rnd++ {
		nextRewardState := curRewardsState.NextRewardsState(basics.Round(rnd), consensusParams, basics.MicroAlgos{Raw: incentivePoolBalance}, totalRewardUnits, log)
		// adjust the incentive pool balance
		var ot basics.OverflowTracker

		// get number of rewards per unit
		rewardsPerUnit := ot.Sub(nextRewardState.RewardsLevel, curRewardsState.RewardsLevel)
		require.False(t, ot.Overflowed)

		// subtract the total dispersed funds from the pool balance
		incentivePoolBalance = ot.Sub(incentivePoolBalance, ot.Mul(totalRewardUnits, rewardsPerUnit))
		if ot.Overflowed {
			require.True(t, overspends)
			return
		}

		if incentivePoolBalance < consensusParams.MinBalance {
			require.True(t, overspends)
			return
		}

		// prepare for the next iteration
		curRewardsState = nextRewardState
	}

	require.False(t, overspends)
}

func TestNextRewardsRateWithFix(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto, ok := config.Consensus[protocol.ConsensusCurrentVersion]
	require.True(t, ok)
	proto.RewardsCalculationFix = true

	tests := []struct {
		name                      string
		rewardsRate               uint64
		rewardsLevel              uint64
		rewardsResidue            uint64
		rewardsRecalculationRound basics.Round
		incentivePoolBalance      uint64
		totalRewardUnits          uint64
		startingRound             uint64
		logs                      bool
	}{
		{"zero_rate", 0, 215332, 0, 18500000, proto.MinBalance, 6756334087, 18063999, false},
		// 3 subtests below use parameters found in the block header `startingRound` - 1.
		{"mainnet_0", 24000000, 215332, 545321700, 18500000, 10464550021728, 6756334087,
			18063999, true},
		{"mainnet_1", 24000000, 215332, 521321700, 18500000, 10464550021728, 6756334078,
			18063998, true},
		{"mainnet_2", 24000000, 215332, 425321700, 18500000, 10464550021728, 6756334079,
			18063994, true},
		{"no_residue", 0, 0, 0, 1000000,
			proto.MinBalance + 500000000000 /* 5*10^11 */, 1, 1000000, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			curRewardsState := RewardsState{
				RewardsLevel:              test.rewardsLevel,
				RewardsResidue:            test.rewardsResidue,
				RewardsRecalculationRound: test.rewardsRecalculationRound,
				RewardsRate:               test.rewardsRate,
			}

			performRewardsRateCalculation(
				t, proto, curRewardsState, test.incentivePoolBalance, test.totalRewardUnits,
				test.startingRound, false, test.logs)
		})
	}
}

func TestNextRewardsRateFailsWithoutFix(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto, ok := config.Consensus[protocol.ConsensusCurrentVersion]
	require.True(t, ok)
	proto.RewardsCalculationFix = false

	curRewardsState := RewardsState{
		RewardsLevel:              0,
		RewardsResidue:            0,
		RewardsRecalculationRound: 1000000,
		RewardsRate:               0,
	}

	performRewardsRateCalculation(
		t, proto, curRewardsState, proto.MinBalance+500000000000,
		1, 1000000, true, false)
}

func TestNextRewardsRateWithFixUsesNewRate(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto, ok := config.Consensus[protocol.ConsensusCurrentVersion]
	require.True(t, ok)
	proto.RewardsCalculationFix = true
	proto.MinBalance = 1
	proto.RewardsRateRefreshInterval = 10

	state := RewardsState{
		RewardsLevel:              4,
		RewardsRate:               80,
		RewardsResidue:            2,
		RewardsRecalculationRound: 100,
	}

	var buf bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&buf)

	newState := state.NextRewardsState(
		state.RewardsRecalculationRound, proto, basics.MicroAlgos{Raw: 113}, 10, log)

	expected := RewardsState{
		RewardsLevel:              5,
		RewardsRate:               11,
		RewardsResidue:            3,
		RewardsRecalculationRound: 110,
	}
	assert.Equal(t, expected, newState)

	assert.Zero(t, buf.Len())
}

func TestNextRewardsRateWithFixPoolBalanceInsufficient(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto, ok := config.Consensus[protocol.ConsensusCurrentVersion]
	require.True(t, ok)
	proto.RewardsCalculationFix = true
	proto.MinBalance = 10

	state := RewardsState{
		RewardsLevel:              4,
		RewardsRate:               80,
		RewardsResidue:            21,
		RewardsRecalculationRound: 100,
	}

	var buf bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&buf)

	newState := state.NextRewardsState(
		state.RewardsRecalculationRound, proto, basics.MicroAlgos{Raw: 19}, 10, log)

	expected := RewardsState{
		RewardsLevel:              6,
		RewardsRate:               0,
		RewardsResidue:            1,
		RewardsRecalculationRound: 100 + basics.Round(proto.RewardsRateRefreshInterval),
	}
	assert.Equal(t, expected, newState)

	assert.Contains(
		t, string(buf.Bytes()), "overflowed when trying to refresh RewardsRate")
}

func TestNextRewardsRateWithFixMaxSpentOverOverflow(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto, ok := config.Consensus[protocol.ConsensusCurrentVersion]
	require.True(t, ok)
	proto.RewardsCalculationFix = true
	proto.MinBalance = 10

	state := RewardsState{
		RewardsLevel:              4,
		RewardsRate:               80,
		RewardsResidue:            math.MaxUint64,
		RewardsRecalculationRound: 100,
	}

	var buf bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&buf)

	newState := state.NextRewardsState(
		state.RewardsRecalculationRound, proto, basics.MicroAlgos{Raw: 9009}, 10, log)

	expected := RewardsState{
		RewardsLevel:              4 + math.MaxUint64/10,
		RewardsRate:               0,
		RewardsResidue:            math.MaxUint64 % 10,
		RewardsRecalculationRound: 100 + basics.Round(proto.RewardsRateRefreshInterval),
	}
	assert.Equal(t, expected, newState)

	assert.Contains(
		t, string(buf.Bytes()),
		"overflowed when trying to accumulate MinBalance(10) and "+
			"RewardsResidue(18446744073709551615)")
}

func TestNextRewardsRateWithFixRewardsWithResidueOverflow(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto, ok := config.Consensus[protocol.ConsensusCurrentVersion]
	require.True(t, ok)
	proto.RewardsCalculationFix = true
	proto.MinBalance = 10

	state := RewardsState{
		RewardsLevel:              4,
		RewardsRate:               80,
		RewardsResidue:            math.MaxUint64,
		RewardsRecalculationRound: 100,
	}

	var buf bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&buf)

	newState := state.NextRewardsState(
		state.RewardsRecalculationRound-1, proto, basics.MicroAlgos{Raw: 0}, 1, log)
	assert.Equal(t, state, newState)

	assert.Contains(t, string(buf.Bytes()), "could not compute next reward level")
}

func TestNextRewardsRateWithFixNextRewardLevelOverflow(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	proto, ok := config.Consensus[protocol.ConsensusCurrentVersion]
	require.True(t, ok)
	proto.RewardsCalculationFix = true
	proto.MinBalance = 10

	state := RewardsState{
		RewardsLevel:              math.MaxUint64,
		RewardsRate:               0,
		RewardsResidue:            1,
		RewardsRecalculationRound: 100,
	}

	var buf bytes.Buffer
	log := logging.NewLogger()
	log.SetOutput(&buf)

	newState := state.NextRewardsState(
		state.RewardsRecalculationRound-1, proto, basics.MicroAlgos{Raw: 1000}, 1, log)
	assert.Equal(t, state, newState)

	assert.Contains(t, string(buf.Bytes()), "could not compute next reward level")
}

func TestBlock_ContentsMatchHeader(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	// Create a block without SHA256 TxnCommitments
	var block Block
	block.CurrentProtocol = protocol.ConsensusV32
	crypto.RandBytes(block.BlockHeader.GenesisHash[:])

	for i := 0; i < 1024; i++ {
		txn := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				GenesisHash: block.BlockHeader.GenesisHash,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Amount: basics.MicroAlgos{Raw: crypto.RandUint64()},
			},
		}

		crypto.RandBytes(txn.Sender[:])
		crypto.RandBytes(txn.PaymentTxnFields.Receiver[:])

		sigtxn := transactions.SignedTxn{Txn: txn}
		ad := transactions.ApplyData{}

		stib, err := block.BlockHeader.EncodeSignedTxn(sigtxn, ad)
		a.NoError(err)

		block.Payset = append(block.Payset, stib)
	}

	tree, err := block.TxnMerkleTree()
	a.NoError(err)
	rootSliceSHA512_256 := tree.Root()

	tree, err = block.TxnMerkleTreeSHA256()
	a.NoError(err)
	rootSliceSHA256 := tree.Root()

	badDigestSlice := []byte("(>^-^)>")

	/* Test V32 */
	a.False(block.ContentsMatchHeader())

	copy(block.BlockHeader.TxnCommitments.NativeSha512_256Commitment[:], rootSliceSHA512_256)
	block.BlockHeader.TxnCommitments.Sha256Commitment = crypto.Digest{}
	a.True(block.ContentsMatchHeader())

	copy(block.BlockHeader.TxnCommitments.NativeSha512_256Commitment[:], rootSliceSHA512_256)
	copy(block.BlockHeader.TxnCommitments.Sha256Commitment[:], rootSliceSHA256)
	a.False(block.ContentsMatchHeader())

	copy(block.BlockHeader.TxnCommitments.NativeSha512_256Commitment[:], badDigestSlice)
	copy(block.BlockHeader.TxnCommitments.Sha256Commitment[:], rootSliceSHA256)
	a.False(block.ContentsMatchHeader())

	block.BlockHeader.TxnCommitments.NativeSha512_256Commitment = crypto.Digest{}
	copy(block.BlockHeader.TxnCommitments.Sha256Commitment[:], rootSliceSHA256)
	a.False(block.ContentsMatchHeader())

	/* Test Consensus Current */
	// Create a block with SHA256 TxnCommitments
	block.CurrentProtocol = protocol.ConsensusCurrentVersion

	block.BlockHeader.TxnCommitments.NativeSha512_256Commitment = crypto.Digest{}
	block.BlockHeader.TxnCommitments.Sha256Commitment = crypto.Digest{}
	a.False(block.ContentsMatchHeader())

	// Now update the SHA256 header to its correct value
	copy(block.BlockHeader.TxnCommitments.NativeSha512_256Commitment[:], rootSliceSHA512_256)
	copy(block.BlockHeader.TxnCommitments.Sha256Commitment[:], rootSliceSHA256)
	a.True(block.ContentsMatchHeader())

	copy(block.BlockHeader.TxnCommitments.NativeSha512_256Commitment[:], badDigestSlice)
	copy(block.BlockHeader.TxnCommitments.Sha256Commitment[:], rootSliceSHA256)
	a.False(block.ContentsMatchHeader())

	copy(block.BlockHeader.TxnCommitments.NativeSha512_256Commitment[:], rootSliceSHA512_256)
	copy(block.BlockHeader.TxnCommitments.Sha256Commitment[:], badDigestSlice)
	a.False(block.ContentsMatchHeader())

	block.BlockHeader.TxnCommitments.NativeSha512_256Commitment = crypto.Digest{}
	copy(block.BlockHeader.TxnCommitments.Sha256Commitment[:], rootSliceSHA256)
	a.False(block.ContentsMatchHeader())
}

func TestBlockHeader_Serialization(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	// This serialized block header was generated from V32 e2e test, using the old BlockHeader struct which contains only TxnCommitments SHA512_256 value
	serializedBlkHdr := "8fa3737074810081a16ecd0200a466656573c42007dacb4b6d9ed141b17576bd459ae6421d486da3d4ef2247c409a396b82ea221a466726163ce1dcd64fea367656ea7746573742d7631a26768c42032cb340d569e1f9e4d9690c1ba04d77759bae6f353e13af1becf42dcd7d3bdeba470726576c420a2270bc90e3cc48d56081b3b85c15d6a10e14303a6d42ca2537954ce90beec40a570726f746fa6667574757265a472617465ce0ee6b27fa3726e6402a6727763616c72ce0007a120a3727764c420ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa473656564c420a19005a25abad1ad28ec2298baeda9a17693a9ef12127a5ff3e5fa9258c7e9eba2746306a27473ce625ed0eaa374786ec420508f9330176e6064767b0fb7eb0e8bf68ffbaf995a4c7b37ca0217c5a82b4a60"
	bytesBlkHdr, err := hex.DecodeString(serializedBlkHdr)
	a.NoError(err)

	var blkHdr BlockHeader
	err = protocol.Decode(bytesBlkHdr, &blkHdr)
	a.NoError(err)

	a.Equal(crypto.Digest{}, blkHdr.TxnCommitments.Sha256Commitment)
	a.NotEqual(crypto.Digest{}, blkHdr.TxnCommitments.NativeSha512_256Commitment)
}

func TestBonusUpgrades(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	ma0 := basics.MicroAlgos{Raw: 0}
	ma99 := basics.MicroAlgos{Raw: 99}
	ma100 := basics.MicroAlgos{Raw: 100}
	ma198 := basics.MicroAlgos{Raw: 198}
	ma200 := basics.MicroAlgos{Raw: 200}

	old := config.BonusPlan{}
	plan := config.BonusPlan{}

	// Nothing happens with empty plans
	a.Equal(ma0, computeBonus(1, ma0, plan, old))
	a.Equal(ma100, computeBonus(1, ma100, plan, old))

	// When plan doesn't change, just expect decay on the intervals
	plan.DecayInterval = 100
	a.Equal(ma100, computeBonus(1, ma100, plan, plan))
	a.Equal(ma100, computeBonus(99, ma100, plan, plan))
	a.Equal(ma99, computeBonus(100, ma100, plan, plan))
	a.Equal(ma100, computeBonus(101, ma100, plan, plan))
	a.Equal(ma99, computeBonus(10000, ma100, plan, plan))

	// When plan changes, the new decay is in effect
	d90 := config.BonusPlan{DecayInterval: 90}
	a.Equal(ma100, computeBonus(100, ma100, d90, plan)) // no decay
	a.Equal(ma99, computeBonus(180, ma100, d90, plan))  // decay

	// When plan changes and amount is present, it is installed
	d90.BaseAmount = 200
	a.Equal(ma200, computeBonus(100, ma100, d90, plan)) // no decay (wrong round and upgrade anyway)
	a.Equal(ma200, computeBonus(180, ma100, d90, plan)) // no decay (upgrade)
	a.Equal(ma198, computeBonus(180, ma200, d90, d90))  // decay
	a.Equal(ma99, computeBonus(180, ma100, d90, d90))   // decay (no install)

	// If there's a baseRound, the amount is installed accordingly
	d90.BaseRound = 150
	a.Equal(ma99, computeBonus(90, ma100, d90, plan))   // decay because baseRound delays install
	a.Equal(ma100, computeBonus(149, ma100, d90, plan)) // no decay (interval) but also not installed yet
	a.Equal(ma200, computeBonus(150, ma100, d90, plan)) // no decay (upgrade and immediate change)
	a.Equal(ma200, computeBonus(151, ma100, d90, plan)) // no decay (upgrade and immediate change)

	// same tests, but not the upgrade round. only the "immediate installs" changes
	a.Equal(ma99, computeBonus(90, ma100, d90, d90))   // decay
	a.Equal(ma100, computeBonus(149, ma100, d90, d90)) // no decay (interval) but also not installed yet
	a.Equal(ma200, computeBonus(150, ma100, d90, d90)) // not upgrade, but baseRound means install time
	a.Equal(ma100, computeBonus(151, ma100, d90, d90)) // no decay (interval)
}

// TestFirstYearsBonus shows what the bonuses look like
func TestFirstYearsBonus(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := require.New(t)

	yearSeconds := 365 * 24 * 60 * 60
	yearRounds := int(float64(yearSeconds) / 2.9)

	plan := config.Consensus[protocol.ConsensusFuture].Bonus
	sum := uint64(0)
	bonus := plan.BaseAmount
	interval := int(plan.DecayInterval)
	r := 0
	for i := 0; i < yearRounds; i++ {
		r++
		sum += bonus
		if r%interval == 0 {
			bonus, _ = basics.Muldiv(bonus, 99, 100)
		}
	}
	suma := sum / 1_000_000 // micro to Algos

	fmt.Printf("paid %d algos\n", suma)
	fmt.Printf("bonus start: %d end: %d\n", plan.BaseAmount, bonus)

	// pays about 88M algos
	a.InDelta(88_500_000, suma, 100_000)

	// decline about 35%
	a.InDelta(0.65, float64(bonus)/float64(plan.BaseAmount), 0.01)

	// year 2
	for i := 0; i < yearRounds; i++ {
		r++
		sum += bonus
		if r%interval == 0 {
			bonus, _ = basics.Muldiv(bonus, 99, 100)
		}
	}

	sum2 := sum / 1_000_000 // micro to Algos

	fmt.Printf("paid %d algos after 2 years\n", sum2)
	fmt.Printf("bonus end: %d\n", bonus)

	// pays about 146M algos (total for 2 years)
	a.InDelta(145_700_000, sum2, 100_000)

	// decline about 58%
	a.InDelta(0.42, float64(bonus)/float64(plan.BaseAmount), 0.01)

	// year 3
	for i := 0; i < yearRounds; i++ {
		r++
		sum += bonus
		if r%interval == 0 {
			bonus, _ = basics.Muldiv(bonus, 99, 100)
		}
	}

	sum3 := sum / 1_000_000 // micro to Algos

	fmt.Printf("paid %d algos after 3 years\n", sum3)
	fmt.Printf("bonus end: %d\n", bonus)

	// pays about 182M algos (total for 3 years)
	a.InDelta(182_600_000, sum3, 100_000)

	// declined to about 27% (but foundation funding probably gone anyway)
	a.InDelta(0.27, float64(bonus)/float64(plan.BaseAmount), 0.01)
}
