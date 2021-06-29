// Copyright (C) 2019-2021 Algorand, Inc.
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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
   "github.com/algorand/go-algorand/testPartitioning"
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
   testPartitioning.PartitionTest(t)

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
   testPartitioning.PartitionTest(t)

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
   testPartitioning.PartitionTest(t)

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

func TestBlockUnsupported(t *testing.T) {
   testPartitioning.PartitionTest(t)

	var b Block
	b.CurrentProtocol = protoUnsupported

	// Temporarily "support" protoUnsupported
	config.Consensus[protoUnsupported] = config.Consensus[proto2]
	b1 := MakeBlock(b.BlockHeader)
	delete(config.Consensus, protoUnsupported)

	err := b1.PreCheck(b.BlockHeader)
	require.Error(t, err)
}

func TestTime(t *testing.T) {
   testPartitioning.PartitionTest(t)

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
	require.Error(t, b.PreCheck(prev.BlockHeader))
	b.TimeStamp = prev.TimeStamp + proto.MaxTimestampIncrement
	require.NoError(t, b.PreCheck(prev.BlockHeader))
	b.TimeStamp = prev.TimeStamp + proto.MaxTimestampIncrement + 1
	require.Error(t, b.PreCheck(prev.BlockHeader))
}

func TestRewardsLevel(t *testing.T) {
   testPartitioning.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	var prev Block
	prev.RewardsLevel = 1
	prev.RewardsRate = 10

	rewardUnits := uint64(10)
	state := prev.NextRewardsState(prev.Round()+1, proto, basics.MicroAlgos{}, rewardUnits)
	require.Equal(t, uint64(2), state.RewardsLevel)
	require.Equal(t, uint64(0), state.RewardsResidue)
}

func TestRewardsLevelWithResidue(t *testing.T) {
   testPartitioning.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var prev Block
	prev.RewardsLevel = 1
	prev.RewardsResidue = 99
	prev.RewardsRate = 1

	rewardUnits := uint64(10)
	state := prev.NextRewardsState(prev.Round()+1, proto, basics.MicroAlgos{}, rewardUnits)
	require.Equal(t, uint64(11), state.RewardsLevel)
	require.Equal(t, uint64(0), state.RewardsResidue)
}

func TestRewardsLevelNoUnits(t *testing.T) {
   testPartitioning.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var prev Block
	prev.RewardsLevel = 1
	prev.RewardsResidue = 2

	rewardUnits := uint64(0)
	state := prev.NextRewardsState(prev.Round()+1, proto, basics.MicroAlgos{}, rewardUnits)
	require.Equal(t, prev.RewardsLevel, state.RewardsLevel)
	require.Equal(t, prev.RewardsResidue, state.RewardsResidue)
}

func TestTinyLevel(t *testing.T) {
   testPartitioning.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	var prev Block
	unitsInAlgos := uint64(1000 * 1000)
	prev.RewardsRate = 10 * unitsInAlgos
	algosInSystem := uint64(1000 * 1000 * 1000)
	rewardUnits := algosInSystem * unitsInAlgos / proto.RewardUnit
	state := prev.NextRewardsState(prev.Round()+1, proto, basics.MicroAlgos{}, rewardUnits)
	require.True(t, state.RewardsLevel > 0 || state.RewardsResidue > 0)
}

func TestRewardsRate(t *testing.T) {
   testPartitioning.PartitionTest(t)

	var prev Block
	prev.RewardsLevel = 1
	prev.RewardsRate = 10
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	// next round should NOT refresh
	prev.BlockHeader.Round = basics.Round(proto.RewardsRateRefreshInterval)
	prev.BlockHeader.RewardsRecalculationRound = prev.BlockHeader.Round
	incentivePoolBalance := basics.MicroAlgos{Raw: 1000 * uint64(proto.RewardsRateRefreshInterval)}

	// make sure that RewardsRate stays the same
	state := prev.NextRewardsState(prev.Round()+1, proto, incentivePoolBalance, 0)
	require.Equal(t, prev.RewardsRate, state.RewardsRate)
	require.Equal(t, prev.BlockHeader.RewardsRecalculationRound, state.RewardsRecalculationRound)
}

func TestRewardsRateRefresh(t *testing.T) {
   testPartitioning.PartitionTest(t)

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
	state := prev.NextRewardsState(nextRound, proto, incentivePoolBalance, 0)
	require.Equal(t, (incentivePoolBalance.Raw-proto.MinBalance)/uint64(proto.RewardsRateRefreshInterval), state.RewardsRate)
	require.Equal(t, nextRound+basics.Round(proto.RewardsRateRefreshInterval), state.RewardsRecalculationRound)
}

func TestEncodeDecodeSignedTxn(t *testing.T) {
   testPartitioning.PartitionTest(t)

	var b Block
	b.BlockHeader.GenesisID = "foo"
	crypto.RandBytes(b.BlockHeader.GenesisHash[:])

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
   testPartitioning.PartitionTest(t)

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
   testPartitioning.PartitionTest(t)

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
   testPartitioning.PartitionTest(t)

	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]

	runTest := func() bool {
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
			nextRewardState := curRewardsState.NextRewardsState(basics.Round(rnd), consensusParams, basics.MicroAlgos{Raw: incentivePoolBalance}, totalRewardUnits)
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
		return true
	}

	// test expected failuire
	consensusParams.InitialRewardsRateCalculation = false
	require.False(t, runTest())

	// test expected success
	consensusParams.InitialRewardsRateCalculation = true
	require.True(t, runTest())
}
