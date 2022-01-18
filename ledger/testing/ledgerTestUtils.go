// Copyright (C) 2019-2022 Algorand, Inc.
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

package testing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/protocol"
)

// MakeNewEmptyBlockSync returns an empty block which is set to pass eval. afterRound is for syncronizing the block generation
func MakeNewEmptyBlockSync(t *testing.T, afterRound basics.Round, l *ledger.Ledger, genesisID string, initAccounts map[basics.Address]basics.AccountData) (blk bookkeeping.Block) {
	l.WaitForCommit(afterRound)
	return MakeNewEmptyBlock(t, l, genesisID, initAccounts)
}

// MakeNewEmptyBlock returns an empty block which is set to pass eval.
func MakeNewEmptyBlock(t *testing.T, l *ledger.Ledger, genesisID string, initAccounts map[basics.Address]basics.AccountData) (blk bookkeeping.Block) {
	a := require.New(t)

	lastBlock, err := l.Block(l.Latest())
	a.NoError(err, "could not get last block")

	proto := config.Consensus[lastBlock.CurrentProtocol]
	poolAddr := testPoolAddr
	var totalRewardUnits uint64
	if l.Latest() == 0 {
		require.NotNil(t, initAccounts)
		for _, acctdata := range initAccounts {
			if acctdata.Status != basics.NotParticipating {
				totalRewardUnits += acctdata.MicroAlgos.RewardUnits(proto)
			}
		}
	} else {
		latestRound, totals, err := l.LatestTotals()
		require.NoError(t, err)
		require.Equal(t, l.Latest(), latestRound)
		totalRewardUnits = totals.RewardUnits()
	}
	poolBal, err := l.Lookup(l.Latest(), poolAddr)
	a.NoError(err, "could not get incentive pool balance")

	blk.BlockHeader = bookkeeping.BlockHeader{
		GenesisID:    genesisID,
		Round:        l.Latest() + 1,
		Branch:       lastBlock.Hash(),
		TimeStamp:    0,
		RewardsState: lastBlock.NextRewardsState(l.Latest()+1, proto, poolBal.MicroAlgos, totalRewardUnits),
		UpgradeState: lastBlock.UpgradeState,
		// Seed:       does not matter,
		// UpgradeVote: empty,
	}

	blk.TxnRoot, err = blk.PaysetCommit()
	require.NoError(t, err)

	if proto.SupportGenesisHash {
		blk.BlockHeader.GenesisHash = crypto.Hash([]byte(genesisID))
	}

	InitNextBlockHeader(&blk.BlockHeader, lastBlock, proto)

	blk.RewardsPool = testPoolAddr
	blk.FeeSink = testSinkAddr
	blk.CurrentProtocol = lastBlock.CurrentProtocol
	return
}

// InitNextBlockHeader initializes the block header so that the block passes eval
func InitNextBlockHeader(correctHeader *bookkeeping.BlockHeader, lastBlock bookkeeping.Block, proto config.ConsensusParams) {
	if proto.TxnCounter {
		correctHeader.TxnCounter = lastBlock.TxnCounter
	}

	if proto.CompactCertRounds > 0 {
		var ccBasic bookkeeping.CompactCertState
		if lastBlock.CompactCert[protocol.CompactCertBasic].CompactCertNextRound == 0 {
			ccBasic.CompactCertNextRound = (correctHeader.Round + basics.Round(proto.CompactCertVotersLookback)).RoundUpToMultipleOf(basics.Round(proto.CompactCertRounds)) + basics.Round(proto.CompactCertRounds)
		} else {
			ccBasic.CompactCertNextRound = lastBlock.CompactCert[protocol.CompactCertBasic].CompactCertNextRound
		}
		correctHeader.CompactCert = map[protocol.CompactCertType]bookkeeping.CompactCertState{
			protocol.CompactCertBasic: ccBasic,
		}
	}
}
