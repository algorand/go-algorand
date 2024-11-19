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

package apply

import (
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBitsMatch(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for b := 0; b <= 6; b++ {
		require.True(t, bitsMatch([]byte{0x1}, []byte{0x2}, b), "%d", b)
	}
	require.False(t, bitsMatch([]byte{0x1}, []byte{0x2}, 7))
	require.False(t, bitsMatch([]byte{0x1}, []byte{0x2}, 8))
	require.False(t, bitsMatch([]byte{0x1}, []byte{0x2}, 9))

	for b := 0; b <= 12; b++ {
		require.True(t, bitsMatch([]byte{0x1, 0xff, 0xaa}, []byte{0x1, 0xf0}, b), "%d", b)
	}
	require.False(t, bitsMatch([]byte{0x1, 0xff, 0xaa}, []byte{0x1, 0xf0}, 13))

	// on a byte boundary
	require.True(t, bitsMatch([]byte{0x1}, []byte{0x1}, 8))
	require.False(t, bitsMatch([]byte{0x1}, []byte{0x1}, 9))
	require.True(t, bitsMatch([]byte{0x1, 0xff}, []byte{0x1, 0x00}, 8))
	require.False(t, bitsMatch([]byte{0x1, 0xff}, []byte{0x1, 00}, 9))
}

func TestFailsChallenge(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := assert.New(t)

	// a valid challenge, with 4 matching bits, and an old last seen
	a.True(challenge{round: 11, seed: [32]byte{0xb0, 0xb4}, bits: 4}.Failed(basics.Address{0xbf, 0x34}, 10))

	// challenge isn't "on"
	a.False(challenge{round: 0, seed: [32]byte{0xb0, 0xb4}, bits: 4}.Failed(basics.Address{0xbf, 0x34}, 10))
	// node has appeared more recently
	a.False(challenge{round: 11, seed: [32]byte{0xb0, 0xb4}, bits: 4}.Failed(basics.Address{0xbf, 0x34}, 12))
	// bits don't match
	a.False(challenge{round: 11, seed: [32]byte{0xb0, 0xb4}, bits: 4}.Failed(basics.Address{0xcf, 0x34}, 10))
	// no enough bits match
	a.False(challenge{round: 11, seed: [32]byte{0xb0, 0xb4}, bits: 5}.Failed(basics.Address{0xbf, 0x34}, 10))
}

type singleSource bookkeeping.BlockHeader

func (ss singleSource) BlockHdr(r basics.Round) (bookkeeping.BlockHeader, error) {
	return bookkeeping.BlockHeader(ss), nil
}

func TestActiveChallenge(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	a := assert.New(t)

	nowHeader := bookkeeping.BlockHeader{
		UpgradeState: bookkeeping.UpgradeState{
			// Here the rules are on, so they certainly differ from rules in oldHeader's params
			CurrentProtocol: protocol.ConsensusFuture,
		},
	}
	rules := config.Consensus[nowHeader.CurrentProtocol].Payouts

	// simplest test. when interval=X and grace=G, X+G+1 is a challenge
	inChallenge := basics.Round(rules.ChallengeInterval + rules.ChallengeGracePeriod + 1)
	ch := FindChallenge(rules, inChallenge, singleSource(nowHeader), ChActive)
	a.NotZero(ch.round)

	// all rounds before that have no challenge
	for r := basics.Round(1); r < inChallenge; r++ {
		ch := FindChallenge(rules, r, singleSource(nowHeader), ChActive)
		a.Zero(ch.round, r)
	}

	// ChallengeGracePeriod rounds allow challenges starting with inChallenge
	for r := inChallenge; r < inChallenge+basics.Round(rules.ChallengeGracePeriod); r++ {
		ch := FindChallenge(rules, r, singleSource(nowHeader), ChActive)
		a.EqualValues(ch.round, rules.ChallengeInterval)
	}

	// And the next round is again challenge-less
	ch = FindChallenge(rules, inChallenge+basics.Round(rules.ChallengeGracePeriod), singleSource(nowHeader), ChActive)
	a.Zero(ch.round)

	// ignore challenge if upgrade happened
	oldHeader := bookkeeping.BlockHeader{
		UpgradeState: bookkeeping.UpgradeState{
			// We need a version from before payouts got turned on
			CurrentProtocol: protocol.ConsensusV39,
		},
	}
	ch = FindChallenge(rules, inChallenge, singleSource(oldHeader), ChActive)
	a.Zero(ch.round)
}
