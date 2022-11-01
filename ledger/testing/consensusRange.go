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
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

var consensusByNumber = []protocol.ConsensusVersion{
	"", "", "", "", "", "", "",
	protocol.ConsensusV7,
	protocol.ConsensusV8,
	protocol.ConsensusV9,
	protocol.ConsensusV10,
	protocol.ConsensusV11, // first with viable payset commit type
	protocol.ConsensusV12,
	protocol.ConsensusV13,
	protocol.ConsensusV14,
	protocol.ConsensusV15, // rewards in AD
	protocol.ConsensusV16,
	protocol.ConsensusV17,
	protocol.ConsensusV18,
	protocol.ConsensusV19,
	protocol.ConsensusV20,
	protocol.ConsensusV21,
	protocol.ConsensusV22,
	protocol.ConsensusV23,
	protocol.ConsensusV24, // AVM v2 (apps)
	protocol.ConsensusV25,
	protocol.ConsensusV26,
	protocol.ConsensusV27,
	protocol.ConsensusV28,
	protocol.ConsensusV29,
	protocol.ConsensusV30, // AVM v5 (inner txs)
	protocol.ConsensusV31, // AVM v6 (inner txs with appls)
	protocol.ConsensusV32, // unlimited assets and apps
	protocol.ConsensusV33, // 320 rounds
	protocol.ConsensusV34, // AVM v7, stateproofs
	protocol.ConsensusV35, // minor, double upgrade withe v34
	protocol.ConsensusV36, // box storage
	protocol.ConsensusFuture,
}

// TestConsensusRange allows for running tests against a range of consensus
// versions. Generally `start` will be the version that introduced the feature,
// and `stop` will be 0 to indicate it should work right on up through vFuture.
// `stop` will be an actual version number if we're confirming that something
// STOPS working as of a particular version.  When writing the test for a new
// feature that is currently in vFuture, use the expected version number as
// `start`.  That will correspond to vFuture until a new consensus version is
// created and inserted in consensusByNumber. At that point, your feature is
// probably active in that version. (If it's being held in vFuture, just
// increment your `start`.)
func TestConsensusRange(t *testing.T, start, stop int, test func(t *testing.T, ver int, cv protocol.ConsensusVersion)) {
	if stop == 0 { // Treat 0 as "future"
		stop = len(consensusByNumber) - 1
	}
	require.LessOrEqual(t, start, stop)
	for i := start; i <= stop; i++ {
		var version string
		if i == len(consensusByNumber)-1 {
			version = "vFuture"
		} else {
			version = fmt.Sprintf("v%d", i)
		}
		t.Run(fmt.Sprintf("cv=%s", version), func(t *testing.T) {
			test(t, i, consensusByNumber[i])
		})
	}
}

// BenchConsensusRange is for getting benchmarks across consensus versions.
func BenchConsensusRange(b *testing.B, start, stop int, bench func(t *testing.B, ver int, cv protocol.ConsensusVersion)) {
	if stop == 0 { // Treat 0 as "future"
		stop = len(consensusByNumber) - 1
	}
	for i := start; i <= stop; i++ {
		var version string
		if i == len(consensusByNumber)-1 {
			version = "vFuture"
		} else {
			version = fmt.Sprintf("v%d", i)
		}
		b.Run(fmt.Sprintf("cv=%s", version), func(b *testing.B) {
			bench(b, i, consensusByNumber[i])
		})
	}
}
