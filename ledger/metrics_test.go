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

package ledger

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/metrics"
)

func TestMetricsReload(t *testing.T) {
	partitiontest.PartitionTest(t)

	mt := metricsTracker{}
	accts := ledgertesting.RandomAccounts(1, true)
	ml := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion, []map[basics.Address]basics.AccountData{accts})

	mt.loadFromDisk(ml, 0)
	blk := bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{Round: 1}}
	mt.newBlock(blk, ledgercore.StateDelta{})
	mt.close()

	mt.loadFromDisk(ml, 0)
	blk = bookkeeping.Block{BlockHeader: bookkeeping.BlockHeader{Round: 2}}
	mt.newBlock(blk, ledgercore.StateDelta{})

	var buf strings.Builder
	metrics.DefaultRegistry().WriteMetrics(&buf, "")
	lines := strings.Split(buf.String(), "\n")
	txCount := 0
	rcCount := 0
	rCount := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "# HELP") || strings.HasPrefix(line, "# TYPE") {
			// ignore comments
			continue
		}
		if strings.HasPrefix(line, metrics.LedgerTransactionsTotal.Name) {
			txCount++
		}
		if strings.HasPrefix(line, metrics.LedgerRewardClaimsTotal.Name) {
			rcCount++
		}
		if strings.HasPrefix(line, metrics.LedgerRound.Name) {
			rCount++
		}
	}
	require.Equal(t, 1, txCount)
	require.Equal(t, 1, rcCount)
	require.Equal(t, 1, rCount)

	mt.close()
}
