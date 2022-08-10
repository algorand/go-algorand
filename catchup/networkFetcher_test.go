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

package catchup

import (
	"context"
	"testing"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestFetchBlock(t *testing.T) {
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()

	ledger, next, b, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}

	blockServiceConfig := config.GetDefaultLocal()
	blockServiceConfig.EnableBlockService = true
	blockServiceConfig.EnableBlockServiceFallbackToArchiver = false

	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, ledger, net, "test genesisID")

	nodeA := basicRPCNode{}
	nodeA.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()

	net.addPeer(rootURL)

	fetcher := NewNetworkFetcher(logging.TestingLog(t), net, cfg, false)

	var block *bookkeeping.Block
	var cert *agreement.Certificate
	var duration time.Duration
	block, _, duration, err = fetcher.FetchBlock(context.Background(), next)

	require.NoError(t, err)
	require.Equal(t, &b, block)
	require.GreaterOrEqual(t, int64(duration), int64(0))

	block, _, duration, err = fetcher.FetchBlock(context.Background(), next+1)

	require.Error(t, errNoBlockForRound, err)
	require.Contains(t, err.Error(), "No block available for given round")
	require.Nil(t, block)
	require.Nil(t, cert)
	require.Equal(t, int64(duration), int64(0))
}
