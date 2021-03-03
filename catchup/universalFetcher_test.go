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

package catchup

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/rpcs"
)

// TestUGetBlockWs tests the universal fetcher ws peer case
func TestUGetBlockWs(t *testing.T) {

	cfg := config.GetDefaultLocal()
	cfg.EnableCatchupFromArchiveServers = true

	ledger, next, b, err := buildTestLedger(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	version := "2.1"
	blockServiceConfig := config.GetDefaultLocal()
	blockServiceConfig.EnableBlockService = true

	net := &httpTestPeerSource{}

	up := makeTestUnicastPeer(net, version, t)
	ls := rpcs.MakeBlockService(blockServiceConfig, ledger, net, "test genesisID")
	ls.Start()

	fetcher := makeUniversalBlockFetcher(logging.TestingLog(t), net, cfg)

	var block *bookkeeping.Block
	var cert *agreement.Certificate
	var duration time.Duration

	block, cert, _, err = fetcher.fetchBlock(context.Background(), next, up)

	require.NoError(t, err)
	require.Equal(t, &b, block)
	require.GreaterOrEqual(t, int64(duration), int64(0))

	block, cert, duration, err = fetcher.fetchBlock(context.Background(), next+1, up)

	require.Error(t, err)
	require.Contains(t, err.Error(), "requested block is not available")
	require.Nil(t, block)
	require.Nil(t, cert)
	require.Equal(t, int64(duration), int64(0))
}

// TestUGetBlockHttp tests the universal fetcher http peer case
func TestUGetBlockHttp(t *testing.T) {

	cfg := config.GetDefaultLocal()
	cfg.EnableCatchupFromArchiveServers = true

	ledger, next, b, err := buildTestLedger(t)
	if err != nil {
		t.Fatal(err)
		return
	}

	blockServiceConfig := config.GetDefaultLocal()
	blockServiceConfig.EnableBlockService = true

	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(blockServiceConfig, ledger, net, "test genesisID")

	nodeA := basicRPCNode{}
	nodeA.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	nodeA.start()
	defer nodeA.stop()
	rootURL := nodeA.rootURL()

	net.addPeer(rootURL)
	fetcher := makeUniversalBlockFetcher(logging.TestingLog(t), net, cfg)

	var block *bookkeeping.Block
	var cert *agreement.Certificate
	var duration time.Duration
	block, cert, duration, err = fetcher.fetchBlock(context.Background(), next, net.GetPeers()[0])

	require.NoError(t, err)
	require.Equal(t, &b, block)
	require.GreaterOrEqual(t, int64(duration), int64(0))

	block, cert, duration, err = fetcher.fetchBlock(context.Background(), next+1, net.GetPeers()[0])

	require.Error(t, errNoBlockForRound, err)
	require.Contains(t, err.Error(), "No block available for given round")
	require.Nil(t, block)
	require.Nil(t, cert)
	require.Equal(t, int64(duration), int64(0))
}

// TestUGetBlockUnsupported tests the handling of an unsupported peer
func TestUGetBlockUnsupported(t *testing.T) {
	fetcher := universalBlockFetcher{}
	peer := ""
	block, cert, duration, err := fetcher.fetchBlock(context.Background(), 1, peer)
	require.Error(t, err)
	require.Contains(t, err.Error(), "FetchBlock: UniversalFetcher only supports HTTPPeer or UnicastPeer")
	require.Nil(t, block)
	require.Nil(t, cert)
	require.Equal(t, int64(duration), int64(0))
}
