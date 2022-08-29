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
	"sync"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestFetchBlock(t *testing.T) {
	partitiontest.PartitionTest(t)

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

	node := basicRPCNode{}
	node.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	node.start()
	defer node.stop()
	rootURL := node.rootURL()

	net.addPeer(rootURL)

	// Disable block authentication
	cfg := config.GetDefaultLocal()
	cfg.CatchupBlockValidateMode = 1
	fetcher := MakeNetworkFetcher(logging.TestingLog(t), net, cfg, nil, false)

	block, _, duration, err := fetcher.FetchBlock(context.Background(), next)

	require.NoError(t, err)
	require.Equal(t, &b, block)
	require.GreaterOrEqual(t, int64(duration), int64(0))

	block, cert, duration, err := fetcher.FetchBlock(context.Background(), next+1)

	require.Error(t, errNoBlockForRound, err)
	require.Contains(t, err.Error(), "FetchBlock failed after multiple blocks download attempts")
	require.Nil(t, block)
	require.Nil(t, cert)
	require.Equal(t, int64(duration), int64(0))
}

func TestConcurrentAttemptsToFetchBlockSuccess(t *testing.T) {
	partitiontest.PartitionTest(t)

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

	node := basicRPCNode{}
	node.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	node.start()
	defer node.stop()
	rootURL := node.rootURL()

	net.addPeer(rootURL)

	// Disable block authentication
	cfg := config.GetDefaultLocal()
	cfg.CatchupBlockValidateMode = 1
	fetcher := MakeNetworkFetcher(logging.TestingLog(t), net, cfg, nil, false)

	// start is used to synchronize concurrent fetchBlock attempts
	// parallelRequests represents number of concurrent attempts
	start := make(chan struct{})
	parallelRequests := int(cfg.CatchupParallelBlocks)
	var wg sync.WaitGroup
	wg.Add(parallelRequests)
	for i := 0; i < parallelRequests; i++ {
		go func() {
			<-start
			block, _, duration, err := fetcher.FetchBlock(context.Background(), next)
			require.NoError(t, err)
			require.Equal(t, &b, block)
			require.GreaterOrEqual(t, int64(duration), int64(0))
			wg.Done()
		}()
	}
	close(start)
	wg.Wait()
}

func TestHTTPPeerNotAvailable(t *testing.T) {
	partitiontest.PartitionTest(t)

	net := &httpTestPeerSource{}

	// Disable block authentication
	cfg := config.GetDefaultLocal()
	cfg.CatchupBlockValidateMode = 1
	cfg.CatchupBlockDownloadRetryAttempts = 1

	fetcher := MakeNetworkFetcher(logging.TestingLog(t), net, cfg, nil, false)

	_, _, _, err := fetcher.FetchBlock(context.Background(), 1)
	require.Contains(t, err.Error(), "recurring non-HTTP peer was provided by the peer selector")
}

func TestFetchBlockFailed(t *testing.T) {
	partitiontest.PartitionTest(t)

	net := &httpTestPeerSource{}
	wsPeer := makeTestUnicastPeer(net, t)
	net.addPeer(wsPeer.GetAddress())

	// Disable block authentication
	cfg := config.GetDefaultLocal()
	cfg.CatchupBlockValidateMode = 1
	cfg.CatchupBlockDownloadRetryAttempts = 1

	fetcher := MakeNetworkFetcher(logging.TestingLog(t), net, cfg, nil, false)

	_, _, _, err := fetcher.FetchBlock(context.Background(), 1)
	require.Contains(t, err.Error(), "FetchBlock failed after multiple blocks download attempts")
}

func TestFetchBlockAuthenticationFailed(t *testing.T) {
	partitiontest.PartitionTest(t)

	ledger, next, _, err := buildTestLedger(t, bookkeeping.Block{})
	if err != nil {
		t.Fatal(err)
		return
	}

	blockServiceConfig := config.GetDefaultLocal()
	blockServiceConfig.EnableBlockService = true
	blockServiceConfig.EnableBlockServiceFallbackToArchiver = false

	net := &httpTestPeerSource{}
	ls := rpcs.MakeBlockService(logging.Base(), blockServiceConfig, ledger, net, "test genesisID")

	node := basicRPCNode{}
	node.RegisterHTTPHandler(rpcs.BlockServiceBlockPath, ls)
	node.start()
	defer node.stop()
	rootURL := node.rootURL()

	net.addPeer(rootURL)

	cfg := config.GetDefaultLocal()
	cfg.CatchupBlockDownloadRetryAttempts = 1

	fetcher := MakeNetworkFetcher(logging.TestingLog(t), net, cfg, &mockedAuthenticator{errorRound: int(next)}, false)

	_, _, _, err = fetcher.FetchBlock(context.Background(), next)
	require.Contains(t, err.Error(), "FetchBlock failed after multiple blocks download attempts")
}
