// Copyright (C) 2019-2023 Algorand, Inc.
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

package dht

import (
	"context"
	"testing"

	logging "github.com/ipfs/go-log"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestDHTBasic(t *testing.T) {
	partitiontest.PartitionTest(t)

	h, err := libp2p.New()
	require.NoError(t, err)
	dht, err := MakeDHT(
		context.Background(),
		h,
		"devtestnet",
		config.GetDefaultLocal(),
		[]*peer.AddrInfo{{}})
	require.NoError(t, err)
	_, err = MakeDiscovery(dht)
	require.NoError(t, err)
	err = dht.Bootstrap(context.Background())
	require.NoError(t, err)
}

func TestDHTBasicAlgodev(t *testing.T) {
	partitiontest.PartitionTest(t)

	logging.SetDebugLogging()
	h, err := libp2p.New()
	require.NoError(t, err)
	cfg := config.GetDefaultLocal()
	cfg.DNSBootstrapID = "<network>.algodev.network"
	dht, err := MakeDHT(context.Background(), h, "betanet", cfg, []*peer.AddrInfo{})
	require.NoError(t, err)
	_, err = MakeDiscovery(dht)
	require.NoError(t, err)
	err = dht.Bootstrap(context.Background())
	require.NoError(t, err)
}

func TestGetBootstrapPeers(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.DNSBootstrapID = "<network>.algodev.network"
	cfg.DNSSecurityFlags = 0

	addrs := getBootstrapPeersFunc(cfg, "test")()

	require.GreaterOrEqual(t, len(addrs), 1)
	addr := addrs[0]
	require.Equal(t, len(addr.Addrs), 1)
	require.GreaterOrEqual(t, len(addr.Addrs), 1)
}

func TestGetBootstrapPeersFailure(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.DNSSecurityFlags = 0
	cfg.DNSBootstrapID = "non-existent.algodev.network"

	addrs := getBootstrapPeersFunc(cfg, "test")()

	require.Equal(t, 0, len(addrs))
}

func TestGetBootstrapPeersInvalidAddr(t *testing.T) {
	t.Parallel()
	partitiontest.PartitionTest(t)

	cfg := config.GetDefaultLocal()
	cfg.DNSSecurityFlags = 0
	cfg.DNSBootstrapID = "<network>.algodev.network"

	addrs := getBootstrapPeersFunc(cfg, "testInvalidAddr")()

	require.Equal(t, 0, len(addrs))
}
