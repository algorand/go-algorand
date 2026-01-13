// Copyright (C) 2019-2025 Algorand, Inc.
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
		func() []peer.AddrInfo { return nil })
	require.NoError(t, err)
	_, err = MakeDiscovery(dht)
	require.NoError(t, err)
	err = dht.Bootstrap(context.Background())
	require.NoError(t, err)
}

func TestMakeDHTWithModes(t *testing.T) {
	partitiontest.PartitionTest(t)

	modes := []string{"", "server", "client"}
	for _, mode := range modes {
		t.Run("mode_"+mode, func(t *testing.T) {
			h, err := libp2p.New()
			require.NoError(t, err)
			defer h.Close()

			cfg := config.GetDefaultLocal()
			cfg.DHTMode = mode

			dht, err := MakeDHT(
				context.Background(),
				h,
				"devtestnet",
				cfg,
				func() []peer.AddrInfo { return nil })
			require.NoError(t, err)
			require.NotNil(t, dht)
			err = dht.Close()
			require.NoError(t, err)
		})
	}
}

func TestDHTModeDefaults(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Run("node with NetAddress defaults to server mode", func(t *testing.T) {
		cfg := config.GetDefaultLocal()
		cfg.NetAddress = ":4160"
		cfg.DHTMode = ""

		h, err := libp2p.New()
		require.NoError(t, err)
		defer h.Close()

		dht, err := MakeDHT(context.Background(), h, "devtestnet", cfg, func() []peer.AddrInfo { return nil })
		require.NoError(t, err)
		require.NotNil(t, dht)
		err = dht.Close()
		require.NoError(t, err)
	})

	t.Run("node without NetAddress defaults to client mode", func(t *testing.T) {
		cfg := config.GetDefaultLocal()
		cfg.NetAddress = ""
		cfg.DHTMode = ""

		h, err := libp2p.New()
		require.NoError(t, err)
		defer h.Close()

		dht, err := MakeDHT(context.Background(), h, "devtestnet", cfg, func() []peer.AddrInfo { return nil })
		require.NoError(t, err)
		require.NotNil(t, dht)
		err = dht.Close()
		require.NoError(t, err)
	})
}

func TestDHTBasicAlgodev(t *testing.T) {
	partitiontest.PartitionTest(t)

	logging.SetDebugLogging()
	h, err := libp2p.New()
	require.NoError(t, err)
	cfg := config.GetDefaultLocal()
	cfg.DNSBootstrapID = "<network>.algodev.network"
	dht, err := MakeDHT(context.Background(), h, "betanet", cfg, func() []peer.AddrInfo { return nil })
	require.NoError(t, err)
	_, err = MakeDiscovery(dht)
	require.NoError(t, err)
	err = dht.Bootstrap(context.Background())
	require.NoError(t, err)
}
