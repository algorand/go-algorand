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

package p2p

import (
	"context"
	"testing"

	golog "github.com/ipfs/go-log"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
)

func TestCapabilitiesDiscovery(t *testing.T) {
	golog.SetDebugLogging()
	var caps []*CapabilitiesDiscovery
	var addrs []peer.AddrInfo
	testSize := 3
	for i := 0; i < testSize; i++ {
		tempdir := t.TempDir()
		capD, err := MakeCapabilitiesDiscovery(context.Background(), config.GetDefaultLocal(), tempdir, "devtestnet", logging.Base(), []*peer.AddrInfo{})
		require.NoError(t, err)
		caps = append(caps, capD)
		addrs = append(addrs, peer.AddrInfo{
			ID:    capD.Host().ID(),
			Addrs: capD.Host().Addrs(),
		})
	}
	for _, capD := range caps {
		peersAdded := 0
		for _, addr := range addrs {
			added, err := capD.AddPeer(addr)
			require.NoError(t, err)
			require.True(t, added)
			peersAdded++
		}
		err := capD.dht.Bootstrap(context.Background())
		require.NoError(t, err)
		capD.dht.ForceRefresh()
		require.Equal(t, peersAdded, capD.dht.RoutingTable().Size())
	}
}
