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
	"time"

	golog "github.com/ipfs/go-log"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	algodht "github.com/algorand/go-algorand/network/p2p/dht"
	"github.com/algorand/go-algorand/network/p2p/peerstore"
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

func setupDHTHosts(t *testing.T, numHosts int) []*dht.IpfsDHT {
	var hosts []host.Host
	var bootstrapPeers []*peer.AddrInfo
	var dhts []*dht.IpfsDHT
	cfg := config.GetDefaultLocal()
	for i := 0; i < numHosts; i++ {
		tmpdir := t.TempDir()
		pk, err := GetPrivKey(cfg, tmpdir)
		require.NoError(t, err)
		ps, err := peerstore.NewPeerStore([]*peer.AddrInfo{})
		require.NoError(t, err)
		h, err := libp2p.New(
			libp2p.ListenAddrStrings("/dns4/localhost/tcp/0"),
			libp2p.Identity(pk),
			libp2p.Peerstore(ps))
		require.NoError(t, err)
		hosts = append(hosts, h)
		bootstrapPeers = append(bootstrapPeers, &peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()})
	}
	for _, h := range hosts {
		ht, err := algodht.MakeDHT(context.Background(), h, "devtestnet", cfg, bootstrapPeers)
		require.NoError(t, err)
		err = ht.Bootstrap(context.Background())
		require.NoError(t, err)
		dhts = append(dhts, ht)
	}
	return dhts
}

func TestDHTTwoPeers(t *testing.T) {
	numAdvertisers := 2
	dhts := setupDHTHosts(t, numAdvertisers)
	topic := "foobar"
	for i, ht := range dhts {
		disc, err := algodht.MakeDiscovery(ht)
		require.NoError(t, err)
		refreshCtx, _ := context.WithTimeout(context.Background(), time.Second*5)
	peersPopulated:
		for {
			select {
			case <-refreshCtx.Done():
				require.Fail(t, "failed to populate routing table before timeout")
			default:
				if ht.RoutingTable().Size() > 0 {
					break peersPopulated
				}
			}
		}
		_, err = disc.Advertise(context.Background(), topic)
		require.NoError(t, err)

		ctx, _ := context.WithTimeout(context.Background(), time.Second*5)
		var advertisers []peer.AddrInfo
		peersChan, err := disc.FindPeers(ctx, topic, discovery.Limit(numAdvertisers))
	pollingForPeers:
		for {
			select {
			case p, open := <-peersChan:
				if p.ID.Size() > 0 {
					advertisers = append(advertisers, p)
				}
				if !open {
					break pollingForPeers
				}
			}
		}
		// Returned peers will include the querying node's ID since it advertises for the topic as well
		require.Equal(t, i+1, len(advertisers))
	}
}
