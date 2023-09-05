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
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestCapabilitiesDiscovery(t *testing.T) {
	partitiontest.PartitionTest(t)

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

func waitForRouting(t *testing.T, disc *CapabilitiesDiscovery) {
	refreshCtx, refCancel := context.WithTimeout(context.Background(), time.Second*5)
	for {
		select {
		case <-refreshCtx.Done():
			refCancel()
			require.Fail(t, "failed to populate routing table before timeout")
		default:
			if disc.dht.RoutingTable().Size() > 0 {
				refCancel()
				return
			}
		}
	}
}

func setupCapDiscovery(t *testing.T, numHosts int) []*CapabilitiesDiscovery {
	var hosts []host.Host
	var bootstrapPeers []*peer.AddrInfo
	var capsDisc []*CapabilitiesDiscovery
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
		disc, err := algodht.MakeDiscovery(ht)
		require.NoError(t, err)
		cd := &CapabilitiesDiscovery{
			disc: disc,
			dht:  ht,
			log:  logging.Base(),
		}
		capsDisc = append(capsDisc, cd)
	}
	return capsDisc
}

func TestDHTTwoPeers(t *testing.T) {
	partitiontest.PartitionTest(t)

	numAdvertisers := 2
	dhts := setupDHTHosts(t, numAdvertisers)
	topic := "foobar"
	for i, ht := range dhts {
		disc, err := algodht.MakeDiscovery(ht)
		require.NoError(t, err)
		refreshCtx, refCancel := context.WithTimeout(context.Background(), time.Second*5)
	peersPopulated:
		for {
			select {
			case <-refreshCtx.Done():
				refCancel()
				require.Fail(t, "failed to populate routing table before timeout")
			default:
				if ht.RoutingTable().Size() > 0 {
					refCancel()
					break peersPopulated
				}
			}
		}
		_, err = disc.Advertise(context.Background(), topic)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
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
		cancel()
		// Returned peers will include the querying node's ID since it advertises for the topic as well
		require.Equal(t, i+1, len(advertisers))
	}
}

func TestVaryingCapabilities(t *testing.T) {
	partitiontest.PartitionTest(t)

	numAdvertisers := 10
	capsDisc := setupCapDiscovery(t, numAdvertisers)
	noCap := capsDisc[:3]
	archOnly := capsDisc[3:5]
	catchOnly := capsDisc[5:7]
	archCatch := capsDisc[7:]

	for _, disc := range archOnly {
		waitForRouting(t, disc)
		disc.AdvertiseCapabilities(Archival)
	}
	for _, disc := range catchOnly {
		waitForRouting(t, disc)
		disc.AdvertiseCapabilities(Catchpoints)
	}
	for _, disc := range archCatch {
		waitForRouting(t, disc)
		disc.AdvertiseCapabilities(Archival, Catchpoints)
	}

	for _, disc := range noCap {
		require.Eventuallyf(t,
			func() bool {
				numArchPeers := len(archOnly) + len(archCatch)
				peers, err := disc.PeersForCapability(Archival, numArchPeers)
				if err == nil && len(peers) == numArchPeers {
					return true
				}
				return false
			},
			time.Minute,
			time.Second,
			"Not all expected archival peers were found",
		)

		require.Eventuallyf(t,
			func() bool {
				numCatchPeers := len(catchOnly) + len(archCatch)
				peers, err := disc.PeersForCapability(Catchpoints, numCatchPeers)
				if err == nil && len(peers) == numCatchPeers {
					return true
				}
				return false
			},
			time.Minute,
			time.Second,
			"Not all expected catchpoint peers were found",
		)
	}

	for _, disc := range capsDisc[3:] {
		disc.Close()
		// Make sure it actually closes
		disc.wg.Wait()
	}
}

func TestCapabilitiesExcludesSelf(t *testing.T) {
	partitiontest.PartitionTest(t)
	disc := setupCapDiscovery(t, 2)

	testPeersFound := func(disc *CapabilitiesDiscovery, n int, cap Capability) bool {
		peers, err := disc.PeersForCapability(cap, n+1)
		if err == nil && len(peers) == n {
			return true
		}
		return false
	}

	waitForRouting(t, disc[0])
	disc[0].AdvertiseCapabilities(Archival)
	// disc[1] finds Archival
	require.Eventuallyf(t,
		func() bool { return testPeersFound(disc[1], 1, Archival) },
		time.Minute,
		time.Second,
		"Could not find archival peer",
	)

	// disc[0] doesn't find itself
	require.Neverf(t,
		func() bool { return testPeersFound(disc[0], 1, Archival) },
		time.Second*5,
		time.Second,
		"Found self when searching for capability",
	)

	disc[0].Close()
	disc[0].wg.Wait()
}
