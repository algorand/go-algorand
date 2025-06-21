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

package p2p

import (
	"bytes"
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

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

func setupDHTHosts(t *testing.T, numHosts int) []*dht.IpfsDHT {
	var hosts []host.Host
	var bootstrapPeers []peer.AddrInfo
	var dhts []*dht.IpfsDHT
	cfg := config.GetDefaultLocal()
	for i := 0; i < numHosts; i++ {
		tmpdir := t.TempDir()
		pk, err := GetPrivKey(cfg, tmpdir)
		require.NoError(t, err)
		ps, err := peerstore.NewPeerStore(nil, "")
		require.NoError(t, err)
		h, err := libp2p.New(
			libp2p.ListenAddrStrings("/dns4/localhost/tcp/0"),
			libp2p.Identity(pk),
			libp2p.Peerstore(ps))
		require.NoError(t, err)
		hosts = append(hosts, h)
		bootstrapPeers = append(bootstrapPeers, peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()})
	}
	for _, h := range hosts {
		ht, err := algodht.MakeDHT(context.Background(), h, "devtestnet", cfg, func() []peer.AddrInfo { return bootstrapPeers })
		require.NoError(t, err)
		// this is a workaround for the following issue
		// "failed to negotiate security protocol: error reading handshake message: noise: message is too short"
		// it appears simultaneous connection attempts (dht.New() attempts to connect) causes this handshake error.
		// https://github.com/libp2p/go-libp2p-noise/issues/70
		time.Sleep(200 * time.Millisecond)

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

func setupCapDiscovery(t *testing.T, numHosts int, numBootstrapPeers int) []*CapabilitiesDiscovery {
	var hosts []host.Host
	var bootstrapPeers []peer.AddrInfo
	var capsDisc []*CapabilitiesDiscovery
	cfg := config.GetDefaultLocal()
	for i := 0; i < numHosts; i++ {
		tmpdir := t.TempDir()
		pk, err := GetPrivKey(cfg, tmpdir)
		require.NoError(t, err)
		ps, err := peerstore.NewPeerStore(nil, "")
		require.NoError(t, err)
		h, err := libp2p.New(
			libp2p.ListenAddrStrings("/dns4/localhost/tcp/0"),
			libp2p.Identity(pk),
			libp2p.Peerstore(ps))
		require.NoError(t, err)
		hosts = append(hosts, h)
		bootstrapPeers = append(bootstrapPeers, peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()})
	}
	for _, h := range hosts {
		bp := bootstrapPeers
		if numBootstrapPeers != 0 && numBootstrapPeers != numHosts {
			bp = make([]peer.AddrInfo, len(bootstrapPeers))
			copy(bp, bootstrapPeers)
			rand.Shuffle(len(bootstrapPeers), func(i, j int) {
				bp[i], bp[j] = bp[j], bp[i]
			})
			bp = bp[:numBootstrapPeers]
		}
		ht, err := algodht.MakeDHT(context.Background(), h, "devtestnet", cfg, func() []peer.AddrInfo { return bp })
		require.NoError(t, err)
		// this is a workaround for the following issue
		// "failed to negotiate security protocol: error reading handshake message: noise: message is too short"
		// it appears simultaneous connection attempts (dht.New() attempts to connect) causes this handshake error.
		// https://github.com/libp2p/go-libp2p-noise/issues/70
		time.Sleep(200 * time.Millisecond)

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

func TestCapabilities_DHTTwoPeers(t *testing.T) {
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
		require.NoError(t, err)
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

func TestCapabilities_Varying(t *testing.T) {
	partitiontest.PartitionTest(t)

	const numAdvertisers = 10

	var tests = []struct {
		name         string
		numBootstrap int
	}{
		{"bootstrap=all", numAdvertisers},
		{"bootstrap=2", 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capsDisc := setupCapDiscovery(t, numAdvertisers, test.numBootstrap)
			noCap := capsDisc[:3]
			archOnly := capsDisc[3:5]
			catchOnly := capsDisc[5:7]
			archCatch := capsDisc[7:]

			var wg sync.WaitGroup
			wg.Add(len(archOnly) + len(catchOnly) + len(archCatch))
			for _, disc := range archOnly {
				go func(disc *CapabilitiesDiscovery) {
					defer wg.Done()
					waitForRouting(t, disc)
					disc.AdvertiseCapabilities(Archival)
				}(disc)
			}
			for _, disc := range catchOnly {
				go func(disc *CapabilitiesDiscovery) {
					defer wg.Done()
					waitForRouting(t, disc)
					disc.AdvertiseCapabilities(Catchpoints)
				}(disc)
			}
			for _, disc := range archCatch {
				go func(disc *CapabilitiesDiscovery) {
					defer wg.Done()
					waitForRouting(t, disc)
					disc.AdvertiseCapabilities(Archival, Catchpoints)
				}(disc)
			}

			wg.Wait()

			wg.Add(len(noCap) * 2)
			for _, disc := range noCap {
				go func(disc *CapabilitiesDiscovery) {
					defer wg.Done()
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
				}(disc)

				go func(disc *CapabilitiesDiscovery) {
					defer wg.Done()
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
				}(disc)
			}

			wg.Wait()

			for _, disc := range capsDisc[3:] {
				err := disc.Close()
				require.NoError(t, err)
				// Make sure it actually closes
				disc.wg.Wait()
			}
		})
	}
}

func TestCapabilities_ExcludesSelf(t *testing.T) {
	partitiontest.PartitionTest(t)
	disc := setupCapDiscovery(t, 2, 2)

	testPeersFound := func(disc *CapabilitiesDiscovery, n int, cap Capability) bool {
		peers, err := disc.PeersForCapability(cap, n)
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

	err := disc[0].Close()
	require.NoError(t, err)
	disc[0].wg.Wait()
}

// TestCapabilities_NoPeers makes sure no errors logged when no peers in routing table on advertise
func TestCapabilities_NoPeers(t *testing.T) {
	partitiontest.PartitionTest(t)

	// create a single host/DHT => no peers in routing table
	cfg := config.GetDefaultLocal()
	tmpdir := t.TempDir()
	pk, err := GetPrivKey(cfg, tmpdir)
	require.NoError(t, err)
	ps, err := peerstore.NewPeerStore(nil, "")
	require.NoError(t, err)
	h, err := libp2p.New(
		libp2p.ListenAddrStrings("/dns4/localhost/tcp/0"),
		libp2p.Identity(pk),
		libp2p.Peerstore(ps))
	require.NoError(t, err)
	defer h.Close()

	ht, err := algodht.MakeDHT(context.Background(), h, "devtestnet", cfg, func() []peer.AddrInfo { return nil })
	require.NoError(t, err)
	err = ht.Bootstrap(context.Background())
	require.NoError(t, err)
	defer ht.Close()

	disc, err := algodht.MakeDiscovery(ht)
	require.NoError(t, err)

	var buf bytes.Buffer
	log := logging.NewLogger()
	log.SetLevel(logging.Info)
	log.SetOutput(&buf)

	cd := &CapabilitiesDiscovery{
		disc: disc,
		dht:  ht,
		log:  log,
	}
	defer cd.Close()

	cd.AdvertiseCapabilities(Archival)

	// sleep 3x capAdvertisementInitialDelay to allow for the log messages to be generated
	time.Sleep(3 * capAdvertisementInitialDelay)

	logData := buf.String()
	require.NotContains(t, logData, "advertised capability")
	require.NotContains(t, logData, "failed to advertise for capability")
	require.NotContains(t, logData, "failed to find any peer in table")
}
