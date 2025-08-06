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
	"context"
	randv1 "math/rand"
	"math/rand/v2"
	"sync"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	kbucket "github.com/libp2p/go-libp2p-kbucket"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	libpeerstore "github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/discovery/backoff"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	algoDht "github.com/algorand/go-algorand/network/p2p/dht"
	"github.com/algorand/go-algorand/protocol"
)

// Capability represents functions that some nodes may provide and other nodes would want to know about
type Capability string

const (
	// Archival nodes
	Archival Capability = "archival"
	// Catchpoints storing nodes
	Catchpoints = "catchpointStoring"
	// Gossip nodes are non permissioned relays
	Gossip = "gossip"
)

const operationTimeout = time.Second * 5
const maxAdvertisementInterval = time.Hour * 22

// CapabilitiesDiscovery exposes Discovery interfaces and wraps underlying DHT methods to provide capabilities advertisement for the node
type CapabilitiesDiscovery struct {
	disc discovery.Discovery
	dht  *dht.IpfsDHT
	log  logging.Logger
	wg   sync.WaitGroup
}

// advertise implements the discovery.Discovery/discovery.Advertiser interface
func (c *CapabilitiesDiscovery) advertise(ctx context.Context, ns string, opts ...discovery.Option) (time.Duration, error) {
	return c.disc.Advertise(ctx, ns, opts...)
}

// findPeers implements the discovery.Discovery/discovery.Discoverer interface
func (c *CapabilitiesDiscovery) findPeers(ctx context.Context, ns string, opts ...discovery.Option) (<-chan peer.AddrInfo, error) {
	return c.disc.FindPeers(ctx, ns, opts...)
}

// Close should be called when fully shutting down the node
func (c *CapabilitiesDiscovery) Close() error {
	err := c.dht.Close()
	c.wg.Wait()
	return err
}

// Host exposes the underlying libp2p host.Host object
func (c *CapabilitiesDiscovery) Host() host.Host {
	return c.dht.Host()
}

// addPeer adds a given peer.AddrInfo to the Host's Peerstore, and the DHT's routing table
func (c *CapabilitiesDiscovery) addPeer(p peer.AddrInfo) (bool, error) { //nolint:unused // TODO
	c.Host().Peerstore().AddAddrs(p.ID, p.Addrs, libpeerstore.AddressTTL)
	return c.dht.RoutingTable().TryAddPeer(p.ID, true, true)
}

// PeersForCapability returns a slice of peer.AddrInfo for a Capability
// Since CapabilitiesDiscovery uses a backoffcache, it will attempt to hit cache, then disk, then network
// in order to fetch n peers which are advertising the required capability.
func (c *CapabilitiesDiscovery) PeersForCapability(capability Capability, n int) ([]peer.AddrInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	var peers []peer.AddrInfo
	// +1 because it can include self but we exclude self from the returned list
	// that might confuse the caller (and tests assertions)
	peersChan, err := c.findPeers(ctx, string(capability), discovery.Limit(n+1))
	if err != nil {
		return nil, err
	}
	for p := range peersChan {
		if p.ID.Size() > 0 && p.ID != c.Host().ID() {
			peers = append(peers, p)
		}
		if len(peers) >= n {
			break
		}
	}
	return peers, nil
}

const capAdvertisementInitialDelay = time.Second / 10000

// AdvertiseCapabilities periodically runs the Advertiser interface on the DHT
// If a capability fails to advertise we will retry every 100 seconds until full success
// This gets rerun every at the minimum ttl or the maxAdvertisementInterval.
func (c *CapabilitiesDiscovery) AdvertiseCapabilities(capabilities ...Capability) {
	c.wg.Add(1)
	go func() {
		// Run the initial Advertisement immediately
		nextExecution := time.After(capAdvertisementInitialDelay)
		defer func() {
			c.wg.Done()
		}()
		// Create a exp jitter backoff strategy to use for retrying failed advertisements
		ebf := backoff.NewExponentialDecorrelatedJitter(1*time.Second, 100*time.Second, 3.0, randv1.NewSource(randv1.Int63()))
		eb := ebf()

		for {
			// shuffle capabilities to advertise in random order
			// since the DHT's internal advertisement happens concurrently for peers in its routing table
			// any peer error does not prevent advertisement of other peers.
			// on repeated advertisement, we want to avoid the same order to make sure all capabilities are advertised.
			if len(capabilities) > 1 {
				rand.Shuffle(len(capabilities), func(i, j int) {
					capabilities[i], capabilities[j] = capabilities[j], capabilities[i]
				})
			}
			select {
			case <-c.dht.Context().Done():
				return
			case <-nextExecution:
				var err error
				advertisementInterval := maxAdvertisementInterval
				for _, capa := range capabilities {
					ttl, err0 := c.advertise(c.dht.Context(), string(capa))
					if err0 != nil {
						err = err0
						loggerFn := c.log.Errorf
						if err0 == kbucket.ErrLookupFailure {
							// No peers in a routing table, it is typical for startup and not an error
							loggerFn = c.log.Debugf
						}
						loggerFn("failed to advertise for capability %s: %v", capa, err0)
						break
					}
					if ttl < advertisementInterval {
						advertisementInterval = ttl
					}
					c.log.Infof("advertised capability %s", capa)
				}
				// If we failed to advertise, retry every according to exp jitter delays until successful
				if err != nil {
					nextExecution = time.After(eb.Delay())
				} else {
					// Otherwise, ensure we're at the correct interval
					nextExecution = time.After(advertisementInterval)
					eb.Reset()
				}
			}
		}
	}()
}

// Sizer exposes the Size method
type Sizer interface {
	Size() int
}

// RoutingTable exposes some knowledge about the DHT routing table
func (c *CapabilitiesDiscovery) RoutingTable() Sizer {
	return c.dht.RoutingTable()
}

// MakeCapabilitiesDiscovery creates a new CapabilitiesDiscovery object which exposes peer discovery and capabilities advertisement
func MakeCapabilitiesDiscovery(ctx context.Context, cfg config.Local, h host.Host, networkID protocol.NetworkID, log logging.Logger, bootstrapFunc func() []peer.AddrInfo) (*CapabilitiesDiscovery, error) {
	discDht, err := algoDht.MakeDHT(ctx, h, networkID, cfg, bootstrapFunc)
	if err != nil {
		return nil, err
	}
	discImpl, err := algoDht.MakeDiscovery(discDht)
	if err != nil {
		return nil, err
	}
	return &CapabilitiesDiscovery{
		disc: discImpl,
		dht:  discDht,
		log:  log,
	}, nil
}
