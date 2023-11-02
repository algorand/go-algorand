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
	"fmt"
	"math/rand"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	crouting "github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/backoff"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/network/p2p/dnsaddr"
	algoproto "github.com/algorand/go-algorand/protocol"
)

const minBackoff = time.Second * 5
const maxBackoff = time.Second * 20
const baseBackoff = float64(1)

// getBootstrapPeersFunc looks up a list of Multiaddrs strings from the dnsaddr records at the primary
// SRV record domain.
func getBootstrapPeersFunc(cfg config.Local, network string) func() []peer.AddrInfo {
	return func() []peer.AddrInfo {
		var addrs []peer.AddrInfo
		bootstraps := cfg.DNSBootstrapArray(algoproto.NetworkID(network))
		for _, dnsBootstrap := range bootstraps {
			controller := dnsaddr.NewMultiaddrDNSResolveController(cfg.DNSSecuritySRVEnforced(), "")
			resolvedAddrs, err := dnsaddr.MultiaddrsFromResolver(dnsBootstrap.PrimarySRVBootstrap, controller)
			if err != nil {
				continue
			}
			for _, resolvedAddr := range resolvedAddrs {
				info, err0 := peer.AddrInfoFromP2pAddr(resolvedAddr)
				if err0 != nil {
					continue
				}
				addrs = append(addrs, *info)
			}
		}
		return addrs
	}
}

func dhtProtocolPrefix(network string) protocol.ID {
	return protocol.ID(fmt.Sprintf("/algorand/kad/%s", network))
}

// MakeDHT creates the dht.IpfsDHT object
func MakeDHT(ctx context.Context, h host.Host, network string, cfg config.Local, bootstrapPeers []*peer.AddrInfo) (*dht.IpfsDHT, error) {
	var peers []peer.AddrInfo
	for _, bPeer := range bootstrapPeers {
		if bPeer != nil {
			peers = append(peers, *bPeer)
		}
	}
	dhtCfg := []dht.Option{
		// Automatically determine server or client mode
		dht.Mode(dht.ModeAutoServer),
		// We don't need the value store right now
		dht.DisableValues(),
		dht.ProtocolPrefix(dhtProtocolPrefix(network)),
		dht.BootstrapPeers(peers...),
	}
	if len(bootstrapPeers) == 0 {
		dhtCfg = append(dhtCfg, dht.BootstrapPeersFunc(getBootstrapPeersFunc(cfg, network)))
	}
	return dht.New(ctx, h, dhtCfg...)
}

func backoffFactory() backoff.BackoffFactory {
	return backoff.NewExponentialDecorrelatedJitter(minBackoff, maxBackoff, baseBackoff, rand.New(rand.NewSource(rand.Int63())))
}

// MakeDiscovery creates a discovery.Discovery object using backoff and cacching
func MakeDiscovery(r crouting.ContentRouting) (discovery.Discovery, error) {
	return backoff.NewBackoffDiscovery(routing.NewRoutingDiscovery(r), backoffFactory(), backoff.WithBackoffDiscoveryReturnedChannelSize(0), backoff.WithBackoffDiscoverySimultaneousQueryBufferSize(0))
}
