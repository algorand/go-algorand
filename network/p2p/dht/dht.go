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
)

const minBackoff = time.Second * 5
const maxBackoff = time.Second * 20
const baseBackoff = float64(1)

func dhtProtocolPrefix(network string) protocol.ID {
	return protocol.ID(fmt.Sprintf("/algorand/kad/%s", network))
}

func MakeDHT(ctx context.Context, h host.Host, network string, bootstrapPeers []*peer.AddrInfo) (*dht.IpfsDHT, error) {
	var peers []peer.AddrInfo
	for _, peer := range bootstrapPeers {
		if peer != nil {
			peers = append(peers, *peer)
		}
	}
	cfg := []dht.Option{
		// Automatically determine server or client mode
		dht.Mode(dht.ModeAutoServer),
		// We don't need the value store right now
		dht.DisableValues(),
		dht.ProtocolPrefix(dhtProtocolPrefix(network)),
		dht.BootstrapPeers(peers...),
	}
	return dht.New(ctx, h, cfg...)
}

func backoffFactory() backoff.BackoffFactory {
	return backoff.NewExponentialDecorrelatedJitter(minBackoff, maxBackoff, baseBackoff, rand.New(rand.NewSource(rand.Int63())))
}

func MakeDiscovery(r crouting.ContentRouting) (discovery.Discovery, error) {
	return backoff.NewBackoffDiscovery(routing.NewRoutingDiscovery(r), backoffFactory(), backoff.WithBackoffDiscoveryReturnedChannelSize(0), backoff.WithBackoffDiscoverySimultaneousQueryBufferSize(0))
}
