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
	"fmt"
	"math/rand"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	dhtmetrics "github.com/libp2p/go-libp2p-kad-dht/metrics"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	crouting "github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/backoff"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"go.opencensus.io/stats/view"

	"github.com/algorand/go-algorand/config"
	algoproto "github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/metrics"
)

const minBackoff = time.Second * 5
const maxBackoff = time.Second * 20
const baseBackoff = float64(1.1)

func dhtProtocolPrefix(networkID algoproto.NetworkID) protocol.ID {
	return protocol.ID(fmt.Sprintf("/algorand/kad/%s", networkID))
}

// MakeDHT creates the dht.IpfsDHT object
func MakeDHT(ctx context.Context, h host.Host, networkID algoproto.NetworkID, cfg config.Local, bootstrapFunc func() []peer.AddrInfo) (*dht.IpfsDHT, error) {
	dhtCfg := []dht.Option{
		// Automatically determine server or client mode
		dht.Mode(dht.ModeAutoServer),
		// We don't need the value store right now
		dht.DisableValues(),
		dht.ProtocolPrefix(dhtProtocolPrefix(networkID)),
		dht.BootstrapPeersFunc(bootstrapFunc),
	}

	if err := view.Register(dhtmetrics.DefaultViews...); err != nil {
		return nil, err
	}
	metrics.DefaultRegistry().Register(&metrics.OpencensusDefaultMetrics)

	return dht.New(ctx, h, dhtCfg...)
}

func backoffFactory() backoff.BackoffFactory {
	return backoff.NewExponentialDecorrelatedJitter(minBackoff, maxBackoff, baseBackoff, rand.NewSource(rand.Int63()))
}

// MakeDiscovery creates a discovery.Discovery object using backoff and caching
func MakeDiscovery(r crouting.ContentRouting) (discovery.Discovery, error) {
	return backoff.NewBackoffDiscovery(routing.NewRoutingDiscovery(r), backoffFactory())
}
