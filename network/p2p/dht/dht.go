// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"errors"
	"fmt"
	"math/rand"
	"time"

	ds "github.com/ipfs/go-datastore"
	dssync "github.com/ipfs/go-datastore/sync"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p-kad-dht/records"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	crouting "github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/backoff"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/multiformats/go-multihash"

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

// dhtMode returns the appropriate DHT mode based on config.
// If DHTMode is explicitly set, use that. Otherwise:
// - Nodes with listen addresses (NetAddress or P2PHybridNetAddress) default to ModeServer to be discoverable
// - Other nodes default to ModeClient
func dhtMode(cfg config.Local) dht.ModeOpt {
	switch cfg.DHTMode {
	case "server":
		return dht.ModeServer
	case "client":
		return dht.ModeClient
	case "":
		// Default behavior: nodes with listen addresses should be discoverable
		if cfg.IsListenServer() {
			return dht.ModeServer
		}
		return dht.ModeClient
	default:
		return dht.ModeClient
	}
}

var errUnknownProviderKey = errors.New("provider key is not a known discovery namespace")

// maxProviderAddrs is the number of addresses the peerstore may hold for a peer
// before further addresses from its provider announcements are ignored.
const maxProviderAddrs = 16

// namespaceProviderStore keeps provider records for a fixed set of keys only,
// and limits the addresses the peerstore keeps for a peer.
type namespaceProviderStore struct {
	records.ProviderStore
	keys   map[string]struct{}
	pstore peerstore.Peerstore
}

// AddProvider implements records.ProviderStore
func (s *namespaceProviderStore) AddProvider(ctx context.Context, key []byte, prov peer.AddrInfo) error {
	if _, ok := s.keys[string(key)]; !ok {
		return errUnknownProviderKey
	}
	// the peerstore limits the addresses of all peers together, do not let one peer use it up
	if room := maxProviderAddrs - len(s.pstore.Addrs(prov.ID)); room <= 0 {
		prov.Addrs = nil
	} else if len(prov.Addrs) > room {
		prov.Addrs = prov.Addrs[:room]
	}
	return s.ProviderStore.AddProvider(ctx, key, prov)
}

// makeNamespaceProviderStore wraps the default in-memory provider store so that
// it only accepts records for the DHT keys derived from the given discovery namespaces.
func makeNamespaceProviderStore(ctx context.Context, h host.Host, namespaces []string) (*namespaceProviderStore, error) {
	keys := make(map[string]struct{}, len(namespaces))
	for _, ns := range namespaces {
		// same key as routing.RoutingDiscovery derives from a namespace
		key, err := multihash.Sum([]byte(ns), multihash.SHA2_256, -1)
		if err != nil {
			return nil, err
		}
		keys[string(key)] = struct{}{}
	}
	// same datastore as the kad-dht default
	store, err := records.NewProviderManager(ctx, h.ID(), h.Peerstore(), dssync.MutexWrap(ds.NewMapDatastore()))
	if err != nil {
		return nil, err
	}
	return &namespaceProviderStore{ProviderStore: store, keys: keys, pstore: h.Peerstore()}, nil
}

// MakeDHT creates the dht.IpfsDHT object
func MakeDHT(ctx context.Context, h host.Host, networkID algoproto.NetworkID, cfg config.Local, bootstrapFunc func() []peer.AddrInfo, namespaces ...string) (*dht.IpfsDHT, error) {
	dhtCfg := []dht.Option{
		dht.Mode(dhtMode(cfg)),
		// We don't need the value store right now
		dht.DisableValues(),
		dht.ProtocolPrefix(dhtProtocolPrefix(networkID)),
		dht.BootstrapPeersFunc(bootstrapFunc),
	}

	if len(namespaces) > 0 {
		store, err := makeNamespaceProviderStore(ctx, h, namespaces)
		if err != nil {
			return nil, err
		}
		dhtCfg = append(dhtCfg, dht.ProviderStore(store))
	}

	if err := metrics.SetupOTelPrometheusExporter(); err != nil {
		return nil, err
	}

	return dht.New(ctx, h, dhtCfg...)
}

func backoffFactory() backoff.BackoffFactory {
	return backoff.NewExponentialDecorrelatedJitter(minBackoff, maxBackoff, baseBackoff, rand.NewSource(rand.Int63()))
}

// MakeDiscovery creates a discovery.Discovery object using backoff and caching
func MakeDiscovery(r crouting.ContentRouting) (discovery.Discovery, error) {
	return backoff.NewBackoffDiscovery(routing.NewRoutingDiscovery(r), backoffFactory())
}
