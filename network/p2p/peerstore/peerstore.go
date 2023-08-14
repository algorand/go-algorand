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

package peerstore

import (
	"context"
	"fmt"

	ds "github.com/ipfs/go-datastore"
	pebbledb "github.com/ipfs/go-ds-pebble"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2p "github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoreds"
)

// PeerStore implements libp2p's Peerstore and CertifiedAddrBook interfaces.
type PeerStore struct {
	peerStoreCAB
}

// peerStoreCAB combines the libp2p Peerstore and CertifiedAddrBook interfaces.
type peerStoreCAB interface {
	libp2p.Peerstore
	libp2p.CertifiedAddrBook
}

func initDBStore(path string) (ds.Batching, error) {
	store, err := pebbledb.NewDatastore(path, nil)
	return store, err
}

// NewPeerStore creates a new peerstore backed by a datastore.
func NewPeerStore(ctx context.Context, path string, addrInfo []*peer.AddrInfo) (*PeerStore, error) {
	datastore, err := initDBStore(path)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize a peerstore, invalid path for datastore: %w", err)
	}
	ps, err := pstoreds.NewPeerstore(ctx, datastore, pstoreds.DefaultOpts())
	if err != nil {
		return nil, fmt.Errorf("cannot initialize a peerstore: %w", err)
	}

	// initialize peerstore with addresses
	for i := 0; i < len(addrInfo); i++ {
		info := addrInfo[i]
		ps.AddAddrs(info.ID, info.Addrs, libp2p.AddressTTL)
	}
	pstore := &PeerStore{ps}
	return pstore, nil
}
