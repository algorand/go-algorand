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

	ds "github.com/ipfs/go-datastore"
	leveldb "github.com/ipfs/go-ds-leveldb"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2p "github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoreds"
	"github.com/multiformats/go-multiaddr"
)

// PeerStore implements libp2p.Peerstore
type PeerStore struct {
	libp2p.Peerstore
}

func initDBStore(path string) (ds.Batching, error) {
	store, err := leveldb.NewDatastore(path, nil)
	return store, err
}

// NewPeerStore creates a new peerstore backed by a datastore.
// TODO: consider using PebbleDB in the future.
// it is currently still in experimental state. https://github.com/ipfs/go-ds-pebble
func NewPeerStore(ctx context.Context, path string, peerAddresses []string) (*PeerStore, error) {
	datastore, err := initDBStore(path)
	if err != nil {
		return nil, err
	}
	ps, err := pstoreds.NewPeerstore(ctx, datastore, pstoreds.DefaultOpts())
	if err != nil {
		return nil, err
	}

	// initialize peerstore with addresses
	for _, addr := range peerAddresses {
		maddr, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			return nil, err
		}
		// extract the peer ID from the multiaddr.
		info, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			return nil, err
		}
		ps.AddAddrs(info.ID, info.Addrs, libp2p.PermanentAddrTTL)
	}
	pstore := &PeerStore{ps}
	return pstore, nil
}

// PeerInfoFromAddrString extracts the AddrInfo from the multiaddr string.
func (ps PeerStore) PeerInfoFromAddrString(addr string) (*peer.AddrInfo, error) {
	maddr, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return nil, err
	}
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return nil, err
	}
	return info, err
}
