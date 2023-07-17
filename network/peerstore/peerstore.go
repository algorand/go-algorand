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
	store := &PeerStore{ps}
	return store, nil
}

// PeerInfoFromAddrString extracts the AddrInfo from the multiaddr.
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
