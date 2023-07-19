package peerstore

import (
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// PeerInfoFromAddrs extracts the AddrInfo from a multiaddr string slice.
func PeerInfoFromAddrs(addrs []string) ([]*peer.AddrInfo, error) {
	var addrInfo []*peer.AddrInfo
	for _, addr := range addrs {
		info, err := PeerInfoFromAddr(addr)
		if err != nil {
			return nil, err
		}
		addrInfo = append(addrInfo, info)
	}

	return addrInfo, nil
}

// PeerInfoFromAddr extracts the AddrInfo from a multiaddr string.
func PeerInfoFromAddr(addr string) (*peer.AddrInfo, error) {
	maddr, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return nil, err
	}
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return nil, err
	}
	return info, nil
}
