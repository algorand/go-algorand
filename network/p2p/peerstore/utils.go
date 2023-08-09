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
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// PeerInfoFromAddrs extracts the AddrInfo from a multiaddr string slice.
func PeerInfoFromAddrs(addrs []string) ([]*peer.AddrInfo, map[string]string) {
	var addrInfo []*peer.AddrInfo
	malformedAddrs := make(map[string]string)
	for _, addr := range addrs {
		info, err := PeerInfoFromAddr(addr)
		// track malformed addresses
		if err != nil {
			malformedAddrs[addr] = err.Error()
			continue
		}
		addrInfo = append(addrInfo, info)
	}
	return addrInfo, malformedAddrs
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
