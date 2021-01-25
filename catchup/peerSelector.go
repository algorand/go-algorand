// Copyright (C) 2019-2021 Algorand, Inc.
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

package catchup

import (
	"errors"
	"sort"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/network"
)

// peerSelector is a helper struct used to select the next peer to try and connect to
// for various catchup purposes. Unlike the underlying network GetPeers(), it allows the
// client to provide feedback regarding the peer's performance, and to have the subsequent
// query(s) take advantage of that intel.
type peerSelector struct {
	deadlock.Mutex
	net         network.GossipNode
	peerClasses []peerClass
	pools       []peerPool
}

type peerClass struct {
	initialRank int
	peerClass   network.PeerOption
}

type peerPool struct {
	rank  int
	peers []network.Peer
}

var errPeerSelectorNoPeerPoolsAvailable = errors.New("no peer pools available")
var errPeerSelectorNoPeersAvailable = errors.New("no peers available")

func makePeerSelector(net network.GossipNode, initialPeersClasses []peerClass) *peerSelector {
	selector := &peerSelector{
		net:         net,
		peerClasses: initialPeersClasses,
	}
	sortNeeded := false
	for _, initClass := range initialPeersClasses {
		peers := net.GetPeers(initClass.peerClass)
		for _, peer := range peers {
			sortNeeded = sortNeeded || selector.addToPool(peer, initClass.initialRank)
		}
	}
	if sortNeeded {
		selector.sort()
	}
	return selector
}

func (ps *peerSelector) addToPool(peer network.Peer, rank int) bool {
	// see if we already have a list with that rank:
	for i, peersList := range ps.pools {
		if peersList.rank == rank {
			// we found an existing group, add this peer to the list.
			ps.pools[i] = peerPool{rank: rank, peers: append(peersList.peers, peer)}
			return false
		} else if peersList.rank > rank {
			break
		}
	}
	ps.pools = append(ps.pools, peerPool{rank: rank, peers: []network.Peer{peer}})
	return true
}

func (ps *peerSelector) sort() {
	sort.SliceStable(ps.pools, func(i, j int) bool {
		return ps.pools[i].rank < ps.pools[j].rank
	})
}

func peerAddress(peer network.Peer) string {
	if httpPeer, ok := peer.(network.HTTPPeer); ok {
		return httpPeer.GetAddress()
	} else if unicastPeer, ok := peer.(network.UnicastPeer); ok {
		return unicastPeer.GetAddress()
	}
	return ""
}

func (ps *peerSelector) refreshAvailablePeers() {
	evalPeers := make(map[string]network.Peer)
	for _, pool := range ps.pools {
		for _, localPeer := range pool.peers {
			if peerAddress := peerAddress(localPeer); peerAddress != "" {
				evalPeers[peerAddress] = localPeer
			}
		}
	}
	sortNeeded := false
	for _, initClass := range ps.peerClasses {
		peers := ps.net.GetPeers(initClass.peerClass)
		for _, peer := range peers {
			peerAddress := peerAddress(peer)
			if peerAddress == "" {
				continue
			}
			if _, has := evalPeers[peerAddress]; has {
				delete(evalPeers, peerAddress)
				continue
			}
			// it's an entry which we did not had before.
			sortNeeded = sortNeeded || ps.addToPool(peer, initClass.initialRank)
		}
	}

	// delete the "old" entries.
	for poolIdx := len(ps.pools) - 1; poolIdx >= 0; poolIdx-- {
		pool := ps.pools[poolIdx]
		for peerIdx := len(pool.peers) - 1; peerIdx >= 0; peerIdx-- {
			peer := pool.peers[peerIdx]
			if peerAddress := peerAddress(peer); peerAddress != "" {
				if _, has := evalPeers[peerAddress]; has {
					// need to be removed.
					pool.peers = append(pool.peers[:peerIdx], pool.peers[peerIdx+1:]...)
				}
			}
		}
		if len(pool.peers) == 0 {
			ps.pools = append(ps.pools[:poolIdx], ps.pools[poolIdx+1:]...)
			sortNeeded = true
		} else {
			ps.pools[poolIdx] = pool
		}
	}

	if sortNeeded {
		ps.sort()
	}
}

func (ps *peerSelector) GetNextPeer() (peer network.Peer, err error) {
	ps.Lock()
	defer ps.Unlock()
	ps.refreshAvailablePeers()
	if len(ps.pools) == 0 {
		return nil, errPeerSelectorNoPeerPoolsAvailable
	}
	for _, pool := range ps.pools {
		if len(pool.peers) == 0 {
			continue
		}
		// pick one of the peers at random.
		peerIdx := crypto.RandUint64() % uint64(len(pool.peers))
		peer = pool.peers[peerIdx]
		return
	}

	return nil, errPeerSelectorNoPeersAvailable
}

func (ps *peerSelector) RankPeer(peer network.Peer, rank int) {
	ps.Lock()
	defer ps.Unlock()

	poolIdx, peerIdx := ps.findPeer(peer)
	if poolIdx >= 0 && peerIdx >= 0 {
		// we need to remove the peer from the pool so we can place it in a different location.
		pool := ps.pools[poolIdx]
		if len(pool.peers) > 1 {
			pool.peers = append(pool.peers[:peerIdx], pool.peers[peerIdx+1:]...)
			ps.pools[poolIdx] = pool
		} else {
			// the last peer was removed from the pool; delete this pool.
			ps.pools = append(ps.pools[:poolIdx], ps.pools[poolIdx+1:]...)
		}
	}

	sortNeeded := ps.addToPool(peer, rank)
	if sortNeeded {
		ps.sort()
	}
}

func (ps *peerSelector) findPeer(peer network.Peer) (poolIdx, peerIdx int) {
	for i, pool := range ps.pools {
		for j, localPeer := range pool.peers {
			if localPeer == peer {
				return i, j
			}
		}
	}
	return -1, -1
}
