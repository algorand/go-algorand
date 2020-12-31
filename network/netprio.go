// Copyright (C) 2019-2020 Algorand, Inc.
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

package network

import (
	"container/heap"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// NetPrioScheme is an implementation of network connection priorities
// based on a challenge-response protocol.
type NetPrioScheme interface {
	NewPrioChallenge() string
	MakePrioResponse(challenge string) []byte
	VerifyPrioResponse(challenge string, response []byte) (basics.Address, error)
	GetPrioWeight(addr basics.Address) uint64
}

func prioResponseHandler(message IncomingMessage) OutgoingMessage {
	wn := message.Net.(*WebsocketNetwork)
	if wn.prioScheme == nil {
		return OutgoingMessage{}
	}

	peer := message.Sender.(*wsPeer)
	challenge := peer.prioChallenge
	if challenge == "" {
		return OutgoingMessage{}
	}

	addr, err := wn.prioScheme.VerifyPrioResponse(challenge, message.Data)
	if err != nil {
		wn.log.Warnf("prioScheme.VerifyPrioResponse from %s: %v", peer.rootURL, err)
	} else {
		weight := wn.prioScheme.GetPrioWeight(addr)

		wn.peersLock.Lock()
		defer wn.peersLock.Unlock()
		wn.prioTracker.setPriority(peer, addr, weight)
	}

	// For testing
	if wn.prioResponseChan != nil {
		wn.prioResponseChan <- peer
	}

	return OutgoingMessage{}
}

var prioHandlers = []TaggedMessageHandler{
	{protocol.NetPrioResponseTag, HandlerFunc(prioResponseHandler)},
}

// The prioTracker sorts active peers by priority, and ensures
// there's only one peer with weight per address.  The data
// structure is not thread-safe; it is protected by wn.peersLock.
type prioTracker struct {
	// If a peer has a non-zero prioWeight, it will be present in
	// this map under its peerAddress.
	peerByAddress map[basics.Address]*wsPeer

	wn *WebsocketNetwork
}

func newPrioTracker(wn *WebsocketNetwork) *prioTracker {
	return &prioTracker{
		peerByAddress: make(map[basics.Address]*wsPeer),
		wn:            wn,
	}
}

func (pt *prioTracker) setPriority(peer *wsPeer, addr basics.Address, weight uint64) {
	wn := pt.wn

	// Make sure this peer is currently in the peers slice
	if peer.peerIndex >= len(wn.peers) || wn.peers[peer.peerIndex] != peer {
		// The peer might be in the process of being added to wn.peers;
		// in this case, wn.addPeer() will call setPriority again and
		// we will finish setup in that call.
		peer.prioAddress = addr
		peer.prioWeight = weight
		return
	}

	// Evict old peer from same address, if present
	old, present := pt.peerByAddress[addr]
	if present {
		if old == peer {
			// No eviction necessary if it was already this peer
			if peer.prioAddress == addr && peer.prioWeight == weight {
				// Same address and weight, nothing to update
				return
			}
		} else if old.prioAddress == addr {
			old.prioWeight = 0
			if old.peerIndex < len(wn.peers) && wn.peers[old.peerIndex] == old {
				heap.Fix(peersHeap{wn}, old.peerIndex)
			}
		}
	}

	// Check if this peer was in peerByAddress[] under its old address,
	// and delete that mapping if so.
	if addr != peer.prioAddress && peer == pt.peerByAddress[peer.prioAddress] {
		delete(pt.peerByAddress, peer.prioAddress)
	}

	pt.peerByAddress[addr] = peer
	peer.prioAddress = addr
	peer.prioWeight = weight
	heap.Fix(peersHeap{wn}, peer.peerIndex)
}

func (pt *prioTracker) removePeer(peer *wsPeer) {
	addr := peer.prioAddress
	old, present := pt.peerByAddress[addr]
	if present && old == peer {
		delete(pt.peerByAddress, addr)
	}
}
