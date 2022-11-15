// Copyright (C) 2019-2022 Algorand, Inc.
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

import "fmt"

// ElasticRateLimiter holds and distributes shared and reserved TPS capacity
// ReservedPerPeer is the number of capacity in each Peer's reserved channel
// Max Capacity is the total of all Reserved and Shared capacity
type ElasticRateLimiter struct {
	MaxCapacity        int
	ReservedPerPeer    int
	ActiveReservations int
	sharedCapacity     chan Capacity
	capacityByPeer     map[*wsPeer]chan Capacity
}

type Capacity struct{}

func NewElasticRateLimiter(maxCapacity, reservedCapacity int) ElasticRateLimiter {
	ret := ElasticRateLimiter{
		MaxCapacity:     maxCapacity,
		ReservedPerPeer: reservedCapacity,
		sharedCapacity:  make(chan Capacity, maxCapacity),
		capacityByPeer:  map[*wsPeer]chan Capacity{},
	}
	// fill the sharedCapacity
	for i := 0; i < maxCapacity; i++ {
		ret.sharedCapacity <- Capacity{}
	}
	return ret
}

// ConsumeCapacity will pop one unit of Capacity from the peer's capacity channel if available,
// and will fall back to popping from the shared Capacity. If neither are available, an error is returned.
func (erl ElasticRateLimiter) ConsumeCapacity(peer *wsPeer) (chan Capacity, error) {
	// Lazy initialize, assume a "guest" peer would consume from sharedCapacity
	if _, exists := erl.capacityByPeer[peer]; !exists {
		erl.capacityByPeer[peer] = erl.sharedCapacity
		return nil, fmt.Errorf("peer not registered for capacity")
	}
	select {
	case <-erl.capacityByPeer[peer]:
		return erl.capacityByPeer[peer], nil
	default:
	}
	select {
	case <-erl.sharedCapacity:
		return erl.sharedCapacity, nil
	default:
	}

	return nil, fmt.Errorf("unable to consume capacity from ElasticRateLimiter")
}

// ReturnCapacity will attempt to put Capacity back to the peer's assigned channel
// but will quietly drop the Capacity if it is full
// NOTE: the peer's capacity channel may be the sharedCapacity channel if the peer's reservation no longer exists
// TODO (?) if helpful, return an error instead of being silent
func (erl ElasticRateLimiter) ReturnCapacity(peer *wsPeer) {
	select {
	case erl.capacityByPeer[peer] <- Capacity{}:
	default:
	}
}

// ReserveCapacity creates an entry in the ElasticRateLimiter's reservedCapacity map,
// and optimistically transfers capacity from the sharedCapacity to the reservedCapacity
func (erl ElasticRateLimiter) ReserveCapacity(peer *wsPeer) error {
	// guard against overprovisioning, if there is less than a reservedCapacity amount left
	remaining := erl.MaxCapacity - (erl.ReservedPerPeer * erl.ActiveReservations)
	if erl.ReservedPerPeer > remaining {
		return fmt.Errorf("not enough capacity to reserve for peer: %d remaining, %d requested", remaining, erl.ReservedPerPeer)
	}
	// make capacity for the provided peer
	erl.capacityByPeer[peer] = make(chan Capacity, erl.ReservedPerPeer)
	erl.ActiveReservations = erl.ActiveReservations + 1

	// start asynchronously filling the capacity
	go func() {
		// by design, the ElasticRateLimiter will overprovision capacity for a newly connected host,
		// but will resolve the discrepancy ASAP by consuming capacity from the shared capacity which it will not return
		for i := 0; i < erl.ReservedPerPeer; i++ {
			select {
			case erl.capacityByPeer[peer] <- Capacity{}:
				continue
			default:
			}
		}
		// allow this thread to stubbornly wait and consume any available capacity,
		// since it needs to repay the capacity loaned to the peer
		for i := 0; i < erl.ReservedPerPeer; i++ {
			<-erl.sharedCapacity
		}
	}()
	return nil
}

// UnreserveCapacity will reroute future Capacity Returns to go to the sharedCapacity,
// and will drain any remaining Capacity from the reservedCapacity to the sharedCapacity
func (erl ElasticRateLimiter) UnreserveCapacity(peer *wsPeer) error {
	peerCh, exists := erl.capacityByPeer[peer]
	if !exists ||
		peerCh == nil ||
		peerCh == erl.sharedCapacity {
		return fmt.Errorf("peer not registered for capacity")
	}
	// reassign the peer's channel to use the sharedCapacity, so any returned Capacity is correctly routed
	erl.capacityByPeer[peer] = erl.sharedCapacity
	erl.ActiveReservations = erl.ActiveReservations - 1
	for {
		select {
		// drain the capacity
		case <-peerCh:
			erl.sharedCapacity <- Capacity{}
		}
	}
}
