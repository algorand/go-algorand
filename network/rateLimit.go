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

// ElasticRateLimiter holds and distributes capacity tokens.
// Capacity consumers are given an error if there is no capacity available for them,
// and a boolean indicating if the capacity they consumed was reserved
type ElasticRateLimiter struct {
	MaxCapacity            int
	CapacityPerReservation int
	sharedCapacity         chan capacity
	capacityByResource     map[interface{}]chan capacity
}

type capacity struct{}

func NewElasticRateLimiter(maxCapacity, reservedCapacity int) *ElasticRateLimiter {
	ret := ElasticRateLimiter{
		MaxCapacity:            maxCapacity,
		CapacityPerReservation: reservedCapacity,
		sharedCapacity:         make(chan capacity, maxCapacity),
		capacityByResource:     map[interface{}]chan capacity{},
	}
	// fill the sharedCapacity
	for i := 0; i < maxCapacity; i++ {
		ret.sharedCapacity <- capacity{}
	}
	return &ret
}

func (erl ElasticRateLimiter) ContainsReservationFor(resource interface{}) bool {
	for k := range erl.capacityByResource {
		if k == resource {
			return true
		}
	}
	return false
}

// ConsumeCapacity will dispense one capacity from either the resource's reservedCapacity,
// or the sharedCapacity. It will return a bool which will be True if the capacity it consumed was reserved
// or will return an error if the capacity could not be consumed from any channel
func (erl ElasticRateLimiter) ConsumeCapacity(resource interface{}) (bool, error) {
	// if the resource exists in the capacityByResource map, attempt to use its capacity
	if _, exists := erl.capacityByResource[resource]; exists {
		select {
		// if capacity can be pulled from the reservedCapacity, return true
		case <-erl.capacityByResource[resource]:
			return true, nil
		default:
		}
	}
	// attempt to pull from sharedCapacity
	select {
	case <-erl.sharedCapacity:
		return false, nil
	default:
	}
	return false, fmt.Errorf("unable to consume capacity from ElasticRateLimiter")
}

// ReturnCapacity will insert new capacity on the sharedCapacity or reservedCapacity of a resource.
// if the capacity could not be returned to any channel, an error is returned
func (erl ElasticRateLimiter) ReturnCapacity(resource interface{}, reserved bool) error {
	// return sharedCapacity to the sharedCapacity channel, ignoring failure
	if !reserved {
		select {
		case erl.sharedCapacity <- capacity{}:
			return nil
		default:
		}
	}
	// check if the resource has a reservedCapacity, and if it does, return capacity to it
	if _, exists := erl.capacityByResource[resource]; exists {
		select {
		case erl.capacityByResource[resource] <- capacity{}:
			return nil
		default:
		}
	} else {
		// an attempt to return reservedCapacity when the resource is unknown should reroute to returning to sharedCapacity
		// this is because the capacity could be returned to a resource who recently had its reservation removed.
		// be aware that this behavior may lead to inappropriate overprovisioning of sharedCapacity
		select {
		case erl.sharedCapacity <- capacity{}:
			return nil
		default:
		}
	}
	return fmt.Errorf("could not return capacity to any reservedCapacity or sharedCapacity")
}

// ReserveCapacity creates an entry in the ElasticRateLimiter's reservedCapacity map,
// and optimistically transfers capacity from the sharedCapacity to the reservedCapacity
func (erl ElasticRateLimiter) ReserveCapacity(resource interface{}) error {
	// guard against overprovisioning, if there is less than a reservedCapacity amount left
	remaining := erl.MaxCapacity - (erl.CapacityPerReservation * len(erl.capacityByResource))
	if erl.CapacityPerReservation > remaining {
		return fmt.Errorf("not enough capacity to reserve for resource: %d remaining, %d requested", remaining, erl.CapacityPerReservation)
	}
	// make capacity for the provided resource
	erl.capacityByResource[resource] = make(chan capacity, erl.CapacityPerReservation)

	// start asynchronously filling the capacity
	go func() {
		// by design, the ElasticRateLimiter will overprovision capacity for a newly connected host,
		// but will resolve the discrepancy ASAP by consuming capacity from the shared capacity which it will not return
		for i := 0; i < erl.CapacityPerReservation; i++ {
			select {
			case erl.capacityByResource[resource] <- capacity{}:
			default:
			}
		}
		// allow this thread to stubbornly wait and consume any available capacity,
		// since it needs to repay the capacity loaned to the resource
		for i := 0; i < erl.CapacityPerReservation; i++ {
			<-erl.sharedCapacity
		}
	}()
	return nil
}

func (erl ElasticRateLimiter) UnreserveCapacity(resource interface{}) error {
	resourceCh, exists := erl.capacityByResource[resource]
	// guard clauses, and preventing the ElasticRateLimiter from draining its own sharedCapacity
	if !exists ||
		resourceCh == nil ||
		resourceCh == erl.sharedCapacity {
		return fmt.Errorf("resource not registered for capacity")
	}
	delete(erl.capacityByResource, resource)
	for len(resourceCh) > 0 {
		<-resourceCh
		erl.ReturnCapacity(nil, false)
	}
	return nil
}
