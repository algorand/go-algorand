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

package util

import (
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// ElasticRateLimiter holds and distributes capacity tokens.
// Capacity consumers are given an error if there is no capacity available for them,
// and a boolean indicating if the capacity they consumed was reserved
type ElasticRateLimiter struct {
	MaxCapacity            int
	CapacityPerReservation int
	sharedCapacity         chan capacity
	capacityByClient       map[interface{}]chan capacity
	// CongestionManager and enable flag
	cm       CongestionManager
	enableCM bool
}

type client interface{}
type capacity struct{}

func NewElasticRateLimiter(maxCapacity, reservedCapacity int, cm CongestionManager) *ElasticRateLimiter {
	ret := ElasticRateLimiter{
		MaxCapacity:            maxCapacity,
		CapacityPerReservation: reservedCapacity,
		sharedCapacity:         make(chan capacity, maxCapacity),
		capacityByClient:       map[interface{}]chan capacity{},
		cm:                     cm,
	}
	// fill the sharedCapacity
	for i := 0; i < maxCapacity; i++ {
		ret.sharedCapacity <- capacity{}
	}
	return &ret
}

func (erl ElasticRateLimiter) EnableCongestionControl() {
	erl.enableCM = true
}

func (erl ElasticRateLimiter) DisableCongestionControl() {
	erl.enableCM = false
}

func (erl ElasticRateLimiter) ContainsReservationFor(c client) bool {
	for k := range erl.capacityByClient {
		if k == c {
			return true
		}
	}
	return false
}

// ConsumeCapacity will dispense one capacity from either the resource's reservedCapacity,
// or the sharedCapacity. It will return a bool which will be True if the capacity it consumed was reserved
// or will return an error if the capacity could not be consumed from any channel
func (erl ElasticRateLimiter) ConsumeCapacity(c client) (bool, error) {
	// if the client exists in the reservation map, attempt to use its capacity
	if _, exists := erl.capacityByClient[c]; exists {
		select {
		// if capacity can be pulled from the reservedCapacity, return true
		case <-erl.capacityByClient[c]:
			erl.cm.TrackActivity(c, true, time.Now())
			return true, nil
		default:
		}
	}
	// before comitting to using sharedCapacity, check with the congestionManager
	if erl.cm != nil &&
		erl.enableCM &&
		erl.cm.ShouldDrop(c) {
		return false, fmt.Errorf("congestionManager prevented client from consuming capacity")
	}
	// attempt to pull from sharedCapacity
	select {
	case <-erl.sharedCapacity:
		erl.cm.TrackActivity(c, false, time.Now())
		return false, nil
	default:
	}
	return false, fmt.Errorf("unable to consume capacity from ElasticRateLimiter")
}

// ReturnCapacity will insert new capacity on the sharedCapacity or reservedCapacity of a client.
// if the capacity could not be returned to any channel, an error is returned
func (erl ElasticRateLimiter) ReturnCapacity(c client, reserved bool) error {
	// return sharedCapacity to the sharedCapacity channel, ignoring failure
	if !reserved {
		select {
		case erl.sharedCapacity <- capacity{}:
			return nil
		default:
		}
	}
	// check if the client has a reservation, and if it does, return capacity to it
	if _, exists := erl.capacityByClient[c]; exists {
		select {
		case erl.capacityByClient[c] <- capacity{}:
			return nil
		default:
		}
	} else {
		// an attempt to return reservedCapacity when the cient is unknown should reroute to returning to sharedCapacity
		// this is because the return could be coming from a client who no longer has a reservation
		// NOTE: this behavior may lead to inappropriate overprovisioning of sharedCapacity
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
func (erl ElasticRateLimiter) ReserveCapacity(c client) error {
	if _, exists := erl.capacityByClient[c]; exists {
		// don't touch any client with an existing reservation
		return nil
	}
	// guard against overprovisioning, if there is less than a reservedCapacity amount left
	remaining := erl.MaxCapacity - (erl.CapacityPerReservation * len(erl.capacityByClient))
	if erl.CapacityPerReservation > remaining {
		return fmt.Errorf("not enough capacity to reserve for client: %d remaining, %d requested", remaining, erl.CapacityPerReservation)
	}
	// make capacity for the provided client
	erl.capacityByClient[c] = make(chan capacity, erl.CapacityPerReservation)

	// start asynchronously filling the capacity
	// by design, the ElasticRateLimiter will overprovision capacity for a newly connected host,
	// but will resolve the discrepancy ASAP by consuming capacity from the shared capacity which it will not return
	for i := 0; i < erl.CapacityPerReservation; i++ {
		select {
		case erl.capacityByClient[c] <- capacity{}:
		default:
		}
	}
	go func() {
		// allow this thread to stubbornly wait and consume any available capacity,
		// since it needs to repay the capacity loaned to the client
		for i := 0; i < erl.CapacityPerReservation; i++ {
			<-erl.sharedCapacity
		}
	}()
	return nil
}

func (erl ElasticRateLimiter) UnreserveCapacity(c client) error {
	clientCh, exists := erl.capacityByClient[c]
	// guard clauses, and preventing the ElasticRateLimiter from draining its own sharedCapacity
	if !exists ||
		clientCh == nil ||
		clientCh == erl.sharedCapacity {
		return fmt.Errorf("client not registered for capacity")
	}
	delete(erl.capacityByClient, c)
	for len(clientCh) > 0 {
		<-clientCh
		erl.ReturnCapacity(nil, false)
	}
	return nil
}

// CongestionManagers can be told of client activity
// with the intention of being able to decide if a client is unfairly claiming capacity
type CongestionManager interface {
	TrackActivity(c client, reserved bool, t time.Time)
	ShouldDrop(c client) bool
}

type activity struct {
	t        time.Time
	reserved bool
}
type ProportionalOddsCongestionManager struct {
	window              time.Duration
	activitiesByClient  map[interface{}][]activity
	targetRate          float64
	trMaintainerRunning bool
	trMaintainerMu      sync.Mutex
}

// MaintainTargetServiceRate will, every 10 seconds, prune every known client with tracked activity,
// and will adjust the targetRate to be the total amount of activity per client per second
func (cm ProportionalOddsCongestionManager) MaintainTargetServiceRate() {
	// check if the maintainer is already running to ensure there is only one routine
	cm.trMaintainerMu.Lock()
	defer cm.trMaintainerMu.Unlock()
	if cm.trMaintainerRunning {
		return
	}
	go func() {
		for {
			cutoff := time.Now().Add((-1 * cm.window))
			n := 0
			i := 0
			for k := range cm.activitiesByClient {
				j := cm.prune(k, cutoff)
				if j > 0 {
					i += j
					n++
				}
			}
			if n > 0 {
				cm.targetRate = (float64(i) / float64(n)) / float64(cm.window/time.Second)
			}
			time.Sleep(10 * time.Second)
		}
	}()
}

func (cm ProportionalOddsCongestionManager) TrackActivity(c client, reserved bool, t time.Time) {
	cm.activitiesByClient[c] = append(cm.activitiesByClient[c], activity{t, reserved})
	cm.prune(c, time.Now().Add(-1*cm.window))
}

// prune eliminates activity entries prior to the cutoff time, and will return
// the length of the list post-prune
func (cm ProportionalOddsCongestionManager) prune(c client, cutoff time.Time) int {
	if _, exists := cm.activitiesByClient[c]; !exists {
		return 0
	}
	// prune the list of old entries, using an in-place slice filter
	i := 0
	for _, activity := range cm.activitiesByClient[c] {
		if activity.t.Before(cutoff) {
			cm.activitiesByClient[c][i] = activity
			i++
		}
	}
	// if after purning, there is no activity for the client, delete the entry
	// otherwise, just cut down the slice since it's been reorganized
	if i == 0 {
		delete(cm.activitiesByClient, c)
	} else {
		cm.activitiesByClient[c] = cm.activitiesByClient[c][:i]
		cm.serviceTally -= i
	}
	return i
}

func (cm ProportionalOddsCongestionManager) ShouldDrop(c client) bool {
	clientServiceRate := cm.prune(c, time.Now().Add(-1*cm.window))
	// A random float is selected, and the Actions per Second of the given client is
	// turned to a ratio against targetRate. the congestion manager recommends to drop activity
	// proportional to its overuse above the targetRate
	r := rand.Float64()
	aps := float64(clientServiceRate) / float64(cm.window/time.Second)
	return (aps / cm.targetRate) > r
}
