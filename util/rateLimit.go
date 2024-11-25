// Copyright (C) 2019-2024 Algorand, Inc.
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
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/algorand/go-algorand/util/metrics"
	"github.com/algorand/go-deadlock"
)

var errConManDropped = errors.New("congestionManager prevented client from consuming capacity")
var errFailedConsume = errors.New("could not consume capacity from capacityQueue")
var errERLReservationExists = errors.New("client already has a reservation")
var errCapacityReturn = errors.New("could not replace capacity to channel")

// ElasticRateLimiter holds and distributes capacity through capacityQueues
// Capacity consumers are given an error if there is no capacity available for them,
// and a "capacityGuard" structure they can use to return the capacity when finished
type ElasticRateLimiter struct {
	MaxCapacity            int
	CapacityPerReservation int
	sharedCapacity         capacityQueue
	capacityByClient       map[ErlClient]capacityQueue
	clientLock             deadlock.RWMutex
	// CongestionManager and enable flag
	cm                       CongestionManager
	enableCM                 bool
	congestionControlCounter *metrics.Counter
}

// ErlClient clients must support OnClose for reservation closing
type ErlClient interface {
	OnClose(func())
}

// capacity is an empty structure used for loading and draining queues
type capacity struct {
}

// Capacity Queue wraps and maintains a channel of opaque capacity structs
type capacityQueue chan capacity

// ErlCapacityGuard is the structure returned to clients so they can release the capacity when needed
// they also inform the congestion manager of events
type ErlCapacityGuard struct {
	cq capacityQueue
	cm CongestionManager
}

// Release will put capacity back into the queue attached to this capacity guard
func (cg *ErlCapacityGuard) Release() error {
	if cg.cq == nil {
		return nil
	}
	select {
	case cg.cq <- capacity{}:
		return nil
	default:
		return errCapacityReturn
	}
}

// Served will notify the CongestionManager that this resource has been served, informing the Service Rate
func (cg *ErlCapacityGuard) Served() {
	if cg.cm != nil {
		cg.cm.Served(time.Now())
	}
}

func (q capacityQueue) blockingRelease() {
	q <- capacity{}
}

func (q capacityQueue) blockingConsume() {
	<-q
}

func (q capacityQueue) consume(cm CongestionManager) (ErlCapacityGuard, error) {
	select {
	case <-q:
		return ErlCapacityGuard{
			cq: q,
			cm: cm,
		}, nil
	default:
		return ErlCapacityGuard{}, errFailedConsume
	}
}

// NewElasticRateLimiter creates an ElasticRateLimiter and initializes maps
// maxCapacity: the total (absolute maximum) number of capacity units vended by this ERL at a given time
// reservedCapacity: the number of capacity units to be reserved per client
// cmWindow:  the window duration of data collection for congestion management, passed to the congestion manager
// conmanCount: the metric to increment when the congestion manager proposes dropping a request
func NewElasticRateLimiter(
	maxCapacity int,
	reservedCapacity int,
	cmWindow time.Duration,
	conmanCount *metrics.Counter) *ElasticRateLimiter {
	ret := ElasticRateLimiter{
		MaxCapacity:              maxCapacity,
		CapacityPerReservation:   reservedCapacity,
		capacityByClient:         map[ErlClient]capacityQueue{},
		sharedCapacity:           capacityQueue(make(chan capacity, maxCapacity)),
		congestionControlCounter: conmanCount,
	}
	congestionManager := NewREDCongestionManager(
		cmWindow,
		maxCapacity)
	ret.cm = congestionManager
	// fill the sharedCapacity
	for i := 0; i < maxCapacity; i++ {
		ret.sharedCapacity.blockingRelease()
	}
	return &ret
}

// Start will start any underlying component of the ElasticRateLimiter
func (erl *ElasticRateLimiter) Start() {
	if erl.cm != nil {
		erl.cm.Start()
	}
}

// Stop will stop any underlying component of the ElasticRateLimiter
func (erl *ElasticRateLimiter) Stop() {
	if erl.cm != nil {
		erl.cm.Stop()
	}
}

// EnableCongestionControl turns on the flag that the ERL uses to check with its CongestionManager
func (erl *ElasticRateLimiter) EnableCongestionControl() {
	erl.clientLock.Lock()
	defer erl.clientLock.Unlock()
	erl.enableCM = true
}

// DisableCongestionControl turns off the flag that the ERL uses to check with its CongestionManager
func (erl *ElasticRateLimiter) DisableCongestionControl() {
	erl.clientLock.Lock()
	defer erl.clientLock.Unlock()
	erl.enableCM = false
}

// ConsumeCapacity will dispense one capacity from either the resource's reservedCapacity,
// and will return a guard who can return capacity when the client is ready
// Returns an error if the capacity could not be vended, which could be:
// - there is not sufficient free capacity to assign a reserved capacity block
// - there is no reserved or shared capacity available for the client
func (erl *ElasticRateLimiter) ConsumeCapacity(c ErlClient) (*ErlCapacityGuard, bool, error) {
	var cg ErlCapacityGuard
	var q capacityQueue
	var err error
	var exists bool
	var isCMEnabled bool
	// get the client's queue
	erl.clientLock.RLock()
	q, exists = erl.capacityByClient[c]
	isCMEnabled = erl.enableCM
	erl.clientLock.RUnlock()

	// Step 0: Check for, and create a capacity reservation if needed
	// Don't interact with reservations if the capacity-per-reservation is zero
	if !exists && erl.CapacityPerReservation > 0 {
		q, err = erl.openReservation(c)
		if err != nil {
			return nil, isCMEnabled, err
		}
		// if the client has been given a new reservation, make sure it cleans up OnClose
		c.OnClose(func() { erl.closeReservation(c) })

		// if this reservation is newly created, directly (blocking) take a capacity
		q.blockingConsume()
		return &ErlCapacityGuard{cq: q, cm: erl.cm}, isCMEnabled, nil
	}

	// Step 1: Attempt consumption from the reserved queue if one exists
	if q != nil {
		cg, err = q.consume(erl.cm)
		if err == nil {
			if erl.cm != nil {
				erl.cm.Consumed(c, time.Now()) // notify the congestion manager that this client consumed from this queue
			}
			return &cg, isCMEnabled, nil
		}
	}

	// Step 2: Potentially gate shared queue access if the congestion manager disallows it
	if erl.cm != nil &&
		isCMEnabled &&
		erl.cm.ShouldDrop(c) {
		if erl.congestionControlCounter != nil {
			erl.congestionControlCounter.Inc(nil)
		}
		return nil, isCMEnabled, errConManDropped
	}

	// Step 3: Attempt consumption from the shared queue
	cg, err = erl.sharedCapacity.consume(erl.cm)
	if err != nil {
		return nil, isCMEnabled, err
	}
	if erl.cm != nil {
		erl.cm.Consumed(c, time.Now()) // notify the congestion manager that this client consumed from this queue
	}
	return &cg, isCMEnabled, nil
}

// openReservation creates an entry in the ElasticRateLimiter's reservedCapacity map,
// and optimistically transfers capacity from the sharedCapacity to the reservedCapacity
func (erl *ElasticRateLimiter) openReservation(c ErlClient) (capacityQueue, error) {
	erl.clientLock.Lock()
	defer erl.clientLock.Unlock()
	if _, exists := erl.capacityByClient[c]; exists {
		return capacityQueue(nil), errERLReservationExists
	}
	// guard against overprovisioning, if there is less than a reservedCapacity amount left
	remaining := erl.MaxCapacity - (erl.CapacityPerReservation * len(erl.capacityByClient))
	if erl.CapacityPerReservation > remaining {
		return capacityQueue(nil), fmt.Errorf("not enough capacity to reserve for client: %d remaining, %d requested", remaining, erl.CapacityPerReservation)
	}
	// make capacity for the provided client
	q := capacityQueue(make(chan capacity, erl.CapacityPerReservation))
	erl.capacityByClient[c] = q
	// create a thread to drain the capacity from sharedCapacity in a blocking way
	// and move it to the reservation, also in a blocking way
	go func() {
		for i := 0; i < erl.CapacityPerReservation; i++ {
			erl.sharedCapacity.blockingConsume()
			q.blockingRelease()
		}
	}()
	return q, nil
}

// closeReservation will remove the client mapping to capacity channel,
// and will kick off a routine to drain the capacity and replace it to the shared capacity
func (erl *ElasticRateLimiter) closeReservation(c ErlClient) {
	erl.clientLock.Lock()
	defer erl.clientLock.Unlock()
	q, exists := erl.capacityByClient[c]
	// guard clauses, and preventing the ElasticRateLimiter from draining its own sharedCapacity
	if !exists || q == erl.sharedCapacity {
		return
	}
	delete(erl.capacityByClient, c)
	// start a routine to consume capacity from the closed reservation, and return it to the sharedCapacity
	go func() {
		for i := 0; i < erl.CapacityPerReservation; i++ {
			q.blockingConsume()
			erl.sharedCapacity.blockingRelease()
		}
	}()
}

// CongestionManager is an interface for tracking events which happen to capacityQueues
type CongestionManager interface {
	Start()
	Stop()
	Consumed(c ErlClient, t time.Time)
	Served(t time.Time)
	ShouldDrop(c ErlClient) bool
}

type event struct {
	c ErlClient
	t time.Time
}

type shouldDropQuery struct {
	c   ErlClient
	ret chan bool
}

// "Random Early Detection" congestion manager,
// will propose to drop messages proportional to the caller's request rate vs Average Service Rate
type redCongestionManager struct {
	runLock                *deadlock.Mutex
	running                bool
	window                 time.Duration
	consumed               chan event
	served                 chan event
	shouldDropQueries      chan shouldDropQuery
	targetRate             float64
	targetRateRefreshTicks int
	// exp is applied as an exponential factor in shouldDrop. 1 would be linearly proportional, higher values punish noisy neighbors more
	exp float64
	// consumed is the only value tracked by-queue. The others are calculated in-total
	// TODO: If we desire later, we can add mappings onto release/done for more insight
	consumedByClient map[ErlClient]*[]time.Time
	serves           []time.Time
	// synchronization for unit tests
	ctx       context.Context
	ctxCancel context.CancelFunc
	wg        sync.WaitGroup
}

// NewREDCongestionManager creates a Congestion Manager which will watches capacityGuard activity,
// and regularly calculates a Target Service Rate, and can give "Should Drop" suggestions
func NewREDCongestionManager(d time.Duration, bsize int) *redCongestionManager {
	ret := redCongestionManager{
		runLock:                &deadlock.Mutex{},
		window:                 d,
		consumed:               make(chan event, bsize),
		served:                 make(chan event, bsize),
		shouldDropQueries:      make(chan shouldDropQuery, bsize),
		targetRateRefreshTicks: bsize / 10, // have the Congestion Manager refresh its target rates every 10% through the queue
		consumedByClient:       map[ErlClient]*[]time.Time{},
		exp:                    4,
		wg:                     sync.WaitGroup{},
	}
	return &ret
}

// Consumed implements CongestionManager by putting an event on the consumed channel,
// to be processed by the Start() loop
func (cm *redCongestionManager) Consumed(c ErlClient, t time.Time) {
	select {
	case cm.consumed <- event{
		c: c,
		t: t,
	}:
	default:
	}
}

// Served implements CongestionManager by putting an event on the done channel,
// to be processed by the Start() loop
func (cm *redCongestionManager) Served(t time.Time) {
	select {
	case cm.served <- event{
		t: t,
	}:
	default:
	}
}

// ShouldDrop implements CongestionManager by putting a query shouldDropQueries channel,
// and blocks on the response to return synchronously to the caller
// if an error should prevent the query from running, the result is defaulted to false
func (cm *redCongestionManager) ShouldDrop(c ErlClient) bool {
	ret := make(chan bool)
	select {
	case cm.shouldDropQueries <- shouldDropQuery{
		c:   c,
		ret: ret,
	}:
		return <-ret
	default:
		return false
	}
}

// Start will kick off a goroutine to consume activity from the different activity channels,
// as well as service queries about if a given capacityQueue should drop
func (cm *redCongestionManager) Start() {
	// check if the maintainer is already running to ensure there is only one routine
	cm.runLock.Lock()
	defer cm.runLock.Unlock()
	if cm.running {
		return
	}
	cm.ctx, cm.ctxCancel = context.WithCancel(context.Background())
	cm.running = true
	cm.wg.Add(1)
	go cm.run()
}

func (cm *redCongestionManager) run() {
	tick := 0
	targetRate := float64(0)
	consumedByClient := map[ErlClient]*[]time.Time{}
	serves := []time.Time{}
	lastServiceRateUpdate := time.Now()
	exit := false
	for {
		select {
		// prioritize shouldDropQueries
		case query := <-cm.shouldDropQueries:
			cutoff := time.Now().Add(-1 * cm.window)
			prune(consumedByClient[query.c], cutoff)
			query.ret <- cm.shouldDrop(targetRate, query.c, consumedByClient[query.c])
		default:
			select {
			// "should drop" queries
			case query := <-cm.shouldDropQueries:
				cutoff := time.Now().Add(-1 * cm.window)
				prune(consumedByClient[query.c], cutoff)
				query.ret <- cm.shouldDrop(targetRate, query.c, consumedByClient[query.c])
			// consumed events -- a client has consumed capacity from a queue
			case e := <-cm.consumed:
				if consumedByClient[e.c] == nil {
					ts := []time.Time{}
					consumedByClient[e.c] = &ts
				}
				*(consumedByClient[e.c]) = append(*(consumedByClient[e.c]), e.t)
			// served events -- the capacity has been totally served
			case e := <-cm.served:
				serves = append(serves, e.t)
			// check for context Done, and flag the thread for shutdown
			case <-cm.ctx.Done():
				exit = true
			}

		}
		// recalculate the service rate every N ticks, or every 100ms
		// also calculate if the routine is going to exit
		tick = (tick + 1) % cm.targetRateRefreshTicks
		if tick == 0 || time.Now().After(lastServiceRateUpdate.Add(100*time.Millisecond)) || exit {
			lastServiceRateUpdate = time.Now()
			cutoff := time.Now().Add(-1 * cm.window)
			prune(&serves, cutoff)
			for c := range consumedByClient {
				if prune(consumedByClient[c], cutoff) == 0 {
					delete(consumedByClient, c)
				}
			}
			targetRate = 0
			// targetRate is the average service rate per client per second
			if len(consumedByClient) > 0 {
				serviceRate := float64(len(serves)) / float64(cm.window/time.Second)
				targetRate = serviceRate / float64(len(consumedByClient))
			}
		}
		if exit {
			cm.setTargetRate(targetRate)
			cm.setConsumedByClient(consumedByClient)
			cm.setServes(serves)
			cm.runLock.Lock()
			defer cm.runLock.Unlock()
			cm.running = false
			cm.wg.Done()
			return
		}
	}
}

func (cm *redCongestionManager) Stop() {
	cm.ctxCancel()
	cm.wg.Wait()
}

func (cm *redCongestionManager) setTargetRate(tr float64) {
	cm.targetRate = tr
}

func (cm *redCongestionManager) setConsumedByClient(cbc map[ErlClient]*[]time.Time) {
	cm.consumedByClient = cbc
}

func (cm *redCongestionManager) setServes(ts []time.Time) {
	cm.serves = ts
}

func (cm *redCongestionManager) arrivalRateFor(arrivals *[]time.Time) float64 {
	clientArrivalRate := float64(0)
	if arrivals != nil {
		clientArrivalRate = float64(len(*arrivals)) / float64(cm.window/time.Second)
	}
	return clientArrivalRate
}

// shouldDrop ultimately makes the recommendation to drop a given request through some fairness probability.
// Comparing this behavior with the behavior of a basic Random Early Detection system:
// A standard RED model will drop any message with chance proportional to its queue's fullness. The more full, the more random dropping is applied to all clients.
// In this RED model, there is an application of fairness, in which the chance a client's request is dropped is proportional to their individual arrival rate, vs a per-client service rate.
// A behavior example is as follows:
// client1 makes 100 requests over a given sliding window (10s for this example)
// client2 makes 200 requests over the window
// all 300 requests were served over the window
//
// This means:
//   - client1's arrival rate is 100/10 = 10/s
//   - client2's arrival rate is 200/10 = 20/s
//   - the service rate is 300/10 = 30/s
//   - the *target rate* is the service rate per client: 30/2 = 15/s
//
// When a shouldDrop request is made:
//   - client1 shouldDrop: 10 / 15 > random float ?
//   - client2 shouldDrop: 20 / 15 > random float ?
//   - Additionally, the arrival and service rates are raised to an exponential power, to increase contrast.
//
// client2 will be throttled because it is making requests in excess of its target rate.
// client1 will be throttled proportional to its usage of the service rate.
// over time, client2 will fall in line with the appropriate service rate, while other clients will be able to use the newly freed capacity
// The net effect is that clients who are disproportionately noisy are dropped more often,
// while quieter ones are are dropped less often.
// The reason this works is that the serviceRate represents the ability for the given resource to be serviced (ie, the rate at which work is dequeued).
// When congestion management is required, the service should attempt a fair distribution of servicing to all clients.
// clients who are making requests in excess of our known ability to fairly service requests should be reduced.
func (cm *redCongestionManager) shouldDrop(targetRate float64, c ErlClient, arrivals *[]time.Time) bool {
	// clients who have "never" been seen do not get dropped
	clientArrivalRate := cm.arrivalRateFor(arrivals)
	if clientArrivalRate == 0 {
		return false
	}
	// if targetRate is 0, it means we haven't had any activity to calculate (or there is not enough data)
	// it should not drop in this case
	if targetRate == 0 {
		return false
	}
	// A random float is selected, and the arrival rate of the given client is
	// turned to a ratio against targetRate. the congestion manager recommends to drop activity
	// proportional to its overuse above the targetRate
	r := rand.Float64()
	return (math.Pow(clientArrivalRate, cm.exp) / math.Pow(targetRate, cm.exp)) > r
}

func prune(ts *[]time.Time, cutoff time.Time) int {
	// guard against nil lists
	if ts == nil {
		return 0
	}
	// guard against empty lists
	if len(*ts) == 0 {
		return 0
	}
	// optimization: if the last element falls before the cutoff, prune the whole list without iteration
	if (*ts)[len(*ts)-1].Before(cutoff) {
		*ts = (*ts)[:0]
		return 0
	}
	// optimization: if the list is longer than 50 elements, use a binary search to find the cutoff line
	if len(*ts) > 50 {
		i := sort.Search(len(*ts), func(i int) bool { return (*ts)[i].After(cutoff) })
		*ts = (*ts)[i:]
		return len(*ts)
	}
	// find the first inserted timestamp *after* the cutoff, and cut everything behind it off
	for i, t := range *ts {
		if t.After(cutoff) {
			*ts = (*ts)[i:]
			return len(*ts)
		}
	}
	// if no values are after the cutoff, clear the array and give back a 0
	*ts = (*ts)[:0]
	return 0
}
