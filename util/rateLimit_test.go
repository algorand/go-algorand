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
	"testing"
	"time"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
)

type mockClient string

type mockCongestionControl struct{}

func (cg mockCongestionControl) Start()                            {}
func (cg mockCongestionControl) Stop()                             {}
func (cg mockCongestionControl) Consumed(c ErlClient, t time.Time) {}
func (cg mockCongestionControl) Served(t time.Time)                {}
func (cg mockCongestionControl) ShouldDrop(c ErlClient) bool       { return true }

func (c mockClient) OnClose(func()) {
	return
}

func TestNewElasticRateLimiter(t *testing.T) {
	partitiontest.PartitionTest(t)
	erl := NewElasticRateLimiter(100, 10, time.Second, nil)

	assert.Equal(t, len(erl.sharedCapacity), 100)
	assert.Equal(t, len(erl.capacityByClient), 0)
}

func TestElasticRateLimiterCongestionControlled(t *testing.T) {
	partitiontest.PartitionTest(t)
	client := mockClient("client")
	erl := NewElasticRateLimiter(3, 2, time.Second, nil)
	// give the ERL a congestion controler with well defined behavior for testing
	erl.cm = mockCongestionControl{}

	_, _, err := erl.ConsumeCapacity(client)
	// because the ERL gives capacity to a reservation, and then asynchronously drains capacity from the share,
	// wait a moment before testing the size of the sharedCapacity
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, len(erl.capacityByClient[client]))
	assert.Equal(t, 1, len(erl.sharedCapacity))
	assert.NoError(t, err)

	erl.EnableCongestionControl()
	_, _, err = erl.ConsumeCapacity(client)
	assert.Equal(t, 0, len(erl.capacityByClient[client]))
	assert.Equal(t, 1, len(erl.sharedCapacity))
	assert.NoError(t, err)

	_, _, err = erl.ConsumeCapacity(client)
	assert.Equal(t, 0, len(erl.capacityByClient[client]))
	assert.Equal(t, 1, len(erl.sharedCapacity))
	assert.Error(t, err)

	erl.DisableCongestionControl()
	_, _, err = erl.ConsumeCapacity(client)
	assert.Equal(t, 0, len(erl.capacityByClient[client]))
	assert.Equal(t, 0, len(erl.sharedCapacity))
	assert.NoError(t, err)
}

func TestReservations(t *testing.T) {
	partitiontest.PartitionTest(t)
	client1 := mockClient("client1")
	client2 := mockClient("client2")
	erl := NewElasticRateLimiter(4, 1, time.Second, nil)

	_, _, err := erl.ConsumeCapacity(client1)
	// because the ERL gives capacity to a reservation, and then asynchronously drains capacity from the share,
	// wait a moment before testing the size of the sharedCapacity
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, len(erl.capacityByClient))
	assert.NoError(t, err)

	_, _, err = erl.ConsumeCapacity(client2)
	// because the ERL gives capacity to a reservation, and then asynchronously drains capacity from the share,
	// wait a moment before testing the size of the sharedCapacity
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 2, len(erl.capacityByClient))
	assert.NoError(t, err)

	erl.closeReservation(client1)
	assert.Equal(t, 1, len(erl.capacityByClient))
	erl.closeReservation(client2)
	assert.Equal(t, 0, len(erl.capacityByClient))
}

// When there is no reservation per client, the reservation map is not used
// This is so we never wait on a capacity queue which would not ever vend
func TestZeroSizeReservations(t *testing.T) {
	partitiontest.PartitionTest(t)
	client1 := mockClient("client1")
	client2 := mockClient("client2")
	erl := NewElasticRateLimiter(4, 0, time.Second, nil)

	_, _, err := erl.ConsumeCapacity(client1)
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, len(erl.capacityByClient))
	assert.NoError(t, err)

	_, _, err = erl.ConsumeCapacity(client2)
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, len(erl.capacityByClient))
	assert.NoError(t, err)

	erl.closeReservation(client1)
	assert.Equal(t, 0, len(erl.capacityByClient))
	erl.closeReservation(client2)
	assert.Equal(t, 0, len(erl.capacityByClient))
}

func TestConsumeReleaseCapacity(t *testing.T) {
	partitiontest.PartitionTest(t)
	client := mockClient("client")
	erl := NewElasticRateLimiter(4, 3, time.Second, nil)

	c1, _, err := erl.ConsumeCapacity(client)
	// because the ERL gives capacity to a reservation, and then asynchronously drains capacity from the share,
	// wait a moment before testing the size of the sharedCapacity
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 2, len(erl.capacityByClient[client]))
	assert.Equal(t, 1, len(erl.sharedCapacity))
	assert.NoError(t, err)

	_, _, err = erl.ConsumeCapacity(client)
	assert.Equal(t, 1, len(erl.capacityByClient[client]))
	assert.Equal(t, 1, len(erl.sharedCapacity))
	assert.NoError(t, err)

	_, _, err = erl.ConsumeCapacity(client)
	assert.Equal(t, 0, len(erl.capacityByClient[client]))
	assert.Equal(t, 1, len(erl.sharedCapacity))
	assert.NoError(t, err)

	// remember this capacity, as it is a shared capacity
	c4, _, err := erl.ConsumeCapacity(client)
	assert.Equal(t, 0, len(erl.capacityByClient[client]))
	assert.Equal(t, 0, len(erl.sharedCapacity))
	assert.NoError(t, err)

	_, _, err = erl.ConsumeCapacity(client)
	assert.Equal(t, 0, len(erl.capacityByClient[client]))
	assert.Equal(t, 0, len(erl.sharedCapacity))
	assert.Error(t, err)

	// now release the capacity and observe the items return to the correct places
	err = c1.Release()
	assert.Equal(t, 1, len(erl.capacityByClient[client]))
	assert.Equal(t, 0, len(erl.sharedCapacity))
	assert.NoError(t, err)

	// now release the capacity and observe the items return to the correct places
	err = c4.Release()
	assert.Equal(t, 1, len(erl.capacityByClient[client]))
	assert.Equal(t, 1, len(erl.sharedCapacity))
	assert.NoError(t, err)

}

func TestREDCongestionManagerShouldDrop(t *testing.T) {
	partitiontest.PartitionTest(t)
	client := mockClient("client")
	other := mockClient("other")
	red := NewREDCongestionManager(time.Second*10, 10000)
	// calculate the target rate every request for most accurate results
	red.targetRateRefreshTicks = 1
	red.Start()
	// indicate that the arrival rate is essentially 1/s
	for i := 0; i < 10; i++ {
		red.Consumed(client, time.Now())
	}
	// indicate that the service rate is essentially 0.9/s
	for i := 0; i < 9; i++ {
		red.Served(time.Now())
	}
	// allow the statistics to catch up before asserting
	time.Sleep(100 * time.Millisecond)
	// the service rate should be 0.9/s, and the arrival rate for this client should be 1/s
	// for this reason, it should always drop the message
	for i := 0; i < 100; i++ {
		assert.True(t, red.ShouldDrop(client))
	}
	// this caller hasn't consumed any capacity before, so it won't need to drop
	for i := 0; i < 10; i++ {
		assert.False(t, red.ShouldDrop(other))
	}
	// allow the congestion manager to consume and process the given messages
	time.Sleep(100 * time.Millisecond)
	red.Stop()
	assert.Equal(t, 10, len(*red.consumedByClient[client]))
	assert.Equal(t, float64(1), red.arrivalRateFor(red.consumedByClient[client]))
	assert.Equal(t, 0.0, red.arrivalRateFor(red.consumedByClient[other]))
	assert.Equal(t, 0.9, red.targetRate)
}

func TestREDCongestionManagerShouldntDrop(t *testing.T) {
	partitiontest.PartitionTest(t)
	client := mockClient("client")
	red := NewREDCongestionManager(time.Second*10, 10000)
	// calculate the target rate every request for most accurate results
	red.targetRateRefreshTicks = 1
	red.Start()

	// indicate that the arrival rate is essentially 0.1/s!
	red.Consumed(client, time.Now())

	// drive 10k messages, in batches of 500, with 100ms sleeps
	for i := 0; i < 20; i++ {
		for j := 0; j < 500; j++ {
			red.Served(time.Now())
		}
		time.Sleep(100 * time.Millisecond)
	}
	// the service rate should be 1000/s, and the arrival rate for this client should be 0.1/s
	// for this reason, shouldDrop should almost certainly return false (true only 1/100k times)
	for i := 0; i < 10; i++ {
		assert.False(t, red.ShouldDrop(client))
	}
	// allow the congestion manager to consume and process the given messages
	time.Sleep(1000 * time.Millisecond)
	red.Stop()
	assert.Equal(t, 1, len(*red.consumedByClient[client]))
	assert.Equal(t, 10000, len(red.serves))
	assert.Equal(t, 0.1, red.arrivalRateFor(red.consumedByClient[client]))
	assert.Equal(t, float64(1000), red.targetRate)
}

func TestREDCongestionManagerTargetRate(t *testing.T) {
	partitiontest.PartitionTest(t)
	client := mockClient("client")
	red := NewREDCongestionManager(time.Second*10, 10000)
	red.Start()
	red.Consumed(client, time.Now())
	red.Consumed(client, time.Now())
	red.Consumed(client, time.Now())
	red.Served(time.Now())
	red.Served(time.Now())
	red.Served(time.Now())
	// allow the congestion manager to consume and process the given messages
	time.Sleep(100 * time.Millisecond)
	red.Stop()
	assert.Equal(t, 0.3, red.arrivalRateFor(red.consumedByClient[client]))
	assert.Equal(t, 0.3, red.targetRate)
}

func TestREDCongestionManagerPrune(t *testing.T) {
	partitiontest.PartitionTest(t)
	client := mockClient("client")
	red := NewREDCongestionManager(time.Second*10, 10000)
	red.Start()
	red.Consumed(client, time.Now().Add(-11*time.Second))
	red.Consumed(client, time.Now().Add(-11*time.Second))
	red.Consumed(client, time.Now().Add(-11*time.Second))
	red.Consumed(client, time.Now())
	red.Served(time.Now().Add(-11 * time.Second))
	red.Served(time.Now().Add(-11 * time.Second))
	red.Served(time.Now().Add(-11 * time.Second))
	red.Served(time.Now())
	// allow the congestion manager to consume and process the given messages
	time.Sleep(100 * time.Millisecond)
	red.Stop()
	assert.Equal(t, 0.1, red.arrivalRateFor(red.consumedByClient[client]))
	assert.Equal(t, 0.1, red.targetRate)
}

func TestREDCongestionManagerStopStart(t *testing.T) {
	partitiontest.PartitionTest(t)
	client := mockClient("client")
	red := NewREDCongestionManager(time.Second*10, 10000)
	red.Start()
	red.Consumed(client, time.Now())
	red.Consumed(client, time.Now())
	red.Consumed(client, time.Now())
	red.Served(time.Now())
	red.Served(time.Now())
	red.Served(time.Now())
	// allow the congestion manager to consume and process the given messages
	time.Sleep(100 * time.Millisecond)
	red.Stop()
	assert.Equal(t, 0.3, red.arrivalRateFor(red.consumedByClient[client]))
	assert.Equal(t, 0.3, red.targetRate)
	// Do it all again, but with 2 calls instead of 3 and 4 serves instead of 3
	red.Start()
	red.Consumed(client, time.Now())
	red.Consumed(client, time.Now())
	red.Served(time.Now())
	red.Served(time.Now())
	red.Served(time.Now())
	red.Served(time.Now())
	// allow the congestion manager to consume and process the given messages
	time.Sleep(100 * time.Millisecond)
	red.Stop()
	assert.Equal(t, 0.2, red.arrivalRateFor(red.consumedByClient[client]))
	assert.Equal(t, 0.4, red.targetRate)
}
