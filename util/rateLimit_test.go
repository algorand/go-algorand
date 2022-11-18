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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewElasticRateLimiter(t *testing.T) {
	erl := NewElasticRateLimiter(100, 10, nil)

	assert.Equal(t, len(erl.sharedCapacity), 100)
	assert.Equal(t, len(erl.capacityByClient), 0)
}

func TestOpenCloseReservation(t *testing.T) {
	client := "client"
	erl := NewElasticRateLimiter(100, 10, nil)
	erl.OpenReservation(client)
	assert.Equal(t, 1, len(erl.capacityByClient))
	assert.Equal(t, 10, len(erl.capacityByClient[client]))
	// because the ERL gives capacity to a reservation, and then asynchronously drains capacity from the share,
	// wait a moment before testing the size of the sharedCapacity
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 90, len(erl.sharedCapacity))

	erl.CloseReservation(client)
	assert.Equal(t, 100, len(erl.sharedCapacity))
	assert.Equal(t, 0, len(erl.capacityByClient))
}

func TestConsumeReturnCapacity(t *testing.T) {
	client := "client"
	erl := NewElasticRateLimiter(2, 1, nil)
	erl.OpenReservation(client)
	assert.Equal(t, 1, len(erl.capacityByClient[client]))
	// because the ERL gives capacity to a reservation, and then asynchronously drains capacity from the share,
	// wait a moment before testing the size of the sharedCapacity
	time.Sleep(100 * time.Millisecond)

	// consuming capacity from a client with a reservation consumes 1 capacity from reservedCapacity
	reservedCapacity, err := erl.ConsumeCapacity(client)
	assert.Equal(t, 1, len(erl.sharedCapacity))
	assert.Equal(t, 0, len(erl.capacityByClient[client]))
	assert.Equal(t, true, reservedCapacity)
	assert.NoError(t, err)

	// if a client uses capacity but their reservedCapacity is empty, consume 1 capacity from sharedCapacity
	reservedCapacity, err = erl.ConsumeCapacity(client)
	assert.Equal(t, 0, len(erl.sharedCapacity))
	assert.Equal(t, 0, len(erl.capacityByClient[client]))
	assert.Equal(t, false, reservedCapacity)
	assert.NoError(t, err)

	// further consumption from the client generates error
	reservedCapacity, err = erl.ConsumeCapacity(client)
	assert.Equal(t, 0, len(erl.sharedCapacity))
	assert.Equal(t, 0, len(erl.capacityByClient[client]))
	assert.Equal(t, false, reservedCapacity)
	assert.Error(t, err)

	// a return with reservation == true will restore the client's reservedCapacity
	err = erl.ReturnCapacity(client, true)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(erl.sharedCapacity))
	assert.Equal(t, 1, len(erl.capacityByClient[client]))
	assert.NoError(t, err)

	// a return with reservation == false will restore the sharedCapacity
	err = erl.ReturnCapacity(client, false)
	assert.Equal(t, 1, len(erl.sharedCapacity))
	assert.Equal(t, 1, len(erl.capacityByClient[client]))
	assert.NoError(t, err)

	// returning such that the sharedCapacity would be overprovisioned gets errors
	err = erl.ReturnCapacity(client, false)
	assert.Equal(t, 1, len(erl.sharedCapacity))
	assert.Equal(t, 1, len(erl.capacityByClient[client]))
	assert.Error(t, err)

	// unknown clients (those without reservation)  get errors
	reservedCapacity, err = erl.ConsumeCapacity("guest client")
	assert.Equal(t, 1, len(erl.sharedCapacity))
	assert.Equal(t, 1, len(erl.capacityByClient[client]))
	assert.Equal(t, false, reservedCapacity)
	assert.Error(t, err)
}

func TestNoCapacityToReserve(t *testing.T) {
	client := "client1"
	erl := NewElasticRateLimiter(2, 1, nil)
	err := erl.OpenReservation(client)
	// because the ERL gives capacity to a reservation, and then asynchronously drains capacity from the share,
	// wait a moment before testing the size of the sharedCapacity
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, len(erl.sharedCapacity))
	assert.Equal(t, 1, len(erl.capacityByClient[client]))
	assert.Equal(t, true, erl.ContainsReservationFor(client))
	assert.NoError(t, err)

	client = "client2"
	err = erl.OpenReservation(client)
	// because the ERL gives capacity to a reservation, and then asynchronously drains capacity from the share,
	// wait a moment before testing the size of the sharedCapacity
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, len(erl.sharedCapacity))
	assert.Equal(t, 1, len(erl.capacityByClient[client]))
	assert.Equal(t, true, erl.ContainsReservationFor(client))
	assert.NoError(t, err)

	// confirm client3 can't have a reservation
	client = "client3"
	err = erl.OpenReservation(client)
	assert.Equal(t, 0, len(erl.sharedCapacity))
	assert.Equal(t, false, erl.ContainsReservationFor(client))
	assert.Error(t, err)
}

func TestReturnCapacityRouting(t *testing.T) {
	client := "client1"
	erl := NewElasticRateLimiter(2, 1, nil)
	err := erl.OpenReservation(client)
	// because the ERL gives capacity to a reservation, and then asynchronously drains capacity from the share,
	// wait a moment before testing the size of the sharedCapacity
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, len(erl.sharedCapacity))
	assert.Equal(t, 1, len(erl.capacityByClient[client]))
	assert.NoError(t, err)
	erl.ConsumeCapacity(client)
	assert.Equal(t, 0, len(erl.capacityByClient[client]))

	// using "false" here lies to the ERL and says the returning capacity is shared
	err = erl.ReturnCapacity(client, false)
	assert.Error(t, err)

	// but if we don't lie, the capacity can be returned
	err = erl.ReturnCapacity(client, true)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(erl.capacityByClient[client]))

	// if a client tries to return a reservedCapacity when it is already full, error
	err = erl.ReturnCapacity(client, true)
	assert.Error(t, err)
	assert.Equal(t, 1, len(erl.capacityByClient[client]))

	// unknown clients can't add any capacity
	err = erl.ReturnCapacity("guest", true)
	assert.Error(t, err)
	err = erl.ReturnCapacity(client, false)
	assert.Error(t, err)

	// once a client has closed its reservation, it can still return its reservedCapacity
	// and the capacity goes to the sharedCapacity
	erl.ConsumeCapacity(client)
	assert.Equal(t, 0, len(erl.capacityByClient[client]))
	erl.CloseReservation(client)
	err = erl.ReturnCapacity(client, true)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(erl.sharedCapacity))
}
