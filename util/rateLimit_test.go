package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewElasticRateLimiter(t *testing.T) {
	erl := NewElasticRateLimiter(100, 10, nil)

	assert.Equal(t, len(erl.sharedCapacity), 100)
	assert.Equal(t, len(erl.capacityByClient), 0)
}

func TestReserveUnreserveCapacity(t *testing.T) {
	client := "client"
	erl := NewElasticRateLimiter(100, 10, nil)
	erl.ReserveCapacity(client)
	assert.Equal(t, len(erl.sharedCapacity), 90)
	assert.Equal(t, len(erl.capacityByClient), 1)
	assert.Equal(t, len(erl.capacityByClient[client]), 10)

	erl.UnreserveCapacity(client)
	assert.Equal(t, len(erl.sharedCapacity), 100)
	assert.Equal(t, len(erl.capacityByClient), 0)
}

func TestConsumeReturnCapacity(t *testing.T) {
	client := "client"
	erl := NewElasticRateLimiter(100, 10, nil)
	erl.ReserveCapacity(client)

	reservedCapacity, err := erl.ConsumeCapacity(client)
	assert.Equal(t, len(erl.sharedCapacity), 90)
	assert.Equal(t, len(erl.capacityByClient), 1)
	assert.Equal(t, len(erl.capacityByClient[client]), 9)
	assert.Equal(t, reservedCapacity, true)
	assert.Nil(t, err)

	err = erl.ReturnCapacity(client, reservedCapacity)
	assert.Equal(t, len(erl.sharedCapacity), 90)
	assert.Equal(t, len(erl.capacityByClient), 1)
	assert.Equal(t, len(erl.capacityByClient[client]), 10)
	assert.Nil(t, err)
}

func TestConsumeSharedCapacity(t *testing.T) {
	client := "client"
	erl := NewElasticRateLimiter(100, 1, nil)
	erl.ReserveCapacity(client)

	reservedCapacity, err := erl.ConsumeCapacity(client)
	assert.Equal(t, len(erl.sharedCapacity), 90)
	assert.Equal(t, len(erl.capacityByClient[client]), 0)
	assert.Equal(t, reservedCapacity, true)
	assert.Nil(t, err)

	reservedCapacity, err = erl.ConsumeCapacity(client)
	assert.Equal(t, len(erl.sharedCapacity), 89)
	assert.Equal(t, len(erl.capacityByClient[client]), 0)
	assert.Equal(t, reservedCapacity, false)
	assert.Nil(t, err)

	err = erl.ReturnCapacity(client, reservedCapacity)
	assert.Equal(t, len(erl.sharedCapacity), 90)
	assert.Equal(t, len(erl.capacityByClient[client]), 0)
	assert.Nil(t, err)

	// "guests" can use sharedCapacity
	reservedCapacity, err = erl.ConsumeCapacity("guest client")
	assert.Equal(t, len(erl.sharedCapacity), 89)
	assert.Equal(t, len(erl.capacityByClient[client]), 0)
	assert.Equal(t, reservedCapacity, false)
	assert.Nil(t, err)
}

func TestConsumedAllCapacity(t *testing.T) {
	client := "client"
	erl := NewElasticRateLimiter(2, 1, nil)
	erl.ReserveCapacity(client)
	assert.Equal(t, len(erl.sharedCapacity), 1)
	assert.Equal(t, len(erl.capacityByClient[client]), 1)

	reservedCapacity, err := erl.ConsumeCapacity(client)
	assert.Equal(t, len(erl.sharedCapacity), 1)
	assert.Equal(t, len(erl.capacityByClient[client]), 0)
	assert.Equal(t, reservedCapacity, true)
	assert.Nil(t, err)

	reservedCapacity, err = erl.ConsumeCapacity(client)
	assert.Equal(t, len(erl.sharedCapacity), 0)
	assert.Equal(t, len(erl.capacityByClient[client]), 0)
	assert.Equal(t, reservedCapacity, false)
	assert.Nil(t, err)

	// Check that further use of the capacity creates an error
	reservedCapacity, err = erl.ConsumeCapacity(client)
	assert.Equal(t, len(erl.sharedCapacity), 0)
	assert.Equal(t, len(erl.capacityByClient[client]), 0)
	assert.Equal(t, reservedCapacity, false)
	assert.Error(t, err)

	// Return ReservedCapacity explicitly, and confirm "guests" still can't use sharedCapacity
	erl.ReturnCapacity(client, true)
	reservedCapacity, err = erl.ConsumeCapacity("guest client")
	assert.Equal(t, len(erl.sharedCapacity), 0)
	assert.Equal(t, len(erl.capacityByClient[client]), 0)
	assert.Equal(t, reservedCapacity, false)
	assert.Error(t, err)
}

func TestNoCapacityToReserve(t *testing.T) {
	client := "client1"
	erl := NewElasticRateLimiter(2, 1, nil)
	err := erl.ReserveCapacity(client)
	assert.Equal(t, len(erl.sharedCapacity), 1)
	assert.Equal(t, len(erl.capacityByClient[client]), 1)
	assert.NoError(t, err)
	client = "client2"
	err = erl.ReserveCapacity(client)
	assert.Equal(t, len(erl.sharedCapacity), 0)
	assert.Equal(t, len(erl.capacityByClient[client]), 1)
	assert.NoError(t, err)
	// confirm resourc3 can't have a reservation
	client = "client3"
	err = erl.ReserveCapacity(client)
	assert.Equal(t, len(erl.sharedCapacity), 0)
	assert.Error(t, err)
	assert.Equal(t, erl.ContainsReservationFor(client), false)
	// innapropriately fill the shared capacity, and confirm it still won't overprovision
	erl.ReturnCapacity(nil, false)
	erl.ReturnCapacity(nil, false)
	client = "client4"
	err = erl.ReserveCapacity(client)
	assert.Equal(t, len(erl.sharedCapacity), 0)
	assert.Error(t, err)
	assert.Equal(t, erl.ContainsReservationFor(client), false)
}
