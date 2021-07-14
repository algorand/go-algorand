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

// Package timers provides a Clock abstraction useful for simulating timeouts.
package timers

import (
	"time"
)

// Clock provides timeout events which fire at some point after a point in time.
type Clock interface {
	// Zero returns a reset Clock. TimeoutAt channels will use the point
	// at which Zero was called as their reference point.
	Zero() Clock

	// GetZero returns the zero time stored in this clock.
	GetZero() time.Time

	// GetTimeout returns the absolute time of the timeout target stored in this clock for duration delta.
	GetTimeout(delta time.Duration) time.Time

	// TimeoutAt returns a channel that fires delta time after Zero was called.
	// If delta has already passed, it returns a closed channel.
	//
	// TimeoutAt must be called after Zero; otherwise, the channel's behavior is undefined.
	TimeoutAt(delta time.Duration) <-chan time.Time

	// Encode serializes the Clock into a byte slice.
	Encode() []byte

	// Decode deserializes the Clock from a byte slice.
	// A Clock which has been Decoded from an Encoded Clock should produce
	// the same timeouts as the original Clock.
	Decode([]byte) (Clock, error)
}

// ClockFactory provides a source of new Clock instances.
type ClockFactory interface {
	// Zero returns a new Clock, with zero set to now.
	Zero() Clock
}
