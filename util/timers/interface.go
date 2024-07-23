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

// Package timers provides a Clock abstraction useful for simulating timeouts.
package timers

import (
	"time"
)

// Clock provides timeout events which fire at some point after a point in time.
type Clock[TimeoutType comparable] interface {
	// Zero returns a reset Clock. TimeoutAt channels will use the point
	// at which Zero was called as their reference point.
	Zero() Clock[TimeoutType]

	// Since returns the time spent between the last time the clock was zeroed out and the current
	// wall clock time.
	Since() time.Duration

	// TimeoutAt returns a channel that fires delta time after Zero was called.
	// timeoutType is specifies the reason for this timeout. If there are two
	// timeouts of the same type at the same time, then only one of them fires.
	// If delta has already passed, it returns a closed channel.
	//
	// TimeoutAt must be called after Zero; otherwise, the channel's behavior is
	// undefined.
	TimeoutAt(delta time.Duration, timeoutType TimeoutType) <-chan time.Time

	// Encode serializes the Clock into a byte slice.
	Encode() []byte

	// Decode deserializes the Clock from a byte slice.
	// A Clock which has been Decoded from an Encoded Clock should produce
	// the same timeouts as the original Clock.
	Decode([]byte) (Clock[TimeoutType], error)
}
