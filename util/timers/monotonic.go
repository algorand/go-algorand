// Copyright (C) 2019-2025 Algorand, Inc.
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

package timers

import (
	"time"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type timeout struct {
	delta time.Duration
	ch    <-chan time.Time
}

// Monotonic uses the system's monotonic clock to emit timeouts.
type Monotonic[TimeoutType comparable] struct {
	zero     time.Time
	timeouts map[TimeoutType]timeout
}

// MakeMonotonicClock creates a new monotonic clock with a given zero point.
func MakeMonotonicClock[TimeoutType comparable](zero time.Time) Clock[TimeoutType] {
	return &Monotonic[TimeoutType]{
		zero: zero,
	}
}

// Zero returns a new Clock reset to the current time.
func (m *Monotonic[TimeoutType]) Zero() Clock[TimeoutType] {
	z := time.Now()
	logging.Base().Debugf("Clock zeroed to %v", z)
	return MakeMonotonicClock[TimeoutType](z)
}

// TimeoutAt returns a channel that will signal when the duration has elapsed.
func (m *Monotonic[TimeoutType]) TimeoutAt(delta time.Duration, timeoutType TimeoutType) <-chan time.Time {
	if m.timeouts == nil {
		m.timeouts = make(map[TimeoutType]timeout)
	}

	tmt, ok := m.timeouts[timeoutType]
	if ok && tmt.delta == delta {
		// if the new timeout is the same as the current one for that type,
		// return the existing channel.
		return tmt.ch
	}

	tmt = timeout{delta: delta}

	target := m.zero.Add(delta)
	left := time.Until(target)
	if left < 0 {
		ch := make(chan time.Time)
		close(ch)
		tmt.ch = ch
	} else {
		tmt.ch = time.After(left)
	}
	m.timeouts[timeoutType] = tmt
	return tmt.ch
}

// Encode implements Clock.Encode.
func (m *Monotonic[TimeoutType]) Encode() []byte {
	return protocol.EncodeReflect(m.zero)
}

// Decode implements Clock.Decode.
func (m *Monotonic[TimeoutType]) Decode(data []byte) (Clock[TimeoutType], error) {
	var zero time.Time
	err := protocol.DecodeReflect(data, &zero)
	if err == nil {
		logging.Base().Debugf("Clock decoded with zero at %v", zero)
	} else {
		logging.Base().Errorf("Clock decoded with zero at %v (err: %v)", zero, err)
	}
	return MakeMonotonicClock[TimeoutType](zero), err
}

func (m *Monotonic[TimeoutType]) String() string {
	return time.Time(m.zero).String()
}

// Since returns the time that has passed between the time the clock was last zeroed out and now
func (m *Monotonic[TimeoutType]) Since() time.Duration {
	return time.Since(m.zero)
}
