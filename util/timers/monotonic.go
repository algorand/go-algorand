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

package timers

import (
	"time"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// MonotonicFactory allocates Monotonic clocks
type MonotonicFactory struct{}

// Zero returns a new Monotonic clock.
func (_ *MonotonicFactory) Zero(label interface{}) Clock {
	z := time.Now().UTC()
	logging.Base().Debugf("Allocating new clock zeroed to %v", z)
	return MakeMonotonicClock(z)
}

// MakeMonotonicClockFactory creates a new monotonic clock factory.
func MakeMonotonicClockFactory() ClockFactory {
	return &MonotonicFactory{}
}

// Monotonic uses the system's monotonic clock to emit timeouts.
type Monotonic struct {
	zero     time.Time
	timeouts map[time.Duration]<-chan time.Time
}

// MakeMonotonicClock creates a new monotonic clock with a given zero point.
func MakeMonotonicClock(zero time.Time) Clock {
	return &Monotonic{
		zero: zero,
	}
}

// TimeoutAt returns a channel that will signal when the duration has elapsed.
func (m *Monotonic) TimeoutAt(delta time.Duration) <-chan time.Time {
	if m.timeouts == nil {
		m.timeouts = make(map[time.Duration]<-chan time.Time)
	}
	timeoutCh, ok := m.timeouts[delta]
	if ok {
		return timeoutCh
	}

	target := m.zero.Add(delta)
	left := time.Until(target)
	if left < 0 {
		timeout := make(chan time.Time)
		close(timeout)
		timeoutCh = timeout
	} else {
		timeoutCh = time.After(left)
	}
	m.timeouts[delta] = timeoutCh
	return timeoutCh
}

// Encode implements Clock.Encode.
func (m *Monotonic) Encode() []byte {
	return protocol.EncodeReflect(m.zero)
}

// Decode implements Clock.Decode.
func (_ *MonotonicFactory) Decode(data []byte) (Clock, error) {
	var zero time.Time
	err := protocol.DecodeReflect(data, &zero)
	if err == nil {
		logging.Base().Debugf("Clock decoded with zero at %v", zero)
	} else {
		logging.Base().Errorf("Clock decoded with zero at %v (err: %v)", zero, err)
	}
	return MakeMonotonicClock(zero), err
}

func (m *Monotonic) String() string {
	return time.Time(m.zero).String()
}

// GetTimeout returns the absolute time of the timeout target stored in this clock for duration delta.
func (m *Monotonic) GetTimeout(delta time.Duration) time.Time {
	return m.zero.Add(delta)
}

// DurationUntil implements the Clock interface.
func (m *Monotonic) DurationUntil(t time.Time) time.Duration {
	return t.Sub(m.zero)
}

// GC implements the Clock interface.
func (m *Monotonic) GC() {}
