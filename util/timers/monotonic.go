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

// Zero returns a new Clock reset to the current time.
func (m *Monotonic) Zero() Clock {
	z := time.Now()
	logging.Base().Debugf("Clock zeroed to %v", z)
	return MakeMonotonicClock(z)
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
	left := target.Sub(time.Now())
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
func (m *Monotonic) Decode(data []byte) (Clock, error) {
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
	return m.zero.String()
}
