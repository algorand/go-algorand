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

// MonotonicDeadlineMonitor is a concerete implementation of the DeadlineMonitor interface
type MonotonicDeadlineMonitor struct {
	clock      WallClock
	expiration time.Duration
	expired    bool
}

// MakeMonotonicDeadlineMonitor creates an instance of the MonotonicDeadlineMonitor type, implementing DeadlineMonitor
func MakeMonotonicDeadlineMonitor(clock WallClock, expiration time.Duration) *MonotonicDeadlineMonitor {
	return &MonotonicDeadlineMonitor{
		clock:      clock,
		expiration: expiration,
	}
}

// Expired return true if the deadline has passed, or false otherwise.
func (m *MonotonicDeadlineMonitor) Expired() bool {
	if m.expired {
		return true
	}
	if m.clock.Since() >= m.expiration {
		m.expired = true
	}
	return m.expired
}
