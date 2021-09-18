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
)

// FrozenFactory is a dummy clock factory.
type FrozenFactory struct{}

// MakeFrozenClockFactory makes a new frozen clock factory.
func MakeFrozenClockFactory() ClockFactory {
	return &FrozenFactory{}
}

// Zero implements ClockFactory
func (_ *FrozenFactory) Zero(label interface{}) Clock {
	return MakeFrozenClock()
}

// Decode implements ClockFactory
func (_ *FrozenFactory) Decode(_ []byte) (Clock, error) {
	return MakeFrozenClock(), nil
}

// Frozen is a dummy frozen clock that never fires.
type Frozen struct {
	timeoutCh chan struct{}
}

// MakeFrozenClock creates a new frozen clock.
func MakeFrozenClock() Clock {
	return &Frozen{
		timeoutCh: make(chan struct{}, 1),
	}
}

// TimeoutAt returns a channel that will signal when the duration has elapsed.
func (m *Frozen) TimeoutAt(delta time.Duration) <-chan struct{} {
	return m.timeoutCh
}

// Encode implements Clock.Encode.
func (m *Frozen) Encode() []byte {
	return []byte{}
}

// DurationUntil implements the Clock interface.
func (m *Frozen) DurationUntil(t time.Time) time.Duration {
	return time.Second
}

// GetTimeout implements the Clock interface.
func (m *Frozen) GetTimeout(delta time.Duration) time.Time {
	return time.Time{}
}

// GC implements the Clock interface.
func (m *Frozen) GC() {
}

func (m *Frozen) String() string {
	return ""
}
