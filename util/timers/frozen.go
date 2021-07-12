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

// Frozen is a dummy frozen clock that never fires.
type Frozen struct {
	timeoutCh chan time.Time
}

// MakeFrozenClock creates a new frozen clock.
func MakeFrozenClock() Clock {
	return &Frozen{
		timeoutCh: make(chan time.Time, 1),
	}
}

// Zero returns a new Clock reset to the current time.
func (m *Frozen) Zero() Clock {
	return MakeFrozenClock()
}

// TimeoutAt returns a channel that will signal when the duration has elapsed.
func (m *Frozen) TimeoutAt(delta time.Duration) <-chan time.Time {
	return m.timeoutCh
}

// Encode implements Clock.Encode.
func (m *Frozen) Encode() []byte {
	return []byte{}
}

// Decode implements Clock.Decode.
func (m *Frozen) Decode([]byte) (Clock, error) {
	return MakeFrozenClock(), nil
}

func (m *Frozen) String() string {
	return ""
}
