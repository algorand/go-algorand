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

package timers

import (
	"time"
)

// Frozen is a dummy frozen clock that never fires.
type Frozen[TimeoutType comparable] struct {
	timeoutCh chan time.Time
}

// MakeFrozenClock creates a new frozen clock.
func MakeFrozenClock[TimeoutType comparable]() Clock[TimeoutType] {
	return &Frozen[TimeoutType]{
		timeoutCh: make(chan time.Time, 1),
	}
}

// Zero returns a new Clock reset to the current time.
func (m *Frozen[TimeoutType]) Zero() Clock[TimeoutType] {
	return MakeFrozenClock[TimeoutType]()
}

// TimeoutAt returns a channel that will signal when the duration has elapsed.
func (m *Frozen[TimeoutType]) TimeoutAt(delta time.Duration, timeoutType TimeoutType) <-chan time.Time {
	return m.timeoutCh
}

// Encode implements Clock.Encode.
func (m *Frozen[TimeoutType]) Encode() []byte {
	return []byte{}
}

// Decode implements Clock.Decode.
func (m *Frozen[TimeoutType]) Decode([]byte) (Clock[TimeoutType], error) {
	return MakeFrozenClock[TimeoutType](), nil
}

func (m *Frozen[TimeoutType]) String() string {
	return ""
}

// Since implements the Clock interface.
func (m *Frozen[TimeoutType]) Since() time.Duration {
	return 0
}
