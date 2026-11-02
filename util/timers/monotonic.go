// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"fmt"
	"time"

	"github.com/algorand/msgp/msgp"

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

// encodeWithMsgp is whether Encode writes the clock with MarshalMsg instead of
// go-codec's msgpack timestamp extension. Decode reads both, so this can be
// enabled once no node can roll back to a release whose Decode reads only the
// go-codec timestamp.
const encodeWithMsgp = false

var _ msgp.Marshaler = (*Monotonic[int])(nil)
var _ msgp.Unmarshaler = (*Monotonic[int])(nil)

// MarshalMsg implements msgp.Marshaler. It writes the reference point as a
// msgpack array of its Unix seconds and its nanoseconds within that second.
// Pending timeouts are not encoded.
func (m *Monotonic[TimeoutType]) MarshalMsg(b []byte) []byte {
	b = msgp.AppendArrayHeader(b, 2)
	b = msgp.AppendInt64(b, m.zero.Unix())
	return msgp.AppendInt64(b, int64(m.zero.Nanosecond()))
}

// CanMarshalMsg implements msgp.Marshaler.
func (m *Monotonic[TimeoutType]) CanMarshalMsg(z any) bool {
	_, ok := (z).(*Monotonic[TimeoutType])
	return ok
}

// UnmarshalMsgWithState implements msgp.Unmarshaler. It reads the MarshalMsg
// form into a clock with no pending timeouts.
func (m *Monotonic[TimeoutType]) UnmarshalMsgWithState(bts []byte, st msgp.UnmarshalState) ([]byte, error) {
	if st.AllowableDepth == 0 {
		return bts, msgp.ErrMaxDepthExceeded{}
	}
	sz, _, bts, err := msgp.ReadArrayHeaderBytes(bts)
	if err != nil {
		return bts, err
	}
	if sz != 2 {
		return bts, fmt.Errorf("monotonic clock has %d elements, want 2", sz)
	}
	sec, bts, err := msgp.ReadInt64Bytes(bts)
	if err != nil {
		return bts, err
	}
	nsec, bts, err := msgp.ReadInt64Bytes(bts)
	if err != nil {
		return bts, err
	}
	if nsec < 0 || nsec >= int64(time.Second) {
		return bts, fmt.Errorf("monotonic clock has nanoseconds %d out of range", nsec)
	}
	*m = Monotonic[TimeoutType]{zero: time.Unix(sec, nsec).UTC()}
	return bts, nil
}

// UnmarshalMsg implements msgp.Unmarshaler.
func (m *Monotonic[TimeoutType]) UnmarshalMsg(bts []byte) ([]byte, error) {
	return m.UnmarshalMsgWithState(bts, msgp.DefaultUnmarshalState)
}

// CanUnmarshalMsg implements msgp.Unmarshaler.
func (m *Monotonic[TimeoutType]) CanUnmarshalMsg(z any) bool {
	_, ok := (z).(*Monotonic[TimeoutType])
	return ok
}

// Encode implements Clock.Encode; see encodeWithMsgp.
func (m *Monotonic[TimeoutType]) Encode() []byte {
	if encodeWithMsgp {
		return protocol.Encode(m)
	}
	return protocol.EncodeReflect(m.zero) //nolint:forbidigo // older releases read only the go-codec time.Time encoding
}

// Decode implements Clock.Decode. It reads both go-codec's msgpack timestamp
// and the MarshalMsg form.
func (m *Monotonic[TimeoutType]) Decode(data []byte) (Clock[TimeoutType], error) {
	var zero time.Time
	var err error
	switch msgp.NextType(data) {
	case msgp.ArrayType:
		var c Monotonic[TimeoutType]
		err = protocol.Decode(data, &c)
		zero = c.zero
	case msgp.NilType:
		// go-codec writes time.Time{} as nil
		_, err = msgp.ReadNilBytes(data)
	default:
		err = protocol.DecodeReflect(data, &zero) //nolint:forbidigo // reads the go-codec time.Time encoding
	}
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
