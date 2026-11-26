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
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func polled(ch <-chan time.Time) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestMonotonicDelta(t *testing.T) {
	partitiontest.PartitionTest(t)

	var m Monotonic[int]
	var c Clock[int]
	var ch <-chan time.Time

	d := time.Millisecond * 100

	c = m.Zero()
	ch = c.TimeoutAt(d, 0)
	if polled(ch) {
		t.Errorf("channel fired ~100ms early")
	}

	<-time.After(d * 2)
	if !polled(ch) {
		t.Errorf("channel failed to fire at 100ms")
	}

	ch = c.TimeoutAt(d/2, 0)
	if !polled(ch) {
		t.Errorf("channel failed to fire at 50ms")
	}
}

func TestMonotonicZeroDelta(t *testing.T) {
	partitiontest.PartitionTest(t)

	var m Monotonic[int]
	var c Clock[int]
	var ch <-chan time.Time

	c = m.Zero()
	ch = c.TimeoutAt(0, 0)
	if !polled(ch) {
		t.Errorf("read failed on channel at zero timeout")
	}
}

func TestMonotonicNegativeDelta(t *testing.T) {
	partitiontest.PartitionTest(t)

	var m Monotonic[int]
	var c Clock[int]
	var ch <-chan time.Time

	c = m.Zero()
	ch = c.TimeoutAt(-time.Second, 0)
	if !polled(ch) {
		t.Errorf("read failed on channel at negative timeout")
	}
}

func TestMonotonicZeroTwice(t *testing.T) {
	partitiontest.PartitionTest(t)

	var m Monotonic[int]
	var c Clock[int]
	var ch <-chan time.Time

	d := time.Millisecond * 100

	c = m.Zero()
	ch = c.TimeoutAt(d, 0)
	if polled(ch) {
		t.Errorf("channel fired ~100ms early")
	}

	<-time.After(d * 2)
	if !polled(ch) {
		t.Errorf("channel failed to fire at 100ms")
	}

	c = c.Zero()
	ch = c.TimeoutAt(d, 0)
	if polled(ch) {
		t.Errorf("channel fired ~100ms early after call to Zero")
	}

	<-time.After(d * 2)
	if !polled(ch) {
		t.Errorf("channel failed to fire at 100ms after call to Zero")
	}
}

func TestMonotonicEncodeDecode(t *testing.T) {
	partitiontest.PartitionTest(t)

	singleTest := func(c Clock[int], descr string) {
		data := c.Encode()
		c0, err := c.Decode(data)
		if err != nil {
			t.Errorf("decoding error: %v", err)
		}
		if !time.Time(c.(*Monotonic[int]).zero).Equal(time.Time(c0.(*Monotonic[int]).zero)) {
			t.Errorf("%v clock not encoded properly: %v != %v", descr, c, c0)
		}
	}

	var c Clock[int]
	var m Monotonic[int]

	c = Clock[int](&m)
	singleTest(c, "empty")

	c = c.Zero()
	singleTest(c, "Zero()'ed")

	now := time.Now()
	for i := 0; i < 100; i++ {
		r := time.Duration(rand.Int63())
		c = Clock[int](
			&Monotonic[int]{
				zero: now.Add(r),
			},
		)
		singleTest(c, "random")
	}
}

// checkEncodeFormats checks that Encode writes the go-codec msgpack timestamp
// while encodeWithMsgp is unset, that the go-codec timestamp and the MarshalMsg
// form carry the instant and not the location, and that Decode reads both back
// to the same instant in UTC.
func checkEncodeFormats(t require.TestingT, ref time.Time) {
	c := MakeMonotonicClock[int](ref).(*Monotonic[int])
	cUTC := MakeMonotonicClock[int](ref.UTC()).(*Monotonic[int])

	legacy := protocol.EncodeReflect(ref)
	require.Equal(t, legacy, c.Encode(), "encodeWithMsgp is set")
	require.Equal(t, legacy, protocol.EncodeReflect(ref.UTC()), "%v encodes differently from its UTC form", ref)

	msgpForm := protocol.Encode(c)
	require.Equal(t, msgp.ArrayType, msgp.NextType(msgpForm))
	require.Equal(t, msgpForm, protocol.Encode(cUTC), "%v encodes differently from its UTC form", ref)

	for _, data := range [][]byte{legacy, msgpForm} {
		decoded, err := c.Decode(data)
		require.NoError(t, err)
		got := decoded.(*Monotonic[int]).zero
		require.True(t, ref.Equal(got), "%v decoded as %v from %x", ref, got, data)
		require.Equal(t, time.UTC, got.Location())
	}
}

func TestMonotonicDecodeFormats(t *testing.T) {
	partitiontest.PartitionTest(t)

	ist := time.FixedZone("IST", 5*3600+30*60)
	pst := time.FixedZone("PST", -8*3600)
	chatham := time.FixedZone("CHAST", 12*3600+45*60)
	instant := time.Date(2026, 11, 2, 12, 34, 56, 789, time.UTC)

	// go-codec writes nil for time.Time{}, a 4 byte payload for whole seconds
	// below 2^32, an 8 byte payload for nanoseconds or seconds below 2^34, and a
	// 12 byte payload for anything else; cover each form and its boundaries.
	times := []time.Time{
		{},
		time.Unix(0, 1),
		time.Unix(1700000000, 0),
		time.Unix(1<<32-1, 0),
		time.Unix(1<<32, 0),
		time.Unix(1700000000, 123456789),
		time.Unix(1700000000, 999999999),
		time.Unix(1<<34-1, 999999999),
		time.Unix(1<<34, 0),
		time.Unix(-1, 0),
		time.Date(1900, 1, 2, 3, 4, 5, 6, time.UTC),
		time.Date(2600, 1, 2, 3, 4, 5, 6, time.UTC),
		instant.In(ist),
		instant.In(pst),
		instant.In(chatham),
		time.Now(),
		time.Now().In(ist),
	}
	for _, ref := range times {
		checkEncodeFormats(t, ref)
	}
}

func TestMonotonicDecodeFormatsRapid(t *testing.T) {
	partitiontest.PartitionTest(t)

	rapid.Check(t, func(t1 *rapid.T) {
		// draw seconds near the go-codec payload boundaries and time.Time{}, as
		// well as across a wide range
		sec := rapid.OneOf(
			rapid.Int64Range(-1<<40, 1<<40),
			rapid.Custom(func(t2 *rapid.T) int64 {
				base := rapid.SampledFrom([]int64{0, 1 << 32, 1 << 34, time.Time{}.Unix()}).Draw(t2, "base")
				return base + rapid.Int64Range(-2, 2).Draw(t2, "delta")
			}),
		).Draw(t1, "sec")
		nsec := rapid.Int64Range(0, 999999999).Draw(t1, "nsec")
		offset := rapid.IntRange(-14*3600, 14*3600).Draw(t1, "offset")
		checkEncodeFormats(t1, time.Unix(sec, nsec).In(time.FixedZone("", offset)))
	})
}

// TestMonotonicDecodeMsgpErrors checks that Decode rejects malformed
// MarshalMsg arrays.
func TestMonotonicDecodeMsgpErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	array := func(elems ...int64) []byte {
		b := msgp.AppendArrayHeader(nil, uint32(len(elems)))
		for _, e := range elems {
			b = msgp.AppendInt64(b, e)
		}
		return b
	}
	tests := []struct {
		data []byte
		err  string
	}{
		{array(1700000000), "has 1 elements, want 2"},
		{array(1700000000, 0, 0), "has 3 elements, want 2"},
		{array(1700000000, -1), "nanoseconds -1 out of range"},
		{array(1700000000, int64(time.Second)), "nanoseconds 1000000000 out of range"},
		{array(1700000000, 0)[:3], "too few bytes"},
	}
	var m Monotonic[int]
	for _, test := range tests {
		_, err := m.Decode(test.data)
		require.ErrorContains(t, err, test.err, "%x", test.data)
	}
}

func TestTimeoutTypes(t *testing.T) {
	partitiontest.PartitionTest(t)

	var m Monotonic[int]
	var c Clock[int]

	d := time.Millisecond * 100

	c = m.Zero()
	ch1 := c.TimeoutAt(d, 0)
	ch2 := c.TimeoutAt(d, 1)
	if polled(ch1) {
		t.Errorf("channel fired ~100ms early")
	}
	if polled(ch2) {
		t.Errorf("channel fired ~100ms early")
	}

	if ch1 == ch2 {
		t.Errorf("equal channels for different timeout types")
	}

	<-time.After(d * 2)
	if !polled(ch1) {
		t.Errorf("channel failed to fire at 100ms")
	}
	if !polled(ch2) {
		t.Errorf("channel failed to fire at 100ms")
	}

	ch1 = c.TimeoutAt(d/2, 0)
	if !polled(ch1) {
		t.Errorf("channel failed to fire at 50ms")
	}
	ch2 = c.TimeoutAt(d/2, 0)
	if !polled(ch2) {
		t.Errorf("channel failed to fire at 50ms")
	}
}
