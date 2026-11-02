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
	"math"
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

// TestMonotonicDecodeFormats checks that Encode still writes the go-codec
// msgpack timestamp that older releases read, and that Decode reads both that
// and the int64 nanosecond form.
func TestMonotonicDecodeFormats(t *testing.T) {
	partitiontest.PartitionTest(t)

	ist := time.FixedZone("IST", 5*3600+30*60)
	pst := time.FixedZone("PST", -8*3600)
	chatham := time.FixedZone("CHAST", 12*3600+45*60)
	instant := time.Date(2026, 11, 2, 12, 34, 56, 789, time.UTC)

	// go-codec writes nil for the zero time, a 4 byte payload for whole seconds
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
		// the encodings carry an instant, not a location
		instant.In(ist),
		instant.In(pst),
		instant.In(chatham),
		time.Now(),
		time.Now().In(ist),
	}
	var m Monotonic[int]
	for _, zero := range times {
		legacy := protocol.EncodeReflect(zero)
		require.Equal(t, legacy, MakeMonotonicClock[int](zero).Encode())
		require.Equal(t, legacy, protocol.EncodeReflect(zero.UTC()), "%v encodes differently from its UTC form", zero)

		forms := [][]byte{legacy}
		if zero.IsZero() {
			forms = append(forms, msgp.AppendNil(nil))
		} else if fitsUnixNano(zero) {
			forms = append(forms, msgp.AppendInt64(nil, zero.UnixNano()))
		}

		for _, data := range forms {
			c, err := m.Decode(data)
			require.NoError(t, err)
			decoded := c.(*Monotonic[int]).zero
			require.True(t, zero.Equal(decoded), "%v decoded as %v from %x", zero, decoded, data)
			require.Equal(t, time.UTC, decoded.Location())
		}
	}
}

// fitsUnixNano reports whether t can be written as an int64 of nanoseconds
// since the Unix epoch, which covers the years 1678 through 2262.
func fitsUnixNano(t time.Time) bool {
	return !t.Before(time.Unix(0, math.MinInt64)) && !t.After(time.Unix(0, math.MaxInt64))
}

// TestMonotonicDecodeFormatsRapid checks the same properties as
// TestMonotonicDecodeFormats for generated instants and UTC offsets.
func TestMonotonicDecodeFormatsRapid(t *testing.T) {
	partitiontest.PartitionTest(t)

	minNanoSec := time.Unix(0, math.MinInt64).Unix()
	maxNanoSec := time.Unix(0, math.MaxInt64).Unix()
	var m Monotonic[int]
	rapid.Check(t, func(t1 *rapid.T) {
		// draw seconds near the go-codec payload boundaries and the int64
		// nanosecond limits, as well as across a wide range
		sec := rapid.OneOf(
			rapid.Int64Range(-1<<40, 1<<40),
			rapid.Custom(func(t2 *rapid.T) int64 {
				base := rapid.SampledFrom([]int64{0, 1 << 32, 1 << 34, minNanoSec, maxNanoSec}).Draw(t2, "base")
				return base + rapid.Int64Range(-2, 2).Draw(t2, "delta")
			}),
		).Draw(t1, "sec")
		nsec := rapid.Int64Range(0, 999999999).Draw(t1, "nsec")
		offset := rapid.IntRange(-14*3600, 14*3600).Draw(t1, "offset")
		zero := time.Unix(sec, nsec).In(time.FixedZone("", offset))

		legacy := protocol.EncodeReflect(zero)
		require.Equal(t1, legacy, MakeMonotonicClock[int](zero).Encode())
		require.Equal(t1, legacy, protocol.EncodeReflect(zero.UTC()))

		forms := [][]byte{legacy}
		if fitsUnixNano(zero) {
			forms = append(forms, msgp.AppendInt64(nil, zero.UnixNano()))
		}
		for _, data := range forms {
			c, err := m.Decode(data)
			require.NoError(t1, err)
			decoded := c.(*Monotonic[int]).zero
			require.True(t1, zero.Equal(decoded), "%v decoded as %v from %x", zero, decoded, data)
			require.Equal(t1, time.UTC, decoded.Location())
		}
	})
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
