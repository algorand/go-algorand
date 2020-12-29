// Copyright (C) 2019-2020 Algorand, Inc.
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

package memory_test

import (
	"github.com/algorand/go-algorand/data/basics/newpkg/memory"
	"github.com/algorand/go-algorand/data/basics/newpkg/teal"
	"github.com/stretchr/testify/require"
	"testing"
)

// TODO: add more test for serialization and type registration

func TestMemorySegment_Snapshot(t *testing.T) {
	var want string

	m := memory.NewSegment(5, 500)
	m.AllocateAt(2, teal.NewUInt(22))
	m.SaveSnapshot()
	before := m.Content()
	costBefore := m.CurrentCost()
	barr := teal.NewByteArray(4)
	barr.Set(0, 7, nil)
	m.AllocateAt(0, barr)

	t.Run("InitialSetup",
		func(t *testing.T) {
			want = "Memory Segment: (maxSize:5)\n[0, *teal.ByteArray)]--->[7 0 0 0]\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->22\n[3, <nil>)]---><nil>\n[4, <nil>)]---><nil>"
			require.Equal(t, want, m.Content())
		})

	t.Run("RestoringOnMainArray",
		func(t *testing.T) {
			m.RestoreSnapshot()
			require.Equal(t, before, m.Content())

			m.AllocateAt(4, teal.NewUInt(3))
			m.RestoreSnapshot()
			require.Equal(t, before, m.Content())
			require.Equal(t, costBefore, m.CurrentCost())
		})

	t.Run("CompactAndExpand",
		func(t *testing.T) {
			m.DiscardSnapshot()
			want = "Memory Segment: (maxSize:5)\n[0, <nil>)]---><nil>\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->22"
			require.Equal(t, want, m.Content())

			m.SetMinPackingGain(0.4)
			m.SaveSnapshot()
			m.DiscardSnapshot()
			want = "Memory Segment: (maxSize:5)\n[0, <nil>)]---><nil>\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->22\n[3, <nil>)]---><nil>\n[4, <nil>)]---><nil>"
			require.Equal(t, want, m.Content())

			m.SetMinPackingGain(0.39)
			m.SaveSnapshot()
			m.DiscardSnapshot()
			want = "Memory Segment: (maxSize:5)\n[0, <nil>)]---><nil>\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->22"
			require.Equal(t, want, m.Content())

			m.SetMinPackingGain(0.15)
			m.SaveSnapshot()
			m.AllocateAt(4, barr)
			m.DiscardSnapshot()
			want = "Memory Segment: (maxSize:5)\n[0, <nil>)]---><nil>\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->22\n[3, <nil>)]---><nil>\n[4, *teal.ByteArray)]--->[7 0 0 0]"
			require.Equal(t, want, m.Content())
		})

	t.Run("RestoringMultipleUpdates",
		func(t *testing.T) {
			m.SaveSnapshot()
			barr.Set(0, 3, m)
			m.SaveSnapshot()
			before = m.Content()
			costBefore = m.CurrentCost()
			barr.Set(0, 5, m)
			barr.Set(2, 6, m)
			barr.Set(2, 10, m)
			i, _ := m.Get(2)
			i.(*teal.UInt).SetValue(45, m)
			m.Delete(2)
			want = "Memory Segment: (maxSize:5)\n[0, <nil>)]---><nil>\n[1, <nil>)]---><nil>\n[2, <nil>)]---><nil>\n[3, <nil>)]---><nil>\n[4, *teal.ByteArray)]--->[5 0 10 0]"
			require.Equal(t, want, m.Content())

			m.AllocateAt(2, teal.NewUInt(42))
			m.AllocateAt(0, teal.NewUInt(11))
			i, _ = m.Get(0)
			i.(*teal.UInt).SetValue(15, m)
			i.(*teal.UInt).SetValue(16, m)
			want = "Memory Segment: (maxSize:5)\n[0, *teal.UInt)]--->16\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->42\n[3, <nil>)]---><nil>\n[4, *teal.ByteArray)]--->[5 0 10 0]"
			require.Equal(t, want, m.Content())
			require.Equal(t, memory.NewSegment(5, 600).CurrentCost()+2*i.Cost()+barr.Cost(), m.CurrentCost())

			m.RestoreSnapshot()
			require.Equal(t, before, m.Content())
			require.Equal(t, costBefore, m.CurrentCost())
		})
}

func TestMemorySegment_Cost(t *testing.T) {
	require.Panics(t, func() { memory.NewSegment(7, 50) })

	m := memory.NewSegment(6, 500)
	b := teal.NewByteArray(10)
	i := teal.NewUInt(20)
	c := m.CurrentCost() + b.Cost() + i.Cost()
	m.SetMaxCost(c - 1)
	m.AllocateAt(2, b)
	err := m.AllocateAt(0, teal.NewUInt(2))
	require.EqualError(t, err, memory.ErrMaxCostExceeded.Error())
	want := "Memory Segment: (maxSize:6)\n[0, <nil>)]---><nil>\n[1, <nil>)]---><nil>\n[2, *teal.ByteArray)]--->[0 0 0 0 0 0 0 0 0 0]\n[3, <nil>)]---><nil>\n[4, <nil>)]---><nil>\n[5, <nil>)]---><nil>"
	require.Equal(t, want, m.Content())
	require.Panics(t, func() { m.SetMaxCost(b.Cost()) })
	m.SaveSnapshot()
	costBefore := m.CurrentCost()

	m.SetMaxCost(c)
	m.AllocateAt(1, i)
	want = "Memory Segment: (maxSize:6)\n[0, <nil>)]---><nil>\n[1, *teal.UInt)]--->20\n[2, *teal.ByteArray)]--->[0 0 0 0 0 0 0 0 0 0]\n[3, <nil>)]---><nil>\n[4, <nil>)]---><nil>\n[5, <nil>)]---><nil>"
	require.Equal(t, want, m.Content())

	m.Delete(2)
	require.Equal(t, c-b.Cost(), m.CurrentCost())

	m.RestoreSnapshot()
	require.Equal(t, costBefore, m.CurrentCost())
}

func TestMemorySegment_AllocateAt(t *testing.T) {
	var err error
	m := memory.NewSegment(0, 500)

	err = m.AllocateAt(0, teal.NewUInt(6))
	require.IsTypef(t, new(memory.OutOfBoundsError), err, "Invalid error in 0 size memory")

	m = memory.NewSegment(5, 500)
	m.DiscardSnapshot()
	err = m.AllocateAt(5, teal.NewUInt(5))
	require.IsType(t, new(memory.OutOfBoundsError), err)

	want := "Memory Segment: (maxSize:5)"
	require.Equal(t, want, m.Content())

	m.AllocateAt(2, teal.NewUInt(12))
	want = "Memory Segment: (maxSize:5)\n[0, <nil>)]---><nil>\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->12\n[3, <nil>)]---><nil>\n[4, <nil>)]---><nil>"
	require.Equal(t, want, m.Content())

	m.DiscardSnapshot()
	err = m.AllocateAt(2, teal.NewUInt(12))
	require.EqualError(t, err, memory.ErrCellNotEmpty.Error())

	m.AllocateAt(0, teal.NewUInt(7))
	want = "Memory Segment: (maxSize:5)\n[0, *teal.UInt)]--->7\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->12"
	require.Equal(t, want, m.Content())
}

func TestMemorySegment_Get(t *testing.T) {
	var err error
	m := memory.NewSegment(0, 500)

	_, err = m.Get(0)
	require.IsTypef(t, new(memory.OutOfBoundsError), err, "Invalid error in 0 size memory")

	m = memory.NewSegment(8, 500)
	barr := teal.NewByteArray(3)
	barr.Set(2, 12, m)
	m.AllocateAt(2, barr)
	m.DiscardSnapshot()
	_, err = m.Get(0)
	require.EqualError(t, err, memory.ErrCellIsEmpty.Error())

	_, err = m.Get(3)
	require.EqualError(t, err, memory.ErrCellIsEmpty.Error(), "Invalid error after compaction")

	temp, _ := m.Get(2)
	_, err = temp.(*teal.ByteArray).Get(3)
	require.IsType(t, new(memory.OutOfBoundsError), err)

	b, _ := barr.Get(2)
	require.Equal(t, uint8(12), b, "Error in getting values of a ByteArray")
}

func TestConstByteArray(t *testing.T) {
	b1 := []byte{2, 0, 4, 1}
	cb := teal.NewConstByteArray(b1, true)
	want := "[2 0 4 1]"
	require.Equal(t, want, cb.String())

	b2 := []byte{2, 0, 4, 1}
	require.True(t, cb.EqualsToSlice(b2))

	b2[2] = 3
	require.False(t, cb.EqualsToSlice(b2))

	other := teal.NewConstByteArray(b2, true)
	require.False(t, cb.Equals(other))

	b2[2] = 4
	other = teal.NewConstByteArray(b2, true)
	require.True(t, cb.Equals(other))
}
