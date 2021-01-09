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

package memory_test

import (
	"bytes"
	"fmt"
	"io"

	"github.com/algorand/go-algorand/data/basics/newpkg/teal"
	"github.com/algorand/go-algorand/data/basics/newpkg/teal/memory"
)

func ExampleNewSegment() {
	ms := memory.NewSegment(8, 120)
	ms.AllocateAt(1, teal.NewUInt(35))
	ms.AllocateAt(2, teal.NewUInt(44))
	ms.AllocateAt(4, teal.NewByteArray(4))
	ms.SaveSnapshot()

	ms.AllocateAt(0, teal.NewUInt(12345))
	data, _ := ms.Get(1)
	x := data.(*teal.UInt)
	x.SetValue(36, ms)
	x.SetValue(37, ms)

	data, _ = ms.Get(4)
	b := data.(*teal.ByteArray)
	b.Set(1, 100, ms)

	ms.Delete(2)
	ms.AllocateAt(3, teal.NewConstByteArray(make([]byte, 36), false))
	err := ms.AllocateAt(2, teal.NewUInt(55))
	if err == memory.ErrMaxCostExceeded {
		fmt.Printf("ERROR: %v.\n", err)
	}
	ms.Delete(3)
	ms.AllocateAt(2, teal.NewUInt(55))
	fmt.Printf("=====\n%v\nCost: %d/%d\n=====\n", ms.Content(), ms.CurrentCost(), ms.MaxCost())

	buf := new(bytes.Buffer)
	ms.MarshalBinaryTo(buf)
	fmt.Printf("Serialization: %v\nSize of Serialization: %d Bytes\n", buf.Bytes(), len(buf.Bytes()))

	gotMs, _ := memory.ReadSegment(buf)
	fmt.Printf("=====\nRead:\n%v\nCost: %d/%d\n=====\n", gotMs.Content(), gotMs.CurrentCost(), gotMs.MaxCost())

	ms.RestoreSnapshot()
	fmt.Printf("After Restoring Snapshot:\n%v\nCost: %d/%d\n=====\n", ms.Content(), ms.CurrentCost(), ms.MaxCost())

	// Output:
	// ERROR: max protocol's cost is exceeded.
	// =====
	// Memory Segment: (maxSize:8)
	// [0, *teal.UInt)]--->12345
	// [1, *teal.UInt)]--->37
	// [2, *teal.UInt)]--->55
	// [3, <nil>)]---><nil>
	// [4, *teal.ByteArray)]--->[0 100 0 0]
	// [5, <nil>)]---><nil>
	// [6, <nil>)]---><nil>
	// [7, <nil>)]---><nil>
	// Cost: 92/120
	// =====
	// Serialization: [8 120 1 3 185 96 37 55 128 131 4 0 100 0 0 0 3]
	// Size of Serialization: 17 Bytes
	// =====
	// Read:
	// Memory Segment: (maxSize:8)
	// [0, *teal.UInt)]--->12345
	// [1, *teal.UInt)]--->37
	// [2, *teal.UInt)]--->55
	// [3, <nil>)]---><nil>
	// [4, *teal.ByteArray)]--->[0 100 0 0]
	// [5, <nil>)]---><nil>
	// [6, <nil>)]---><nil>
	// [7, <nil>)]---><nil>
	// Cost: 92/120
	// =====
	// After Restoring Snapshot:
	// Memory Segment: (maxSize:8)
	// [0, <nil>)]---><nil>
	// [1, *teal.UInt)]--->35
	// [2, *teal.UInt)]--->44
	// [3, <nil>)]---><nil>
	// [4, *teal.ByteArray)]--->[0 0 0 0]
	// [5, <nil>)]---><nil>
	// [6, <nil>)]---><nil>
	// [7, <nil>)]---><nil>
	// Cost: 84/120
	// =====
}

func ExampleSegment_SaveSnapshot() {
	ms, _ := memory.ReadSegment(reader)
	ms.SaveSnapshot()
	err := executeContract(ms)
	if err != nil {
		ms.RestoreSnapshot()
	}
	ms.DiscardSnapshot()
}

func executeContract(segment *memory.Segment) error {
	return nil
}

var reader io.ByteReader
