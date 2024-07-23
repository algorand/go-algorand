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

package logic

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestLineToPC(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	dState := DebugState{
		Disassembly: "abc\ndef\nghi",
		PCOffset:    []PCOffset{{PC: 1, Offset: 4}, {PC: 2, Offset: 8}, {PC: 3, Offset: 12}},
	}
	pc := dState.LineToPC(0)
	require.Equal(t, 0, pc)

	pc = dState.LineToPC(1)
	require.Equal(t, 1, pc)

	pc = dState.LineToPC(2)
	require.Equal(t, 2, pc)

	pc = dState.LineToPC(3)
	require.Equal(t, 3, pc)

	pc = dState.LineToPC(4)
	require.Equal(t, 0, pc)

	pc = dState.LineToPC(-1)
	require.Equal(t, 0, pc)

	pc = dState.LineToPC(0x7fffffff)
	require.Equal(t, 0, pc)

	dState.PCOffset = []PCOffset{}
	pc = dState.LineToPC(1)
	require.Equal(t, 0, pc)

	dState.PCOffset = []PCOffset{{PC: 1, Offset: 0}}
	pc = dState.LineToPC(1)
	require.Equal(t, 0, pc)
}

const testCallStackProgram string = `intcblock 1
callsub label1
intc_0
label1:
callsub label2
label2:
intc_0
`

func TestParseCallstack(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	expectedCallFrames := []CallFrame{
		{
			FrameLine: 1,
			LabelName: "label1",
		},
		{
			FrameLine: 4,
			LabelName: "label2",
		},
	}

	dState := DebugState{
		Disassembly: testCallStackProgram,
		PCOffset:    []PCOffset{{PC: 1, Offset: 18}, {PC: 4, Offset: 30}, {PC: 7, Offset: 45}, {PC: 8, Offset: 65}, {PC: 11, Offset: 88}},
	}
	callstack := []frame{{retpc: 4}, {retpc: 8}}

	cfs := dState.parseCallstack(callstack)
	require.Equal(t, expectedCallFrames, cfs)
}
