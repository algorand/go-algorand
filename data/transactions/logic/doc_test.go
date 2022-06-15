// Copyright (C) 2019-2022 Algorand, Inc.
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
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpDocs(t *testing.T) {
	partitiontest.PartitionTest(t)

	opsSeen := make(map[string]bool, len(OpSpecs))
	for _, op := range OpSpecs {
		opsSeen[op.Name] = false
	}
	for name := range opDocByName {
		if _, ok := opsSeen[name]; !ok { // avoid assert.Contains: printing opsSeen is waste
			assert.Fail(t, "opDocByName contains strange opcode", "%#v", name)
		}
		opsSeen[name] = true
	}
	for op, seen := range opsSeen {
		assert.True(t, seen, "opDocByName is missing doc for %#v", op)
	}

	require.Len(t, onCompletionDescriptions, len(OnCompletionNames))
	require.Len(t, TypeNameDescriptions, len(TxnTypeNames))
}

// TestDocStragglers confirms that we don't have any docs laying
// around for non-existent opcodes, most likely from a rename.
func TestDocStragglers(t *testing.T) {
	partitiontest.PartitionTest(t)

	for op := range opDocExtras {
		_, ok := opDocByName[op]
		require.True(t, ok, "%s is in opDocExtra, but not opDocByName", op)
	}
	for op := range opcodeImmediateNotes {
		_, ok := opDocByName[op]
		require.True(t, ok, "%s is in opcodeImmediateNotes, but not opDocByName", op)
	}
}

func TestOpGroupCoverage(t *testing.T) {
	partitiontest.PartitionTest(t)

	opsSeen := make(map[string]bool, len(OpSpecs))
	for _, op := range OpSpecs {
		opsSeen[op.Name] = false
	}
	for _, names := range OpGroups {
		for _, name := range names {
			_, exists := opsSeen[name]
			if !exists {
				t.Errorf("op %#v in group list but not in OpSpecs\n", name)
				continue
			}
			opsSeen[name] = true
		}
	}
	for name, seen := range opsSeen {
		if !seen {
			t.Errorf("op %#v not in any group of OpGroups\n", name)
		}
	}
}

func TestOpDoc(t *testing.T) {
	partitiontest.PartitionTest(t)

	xd := OpDoc("txn")
	require.NotEmpty(t, xd)
	xd = OpDoc("NOT AN INSTRUCTION")
	require.Empty(t, xd)
}

func TestOpImmediateNote(t *testing.T) {
	partitiontest.PartitionTest(t)

	xd := OpImmediateNote("txn")
	require.NotEmpty(t, xd)
	xd = OpImmediateNote("+")
	require.Empty(t, xd)
}

func TestAllImmediatesDocumented(t *testing.T) {
	partitiontest.PartitionTest(t)

	for _, op := range OpSpecs {
		count := len(op.OpDetails.Immediates)
		note := OpImmediateNote(op.Name)
		if count == 1 && op.OpDetails.Immediates[0].kind >= immBytes {
			// More elaborate than can be checked by easy count.
			assert.NotEmpty(t, note)
			continue
		}
		assert.Equal(t, count, strings.Count(note, "{"), "opcodeImmediateNotes for %s is wrong", op.Name)
	}
}

func TestOpDocExtra(t *testing.T) {
	partitiontest.PartitionTest(t)

	xd := OpDocExtra("bnz")
	require.NotEmpty(t, xd)
	xd = OpDocExtra("-")
	require.Empty(t, xd)
}

func TestOpAllCosts(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := OpAllCosts("+")
	require.Len(t, a, 1)
	require.Equal(t, "1", a[0].Cost)

	a = OpAllCosts("sha256")
	require.Len(t, a, 2)
	for _, cost := range a {
		require.True(t, cost.Cost != "0")
	}
}

func TestOnCompletionDescription(t *testing.T) {
	partitiontest.PartitionTest(t)

	desc := OnCompletionDescription(0)
	require.Equal(t, "Only execute the `ApprovalProgram` associated with this application ID, with no additional effects.", desc)

	desc = OnCompletionDescription(100)
	require.Equal(t, "invalid constant value", desc)
}
