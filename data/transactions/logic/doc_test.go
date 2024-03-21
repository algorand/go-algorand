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
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpDocs(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	opsSeen := make(map[string]bool, len(OpSpecs))
	for _, op := range OpSpecs {
		opsSeen[op.Name] = false
	}
	for name := range opDescByName {
		if _, ok := opsSeen[name]; !ok { // avoid assert.Contains: printing opsSeen is waste
			assert.Fail(t, "opDescByName contains strange opcode", "%#v", name)
		}
		opsSeen[name] = true
	}
	for op, seen := range opsSeen {
		assert.True(t, seen, "opDescByName is missing description for %#v", op)
	}

	require.Len(t, onCompletionDescriptions, len(OnCompletionNames))
	require.Len(t, TypeNameDescriptions, len(TxnTypeNames))
}

func TestOpGroupCoverage(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	opsSeen := make(map[string]int, len(OpSpecs))
	for _, op := range OpSpecs {
		opsSeen[op.Name] = 0
	}
	for _, names := range OpGroups {
		for _, name := range names {
			_, exists := opsSeen[name]
			if !exists {
				t.Errorf("op %#v in group list but not in OpSpecs\n", name)
				continue
			}
			opsSeen[name]++
		}
	}
	for name, seen := range opsSeen {
		if seen == 0 {
			t.Errorf("op %#v not in any group of OpGroups\n", name)
		}
		if seen > 1 {
			t.Errorf("op %#v in %d groups of OpGroups\n", name, seen)
		}
	}
}

func TestOpDoc(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	xd := OpDoc("txn")
	require.NotEmpty(t, xd)
	xd = OpDoc("NOT AN INSTRUCTION")
	require.Empty(t, xd)
}

func TestOpImmediateDetails(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, os := range OpSpecs {
		deets := OpImmediateDetailsFromSpec(os)
		require.Equal(t, len(os.Immediates), len(deets))

		for idx, d := range deets {
			imm := os.Immediates[idx]
			require.NotEmpty(t, d.Comment)
			require.Equal(t, strings.ToLower(d.Name), imm.Name)
			require.Equal(t, d.Encoding, imm.kind.String())

			if imm.Group != nil {
				require.Equal(t, d.Reference, imm.Group.Name)
			}
		}
	}
}

func TestOpDocExtra(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	xd := OpDocExtra("bnz")
	require.NotEmpty(t, xd)
	xd = OpDocExtra("-")
	require.Empty(t, xd)
}

func TestOnCompletionDescription(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	desc := OnCompletionDescription(0)
	require.Equal(t, "Only execute the `ApprovalProgram` associated with this application ID, with no additional effects.", desc)

	desc = OnCompletionDescription(100)
	require.Equal(t, "invalid constant value", desc)
}
