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

package logic

import (
	"testing"

	"github.com/stretchr/testify/require"
   "github.com/algorand/go-algorand/testPartitioning"
)

func TestOpDocs(t *testing.T) {
   testPartitioning.PartitionTest(t)

	opsSeen := make(map[string]bool, len(OpSpecs))
	for _, op := range OpSpecs {
		opsSeen[op.Name] = false
	}
	for name := range opDocByName {
		_, exists := opsSeen[name]
		if !exists {
			t.Errorf("error: doc for op %#v that does not exist in OpSpecs", name)
		}
		opsSeen[name] = true
	}
	for op, seen := range opsSeen {
		if !seen {
			t.Errorf("error: doc for op %#v missing from opDocByName", op)
		}
	}
}

func TestOpGroupCoverage(t *testing.T) {
   testPartitioning.PartitionTest(t)

	opsSeen := make(map[string]bool, len(OpSpecs))
	for _, op := range OpSpecs {
		opsSeen[op.Name] = false
	}
	for _, names := range OpGroups {
		for _, name := range names {
			_, exists := opsSeen[name]
			if !exists {
				t.Errorf("error: op %#v in group list but not in OpSpecs\n", name)
				continue
			}
			opsSeen[name] = true
		}
	}
	for name, seen := range opsSeen {
		if !seen {
			t.Errorf("warning: op %#v not in any group of OpGroupList\n", name)
		}
	}
}

func TestOpDoc(t *testing.T) {
   testPartitioning.PartitionTest(t)

	xd := OpDoc("txn")
	require.NotEmpty(t, xd)
	xd = OpDoc("NOT AN INSTRUCTION")
	require.Empty(t, xd)
}

func TestOpImmediateNote(t *testing.T) {
   testPartitioning.PartitionTest(t)

	xd := OpImmediateNote("txn")
	require.NotEmpty(t, xd)
	xd = OpImmediateNote("+")
	require.Empty(t, xd)
}

func TestOpDocExtra(t *testing.T) {
   testPartitioning.PartitionTest(t)

	xd := OpDocExtra("bnz")
	require.NotEmpty(t, xd)
	xd = OpDocExtra("-")
	require.Empty(t, xd)
}

func TestOpAllCosts(t *testing.T) {
   testPartitioning.PartitionTest(t)

	a := OpAllCosts("+")
	require.Len(t, a, 1)
	require.Equal(t, 1, a[0].Cost)

	a = OpAllCosts("sha256")
	require.Len(t, a, 2)
	for _, cost := range a {
		require.True(t, cost.Cost > 1)
	}
}

func TestOnCompletionDescription(t *testing.T) {
   testPartitioning.PartitionTest(t)

	desc := OnCompletionDescription(0)
	require.Equal(t, "Only execute the `ApprovalProgram` associated with this application ID, with no additional effects.", desc)

	desc = OnCompletionDescription(100)
	require.Equal(t, "invalid constant value", desc)
}

func TestFieldDocs(t *testing.T) {
   testPartitioning.PartitionTest(t)

	txnFields := TxnFieldDocs()
	require.Greater(t, len(txnFields), 0)

	globalFields := GlobalFieldDocs()
	require.Greater(t, len(globalFields), 0)

	doc := globalFields["MinTxnFee"]
	require.NotContains(t, doc, "LogicSigVersion >= 2")

	doc = globalFields["Round"]
	require.Contains(t, doc, "LogicSigVersion >= 2")

}
