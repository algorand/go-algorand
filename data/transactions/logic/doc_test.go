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
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestOpDocs(t *testing.T) {
	partitiontest.PartitionTest(t)

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

	require.Len(t, txnFieldDocs, len(TxnFieldNames))
	require.Len(t, onCompletionDescriptions, len(OnCompletionNames))
	require.Len(t, globalFieldDocs, len(GlobalFieldNames))
	require.Len(t, AssetHoldingFieldDocs, len(AssetHoldingFieldNames))
	require.Len(t, assetParamsFieldDocs, len(AssetParamsFieldNames))
	require.Len(t, appParamsFieldDocs, len(AppParamsFieldNames))
	require.Len(t, TypeNameDescriptions, len(TxnTypeNames))
	require.Len(t, EcdsaCurveDocs, len(EcdsaCurveNames))
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
				t.Errorf("error: op %#v in group list but not in OpSpecs\n", name)
				continue
			}
			opsSeen[name] = true
		}
	}
	for name, seen := range opsSeen {
		if !seen {
			t.Errorf("warning: op %#v not in any group of OpGroups\n", name)
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
		count := len(op.Details.Immediates)
		note := OpImmediateNote(op.Name)
		if count == 1 && op.Details.Immediates[0].kind >= immBytes {
			// More elaborate than can be checked by easy count.
			require.NotEmpty(t, note)
			continue
		}
		require.Equal(t, count, strings.Count(note, "{"), "%s immediates doc is wrong", op.Name)
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
	require.Equal(t, 1, a[0].Cost)

	a = OpAllCosts("sha256")
	require.Len(t, a, 2)
	for _, cost := range a {
		require.True(t, cost.Cost > 1)
	}
}

func TestOnCompletionDescription(t *testing.T) {
	partitiontest.PartitionTest(t)

	desc := OnCompletionDescription(0)
	require.Equal(t, "Only execute the `ApprovalProgram` associated with this application ID, with no additional effects.", desc)

	desc = OnCompletionDescription(100)
	require.Equal(t, "invalid constant value", desc)
}

func TestFieldDocs(t *testing.T) {
	partitiontest.PartitionTest(t)

	txnFields := TxnFieldDocs()
	require.Greater(t, len(txnFields), 0)

	globalFields := GlobalFieldDocs()
	require.Greater(t, len(globalFields), 0)

	doc := globalFields["MinTxnFee"]
	require.NotContains(t, doc, "LogicSigVersion >= 2")

	doc = globalFields["Round"]
	require.Contains(t, doc, "LogicSigVersion >= 2")

}
