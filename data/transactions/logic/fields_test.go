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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logictest"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestArrayFields(t *testing.T) {
	partitiontest.PartitionTest(t)
	require.Equal(t, len(TxnaFieldNames), len(TxnaFieldTypes))
	require.Equal(t, len(txnaFieldSpecByField), len(TxnaFieldTypes))
}

// ensure v2+ fields fail in TEAL assembler and evaluator on a version before they introduced
// ensure v2+ fields error in v1 program
func TestGlobalFieldsVersions(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var fields []globalFieldSpec
	for _, fs := range globalFieldSpecs {
		if fs.version > 1 {
			fields = append(fields, fs)
		}
	}
	require.Greater(t, len(fields), 1)

	ledger := logictest.MakeLedger(nil)
	for _, field := range fields {
		text := fmt.Sprintf("global %s", field.field.String())
		// check assembler fails if version before introduction
		testLine(t, text, assemblerNoVersion, "...available in version...")
		for v := uint64(0); v < field.version; v++ {
			testLine(t, text, v, "...available in version...")
		}
		testLine(t, text, field.version, "")

		ops := testProg(t, text, AssemblerMaxVersion)

		// check on a version before the field version
		preLogicVersion := field.version - 1
		proto := defaultEvalProtoWithVersion(preLogicVersion)
		if preLogicVersion < appsEnabledVersion {
			require.False(t, proto.Application)
		}
		ep := defaultEvalParams(nil, nil)
		ep.Proto = &proto
		ep.Ledger = ledger

		// check failure with version check
		_, err := Eval(ops.Program, ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), "greater than protocol supported version")

		// check opcodes failures
		ops.Program[0] = byte(preLogicVersion) // set version
		_, err = Eval(ops.Program, ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid global field")

		// check opcodes failures on 0 version
		ops.Program[0] = 0 // set version to 0
		_, err = Eval(ops.Program, ep)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid global field")
	}
}

// ensure v2+ fields error in programs of previous TEAL version, similarly to global fields test
func TestTxnFieldVersions(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	var fields []txnFieldSpec
	for _, fs := range txnFieldSpecs {
		if fs.version > 1 {
			fields = append(fields, fs)
		}
	}
	require.Greater(t, len(fields), 1)

	tests := []string{
		"txn %s",
		"gtxn 0 %s",
	}
	subs := map[string]string{
		tests[0]: "txna %s 0",
		tests[1]: "gtxna 0 %s 0",
	}
	txnaVersion := uint64(appsEnabledVersion)

	ledger := logictest.MakeLedger(nil)
	txn := makeSampleTxn()
	// We'll reject too early if we have a nonzero RekeyTo, because that
	// field must be zero for every txn in the group if this is an old
	// TEAL version
	txn.Txn.RekeyTo = basics.Address{}
	txgroup := makeSampleTxnGroup(txn)
	asmDefaultError := "...available in version ..."
	for _, fs := range fields {
		field := fs.field.String()
		for _, command := range tests {
			text := fmt.Sprintf(command, field)
			asmError := asmDefaultError
			txnaMode := false
			if _, ok := txnaFieldSpecByField[fs.field]; ok {
				text = fmt.Sprintf(subs[command], field)
				asmError = "...txna opcode was introduced in ..."
				txnaMode = true
			}
			// check assembler fails if version before introduction
			testLine(t, text, assemblerNoVersion, asmError)
			for v := uint64(0); v < fs.version; v++ {
				if txnaMode && v >= txnaVersion {
					asmError = asmDefaultError
				}
				testLine(t, text, v, asmError)
			}
			testLine(t, text, fs.version, "")

			ops, err := AssembleStringWithVersion(text, AssemblerMaxVersion)
			require.NoError(t, err)

			preLogicVersion := fs.version - 1
			proto := defaultEvalProtoWithVersion(preLogicVersion)
			if preLogicVersion < appsEnabledVersion {
				require.False(t, proto.Application)
			}
			ep := defaultEvalParams(nil, nil)
			ep.Proto = &proto
			ep.Ledger = ledger
			ep.TxnGroup = txgroup

			// check failure with version check
			_, err = Eval(ops.Program, ep)
			require.Error(t, err)
			require.Contains(t, err.Error(), "greater than protocol supported version")

			// check opcodes failures
			ops.Program[0] = byte(preLogicVersion) // set version
			_, err = Eval(ops.Program, ep)
			require.Error(t, err)
			if txnaMode && preLogicVersion < txnaVersion {
				require.Contains(t, err.Error(), "illegal opcode")
			} else {
				require.Contains(t, err.Error(), "invalid txn field")
			}

			// check opcodes failures on 0 version
			ops.Program[0] = 0 // set version to 0
			_, err = Eval(ops.Program, ep)
			require.Error(t, err)
			if txnaMode {
				require.Contains(t, err.Error(), "illegal opcode")
			} else {
				require.Contains(t, err.Error(), "invalid txn field")
			}
		}
	}
}

func TestAssetParamsFieldsVersions(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var fields []assetParamsFieldSpec
	for _, fs := range assetParamsFieldSpecs {
		if fs.version > 2 {
			fields = append(fields, fs)
		}
	}
	require.Greater(t, len(fields), 0)

	for _, field := range fields {
		// Need to use intc so we can "backversion" the
		// program and not have it fail because of pushint.
		text := fmt.Sprintf("intcblock 0 1; intc_0; asset_params_get %s; pop; pop; intc_1", field.field.String())
		// check assembler fails if version before introduction
		for v := uint64(2); v <= AssemblerMaxVersion; v++ {
			ep, _ := makeSampleEnv()
			ep.Proto.LogicSigVersion = v
			if field.version > v {
				testProg(t, text, v, expect{3, "...available in version..."})
				ops := testProg(t, text, field.version) // assemble in the future
				scratch := ops.Program
				scratch[0] = byte(v) // but we'll tweak the version byte back to v
				err := CheckStateful(scratch, ep)
				require.NoError(t, err)
				pass, err := EvalStateful(scratch, ep) // so eval fails on future field
				require.False(t, pass)
				require.Error(t, err)
				require.Contains(t, err.Error(), "invalid asset_params_get field")
			} else {
				testProg(t, text, v)
				testApp(t, text, ep)
			}
		}

	}
}

func TestFieldVersions(t *testing.T) {
	// This test is weird, it confirms that we don't need to
	// bother with a "good" test for AssetHolding and AppParams
	// fields.  It will fail if we add a field that has a
	// different teal debut version, and then we'll need a test
	// like TestAssetParamsFieldsVersions that checks the field is
	// unavailable before its debut.

	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, fs := range assetHoldingFieldSpecs {
		require.Equal(t, uint64(2), fs.version)
	}

	for _, fs := range appParamsFieldSpecs {
		require.Equal(t, uint64(5), fs.version)
	}
}
