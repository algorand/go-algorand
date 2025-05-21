// Copyright (C) 2019-2025 Algorand, Inc.
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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// ensure v2+ fields fail in TEAL assembler and evaluator on a version before they introduced
// ensure v2+ fields error in v1 program
// ensure the types of the returned values are correct
func TestGlobalVersionsAndTypes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var fields []globalFieldSpec
	for _, fs := range globalFieldSpecs {
		if fs.version > 1 {
			fields = append(fields, fs)
		}
	}
	require.Greater(t, len(fields), 1)

	for _, field := range fields {
		text := "global " + field.field.String()
		// check assembler fails if version before introduction
		testLine(t, text, assemblerNoVersion, "...was introduced in...")
		for v := uint64(0); v < field.version; v++ {
			testLine(t, text, v, "...was introduced in...")
		}
		testLine(t, text, field.version, "")

		// tack on a type check, and return a value (`int` gets compiled
		// differently in different versions, so use intc_0 explicitly
		switch field.ftype.AVMType {
		case avmUint64: // ensure the return type is uint64 by using !
			text = "intcblock 1;" + text + "; !; pop; intc_0"
		case avmBytes: // ensure the return type is bytes by using len
			text = "intcblock 1;" + text + "; len; pop; intc_0"
		case avmAny:
			text = "intcblock 1;" + text + "; pop; intc_0"
		}

		// check success in AssemblerMaxVersion and fs.version
		for _, ver := range []uint64{AssemblerMaxVersion, field.version} {
			ops := testProg(t, text, ver)
			switch field.mode {
			case ModeSig:
				testLogicBytes(t, ops.Program, defaultSigParamsWithVersion(ver))
			case ModeApp:
				testAppBytes(t, ops.Program, defaultAppParamsWithVersion(ver))
			case modeAny:
				testLogicBytes(t, ops.Program, defaultSigParamsWithVersion(ver))
				testAppBytes(t, ops.Program, defaultAppParamsWithVersion(ver))
			default:
				t.Fail()
			}
		}
		ops := testProg(t, text, AssemblerMaxVersion)

		// check on a version before the field version
		preVersion := field.version - 1
		ep := defaultSigParamsWithVersion(preVersion)

		// check failure from whole program version check
		testLogicBytes(t, ops.Program, ep,
			"greater than protocol supported version",
			"greater than protocol supported version")

		// check opcodes failures
		ops.Program[0] = byte(preVersion) // set version
		testLogicBytes(t, ops.Program, ep, "invalid global field")

		// check opcodes failures on 0 version
		ops.Program[0] = 0 // set version to 0
		testLogicBytes(t, ops.Program, ep, "invalid global field")
	}
}

// ensure v2+ fields error in programs of previous version, similarly to global fields test
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

	txn := makeSampleTxn()
	// We'll reject too early if we have a nonzero RekeyTo, because that
	// field must be zero for every txn in the group if this is an old
	// AVM version
	txn.Txn.RekeyTo = basics.Address{}
	txgroup := makeSampleTxnGroup(txn)
	asmDefaultError := "...was introduced in ..."
	for _, fs := range fields {
		field := fs.field.String()
		for _, command := range tests {
			text := fmt.Sprintf(command, field)
			asmError := asmDefaultError
			txnaMode := false
			if fs.array {
				text = fmt.Sprintf(subs[command], field)
				asmError = "...txna opcode was introduced in ..."
				txnaMode = true
			}

			// tack on a type check, and return a value (`int` gets compiled
			// differently in different versions, so use `txn FirstValid` to get
			// a positive integer)
			switch fs.ftype.AVMType {
			case avmUint64: // ensure the return type is uint64 by using !
				text += "; !; pop; txn FirstValid"
			case avmBytes: // ensure the return type is bytes by using len
				text += "; len; pop; txn FirstValid"
			case avmAny:
				text += "; pop; txn FirstValid"
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

			ops := testProg(t, text, AssemblerMaxVersion)

			// check success in AssemblerMaxVersion, fs.version
			// also ensures the field returns the right type
			if !fs.effects {
				txgroup[0].Txn.ApprovalProgram = []byte("approve") // not in standard sample txn
				txgroup[0].Txn.ClearStateProgram = []byte("clear")
				ep := defaultAppParamsWithVersion(AssemblerMaxVersion, txgroup...)
				testAppBytes(t, ops.Program, ep)
				opsv := testProg(t, text, fs.version)
				ep = defaultAppParamsWithVersion(fs.version, txgroup...)
				testAppBytes(t, opsv.Program, ep)
			}

			preVersion := fs.version - 1
			ep := defaultSigParamsWithVersion(preVersion, txgroup...)

			// check failure with version check
			testLogicBytes(t, ops.Program, ep,
				"greater than protocol supported version", "greater than protocol supported version")

			// check opcodes failures
			ops.Program[0] = byte(preVersion) // set version
			checkErr := ""
			evalErr := "invalid txn field"
			if txnaMode && preVersion < txnaVersion {
				checkErr = "illegal opcode"
				evalErr = "illegal opcode"
			}
			testLogicBytes(t, ops.Program, ep, checkErr, evalErr)

			// check opcodes failures on 0 version
			ops.Program[0] = 0 // set version to 0
			checkErr = ""
			evalErr = "invalid txn field"
			if txnaMode {
				checkErr = "illegal opcode"
				evalErr = "illegal opcode"
			}
			testLogicBytes(t, ops.Program, ep, checkErr, evalErr)
		}
	}
}

// ensure itxn_field works properly (only) in the versions it's supposed to work
func TestITxnFieldVersions(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var fields []txnFieldSpec
	for _, fs := range txnFieldSpecs {
		if fs.itxVersion > 0 {
			fields = append(fields, fs)
		}
	}
	require.Greater(t, len(fields), 1)

	txn := makeSampleTxn()
	txgroup := makeSampleTxnGroup(txn)
	asmDefaultError := "...was introduced in ..."

	specialArgs := map[string]string{
		"Type": `byte "pay"`,
		// assets must be available
		"XferAsset":   `int 55`,
		"ConfigAsset": `int 55`,
		"FreezeAsset": `int 55`,
		"Assets":      `int 55`,
		// applications must be available
		"ApplicationID": `int 111`,
		"Applications":  `int 111`,
	}
	for _, fs := range fields {
		field := fs.field.String()
		t.Run(field, func(t *testing.T) {
			text := "itxn_begin; itxn_field " + field + "; int 1"
			asmError := asmDefaultError

			if arg, ok := specialArgs[field]; ok {
				text = arg + ";" + text
			} else {
				// prepend a generic value
				switch fs.ftype.AVMType {
				case avmUint64:
					text = "int 1;" + text
				case avmBytes:
					if fs.ftype == StackAddress {
						text = "txn Sender;" + text
					} else {
						text = fmt.Sprintf("byte 0x%s;", strings.Repeat("aa", int(fs.ftype.Bound[0]))) + text
					}
				case avmAny:
					text = "error;"
				}
			}

			// check assembler fails if version before introduction
			testLine(t, text, assemblerNoVersion, asmError)
			for v := uint64(0); v < fs.itxVersion; v++ {
				testLine(t, text, v, asmError)
			}
			t.Log(text)
			testLine(t, text, fs.itxVersion, "")

			// First, make sure it works when it should
			ops := testProg(t, text, fs.itxVersion)
			ep := defaultAppParamsWithVersion(fs.itxVersion, txgroup...)
			testAppBytes(t, ops.Program, ep)

			// And now make sure it doesn't when it shouldn't
			preVersion := fs.itxVersion - 1
			ep = defaultAppParamsWithVersion(preVersion, txgroup...)

			// we change the program version so can run, but itxn_field opcode
			// still won't.
			ops.Program[0] = byte(preVersion) // set version
			checkErr := ""
			evalErr := "invalid itxn_field " + field
			if preVersion < 5 { // when inners and `itxn_field` were introduced
				checkErr = "illegal opcode"
				evalErr = "illegal opcode"
			}
			testAppBytes(t, ops.Program, ep, checkErr, evalErr)
		})
	}
}

// TestTxnEffectsAvailable ensures that LogicSigs can not use "effects" fields
// (ever). And apps can only use effects fields with `gtxn` after
// txnEffectsVersion. (itxn could use them earlier)
func TestTxnEffectsAvailable(t *testing.T) {
	partitiontest.PartitionTest(t)

	t.Parallel()
	for _, fs := range txnFieldSpecs {
		if !fs.effects {
			continue
		}
		source := fmt.Sprintf("gtxn 0 %s; pop; int 1", fs.field)
		if fs.array {
			source = fmt.Sprintf("gtxn 0 %s 0; pop; int 1", fs.field)
		}
		for v := fs.version; v <= AssemblerMaxVersion; v++ {
			ops := testProg(t, source, v)
			ep, _, _ := makeSampleEnv()
			ep.TxnGroup[1].Lsig.Logic = ops.Program
			_, err := EvalSignature(1, ep)
			require.Error(t, err)
			ep.Ledger = NewLedger(nil)
			_, err = EvalApp(ops.Program, 1, 888, ep)
			if v < txnEffectsVersion {
				require.Error(t, err, source)
			} else {
				if fs.array {
					continue // Array (Logs) will be 0 length, so will fail anyway
				}
				require.NoError(t, err, source)
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
		text := fmt.Sprintf("intcblock 55 1; intc_0; asset_params_get %s; bnz ok; err; ok: ", field.field.String())
		switch field.ftype.AVMType {
		case avmUint64: // ensure the return type is uint64 by adding
			text += " intc_1; +"
		case avmBytes: // ensure the return type is bytes by using len
			text += " len" // also happens to ensure that we get non empty - the params fields are fixed width
		}
		// check assembler fails if version before introduction
		for v := uint64(2); v <= AssemblerMaxVersion; v++ {
			ep, txn, ledger := makeSampleEnv()
			ledger.NewAsset(txn.Sender, 55, basics.AssetParams{})
			ep.Proto.LogicSigVersion = v
			if field.version > v {
				testProg(t, text, v, exp(1, "...was introduced in..."))
				ops := testProg(t, text, field.version) // assemble in the future
				ops.Program[0] = byte(v)
				testAppBytes(t, ops.Program, ep, "invalid asset_params_get field")
			} else {
				testProg(t, text, v)
				testApp(t, text, ep)
			}
		}

	}
}

func TestFieldVersions(t *testing.T) {
	// This test is weird, it confirms that we don't need to bother with a
	// "good" test for AssetHolding fields.  It will fail if we add a field that
	// has a different debut version, and then we'll need a test like
	// TestAppParamsFieldsVersions that checks the field is unavailable before
	// its debut.

	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, fs := range assetHoldingFieldSpecs {
		require.Equal(t, uint64(2), fs.version)
	}
}

// TestAppParamsFieldsVersions tests types and accessibility of various app
// fields over different versions.
func TestAppParamsFieldsVersions(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, field := range appParamsFieldSpecs {
		testLogicRange(t, 2, 0, func(t *testing.T, ep *EvalParams, txn *transactions.Transaction, ledger *Ledger) {
			text := fmt.Sprintf("int 56; app_params_get %s; assert;", field.field)
			if field.ftype.AVMType == avmBytes {
				text += "global ZeroAddress; concat; len" // use concat to prove we have bytes
			} else {
				text += "global ZeroAddress; len; +" // use + to prove we have an int
			}

			v := ep.Proto.LogicSigVersion
			ledger.NewApp(txn.Sender, txn.ForeignApps[0], basics.AppParams{
				ApprovalProgram:   []byte("ap"),
				ClearStateProgram: []byte("cs"),
				GlobalState:       map[string]basics.TealValue{},
				StateSchemas:      basics.StateSchemas{},
				ExtraProgramPages: 2,
				Version:           6,
			})
			if field.version > v {
				// check assembler fails if version before introduction
				testProg(t, text, v, exp(1, "...was introduced in..."))
				ops := testProg(t, text, field.version) // assemble in the future
				ops.Program[0] = byte(v)                // but set version back to before intro
				if v < 5 {
					testAppBytes(t, ops.Program, ep, "illegal opcode", "illegal opcode")
				} else {
					testAppBytes(t, ops.Program, ep, "invalid app_params_get field")
				}
			} else {
				testProg(t, text, v)
				testApp(t, text, ep)
			}
		})
	}
}

func TestAcctParamsFieldsVersions(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, field := range acctParamsFieldSpecs {
		text := fmt.Sprintf("txn Sender; acct_params_get %s; assert;", field.field.String())
		if field.ftype.AVMType == avmBytes {
			text += "global ZeroAddress; concat; len" // use concat to prove we have bytes
		} else {
			text += "global ZeroAddress; len; +" // use + to prove we have an int
		}

		testLogicRange(t, 4, 0, func(t *testing.T, ep *EvalParams, txn *transactions.Transaction, ledger *Ledger) {
			v := ep.Proto.LogicSigVersion
			ledger.NewAccount(txn.Sender, 200_000)
			if field.version > v {
				// check assembler fails if version before introduction
				testProg(t, text, v, exp(1, "...was introduced in..."))
				ops := testProg(t, text, field.version) // assemble in the future
				ops.Program[0] = byte(v)                // but set version back to before intro
				if v < 6 {
					testAppBytes(t, ops.Program, ep, "illegal opcode", "illegal opcode")
				} else {
					testAppBytes(t, ops.Program, ep, "invalid acct_params_get field")
				}
			} else {
				testProg(t, text, v)
				testApp(t, text, ep)
			}
		})

	}
}

func TestBlockFieldsVersions(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, field := range blockFieldSpecs {
		text := fmt.Sprintf("txn FirstValid; int 1; - ; block %s;", field.field)
		if field.ftype.AVMType == avmBytes {
			text += "global ZeroAddress; concat; len" // use concat to prove we have bytes
		} else {
			text += "global ZeroAddress; len; +" // use + to prove we have an int
		}

		testLogicRange(t, 4, 0, func(t *testing.T, ep *EvalParams, txn *transactions.Transaction, ledger *Ledger) {
			v := ep.Proto.LogicSigVersion
			if field.version > v {
				// check assembler fails if version before introduction
				testProg(t, text, v, exp(1, "...was introduced in..."))
				ops := testProg(t, text, field.version) // assemble in the future
				ops.Program[0] = byte(v)                // but set version back to before intro
				if v < randomnessVersion {
					testAppBytes(t, ops.Program, ep, "illegal opcode", "illegal opcode")
				} else {
					testAppBytes(t, ops.Program, ep, "invalid block field")
				}
			} else {
				testProg(t, text, v)
				testApp(t, text, ep)
			}
		})

	}
}
