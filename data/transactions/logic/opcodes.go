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
	"sort"
)

// LogicVersion defines default assembler and max eval versions
const LogicVersion = 3

// rekeyingEnabledVersion is the version of TEAL where RekeyTo functionality
// was enabled. This is important to remember so that old TEAL accounts cannot
// be maliciously or accidentally rekeyed. Do not edit!
const rekeyingEnabledVersion = 2

// appsEnabledVersion is the version of TEAL where ApplicationCall
// functionality was enabled. We use this to disallow v0 and v1 TEAL programs
// from being used with applications. Do not edit!
const appsEnabledVersion = 2

// opSize records the length in bytes for an op that is constant-length but not length 1
type opSize struct {
	cost      int
	size      int
	checkFunc opCheckFunc
}

var opSizeDefault = opSize{1, 1, nil}

// OpSpec defines one byte opcode
type OpSpec struct {
	Opcode  byte
	Name    string
	op      opEvalFunc      // evaluate the op
	asm     assembleFunc    // assemble the op
	dis     disassembleFunc // disassemble the op
	Args    StackTypes      // what gets popped from the stack
	Returns StackTypes      // what gets pushed to the stack
	Version uint64          // TEAL version opcode introduced
	Modes   runMode         // if non-zero, then (mode & Modes) != 0 to allow
	opSize  opSize          // opSizes records the size of ops that are constant size but not 1, time 'cost' and custom check functions.
}

var oneBytes = StackTypes{StackBytes}
var twoBytes = StackTypes{StackBytes, StackBytes}
var threeBytes = StackTypes{StackBytes, StackBytes, StackBytes}
var byteIntInt = StackTypes{StackBytes, StackUint64, StackUint64}
var oneInt = StackTypes{StackUint64}
var twoInts = StackTypes{StackUint64, StackUint64}
var oneAny = StackTypes{StackAny}
var twoAny = StackTypes{StackAny, StackAny}

// OpSpecs is the table of operations that can be assembled and evaluated.
//
// Any changes should be reflected in README_in.md which serves as the language spec.
//
// WARNING: special case op assembly by argOps functions must do their own type stack maintenance via ops.tpop() ops.tpush()/ops.tpusha()
var OpSpecs = []OpSpec{
	{0x00, "err", opErr, asmDefault, disDefault, nil, nil, 1, modeAny, opSizeDefault},
	{0x01, "sha256", opSHA256, asmDefault, disDefault, oneBytes, oneBytes, 1, modeAny, opSize{7, 1, nil}},
	{0x02, "keccak256", opKeccak256, asmDefault, disDefault, oneBytes, oneBytes, 1, modeAny, opSize{26, 1, nil}},
	{0x03, "sha512_256", opSHA512_256, asmDefault, disDefault, oneBytes, oneBytes, 1, modeAny, opSize{9, 1, nil}},

	// Cost of these opcodes increases in TEAL version 2 based on measured
	// performance. Should be able to run max hashes during stateful TEAL
	// and achieve reasonable TPS. Same opcode for different TEAL versions
	// is OK.
	{0x01, "sha256", opSHA256, asmDefault, disDefault, oneBytes, oneBytes, 2, modeAny, opSize{35, 1, nil}},
	{0x02, "keccak256", opKeccak256, asmDefault, disDefault, oneBytes, oneBytes, 2, modeAny, opSize{130, 1, nil}},
	{0x03, "sha512_256", opSHA512_256, asmDefault, disDefault, oneBytes, oneBytes, 2, modeAny, opSize{45, 1, nil}},

	{0x04, "ed25519verify", opEd25519verify, asmDefault, disDefault, threeBytes, oneInt, 1, runModeSignature, opSize{1900, 1, nil}},
	{0x08, "+", opPlus, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x09, "-", opMinus, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x0a, "/", opDiv, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x0b, "*", opMul, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x0c, "<", opLt, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x0d, ">", opGt, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x0e, "<=", opLe, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x0f, ">=", opGe, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x10, "&&", opAnd, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x11, "||", opOr, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x12, "==", opEq, asmDefault, disDefault, twoAny, oneInt, 1, modeAny, opSizeDefault},
	{0x13, "!=", opNeq, asmDefault, disDefault, twoAny, oneInt, 1, modeAny, opSizeDefault},
	{0x14, "!", opNot, asmDefault, disDefault, oneInt, oneInt, 1, modeAny, opSizeDefault},
	{0x15, "len", opLen, asmDefault, disDefault, oneBytes, oneInt, 1, modeAny, opSizeDefault},
	{0x16, "itob", opItob, asmDefault, disDefault, oneInt, oneBytes, 1, modeAny, opSizeDefault},
	{0x17, "btoi", opBtoi, asmDefault, disDefault, oneBytes, oneInt, 1, modeAny, opSizeDefault},
	{0x18, "%", opModulo, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x19, "|", opBitOr, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x1a, "&", opBitAnd, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x1b, "^", opBitXor, asmDefault, disDefault, twoInts, oneInt, 1, modeAny, opSizeDefault},
	{0x1c, "~", opBitNot, asmDefault, disDefault, oneInt, oneInt, 1, modeAny, opSizeDefault},
	{0x1d, "mulw", opMulw, asmDefault, disDefault, twoInts, twoInts, 1, modeAny, opSizeDefault},
	{0x1e, "addw", opAddw, asmDefault, disDefault, twoInts, twoInts, 2, modeAny, opSizeDefault},

	{0x20, "intcblock", opIntConstBlock, assembleIntCBlock, disIntcblock, nil, nil, 1, modeAny, opSize{1, 0, checkIntConstBlock}},
	{0x21, "intc", opIntConstLoad, assembleIntC, disIntc, nil, oneInt, 1, modeAny, opSize{1, 2, nil}},
	{0x22, "intc_0", opIntConst0, asmDefault, disDefault, nil, oneInt, 1, modeAny, opSizeDefault},
	{0x23, "intc_1", opIntConst1, asmDefault, disDefault, nil, oneInt, 1, modeAny, opSizeDefault},
	{0x24, "intc_2", opIntConst2, asmDefault, disDefault, nil, oneInt, 1, modeAny, opSizeDefault},
	{0x25, "intc_3", opIntConst3, asmDefault, disDefault, nil, oneInt, 1, modeAny, opSizeDefault},
	{0x26, "bytecblock", opByteConstBlock, assembleByteCBlock, disBytecblock, nil, nil, 1, modeAny, opSize{1, 0, checkByteConstBlock}},
	{0x27, "bytec", opByteConstLoad, assembleByteC, disBytec, nil, oneBytes, 1, modeAny, opSize{1, 2, nil}},
	{0x28, "bytec_0", opByteConst0, asmDefault, disDefault, nil, oneBytes, 1, modeAny, opSizeDefault},
	{0x29, "bytec_1", opByteConst1, asmDefault, disDefault, nil, oneBytes, 1, modeAny, opSizeDefault},
	{0x2a, "bytec_2", opByteConst2, asmDefault, disDefault, nil, oneBytes, 1, modeAny, opSizeDefault},
	{0x2b, "bytec_3", opByteConst3, asmDefault, disDefault, nil, oneBytes, 1, modeAny, opSizeDefault},
	{0x2c, "arg", opArg, assembleArg, disArg, nil, oneBytes, 1, runModeSignature, opSize{1, 2, nil}},
	{0x2d, "arg_0", opArg0, asmDefault, disDefault, nil, oneBytes, 1, runModeSignature, opSizeDefault},
	{0x2e, "arg_1", opArg1, asmDefault, disDefault, nil, oneBytes, 1, runModeSignature, opSizeDefault},
	{0x2f, "arg_2", opArg2, asmDefault, disDefault, nil, oneBytes, 1, runModeSignature, opSizeDefault},
	{0x30, "arg_3", opArg3, asmDefault, disDefault, nil, oneBytes, 1, runModeSignature, opSizeDefault},
	{0x31, "txn", opTxn, assembleTxn, disTxn, nil, oneAny, 1, modeAny, opSize{1, 2, nil}},
	// It is ok to have the same opcode for different TEAL versions.
	// This 'txn' asm command supports additional argument in version 2 and
	// generates 'txna' opcode in that particular case
	{0x31, "txn", opTxn, assembleTxn2, disTxn, nil, oneAny, 2, modeAny, opSize{1, 2, nil}},
	{0x32, "global", opGlobal, assembleGlobal, disGlobal, nil, oneAny, 1, modeAny, opSize{1, 2, nil}},
	{0x33, "gtxn", opGtxn, assembleGtxn, disGtxn, nil, oneAny, 1, modeAny, opSize{1, 3, nil}},
	{0x33, "gtxn", opGtxn, assembleGtxn2, disGtxn, nil, oneAny, 2, modeAny, opSize{1, 3, nil}},
	{0x34, "load", opLoad, assembleLoad, disLoad, nil, oneAny, 1, modeAny, opSize{1, 2, nil}},
	{0x35, "store", opStore, assembleStore, disStore, oneAny, nil, 1, modeAny, opSize{1, 2, nil}},
	{0x36, "txna", opTxna, assembleTxna, disTxna, nil, oneAny, 2, modeAny, opSize{1, 3, nil}},
	{0x37, "gtxna", opGtxna, assembleGtxna, disGtxna, nil, oneAny, 2, modeAny, opSize{1, 4, nil}},

	{0x40, "bnz", opBnz, assembleBranch, disBranch, oneInt, nil, 1, modeAny, opSize{1, 3, checkBranch}},
	{0x41, "bz", opBz, assembleBranch, disBranch, oneInt, nil, 2, modeAny, opSize{1, 3, checkBranch}},
	{0x42, "b", opB, assembleBranch, disBranch, nil, nil, 2, modeAny, opSize{1, 3, checkBranch}},
	{0x43, "return", opReturn, asmDefault, disDefault, oneInt, nil, 2, modeAny, opSizeDefault},
	{0x48, "pop", opPop, asmDefault, disDefault, oneAny, nil, 1, modeAny, opSizeDefault},
	{0x49, "dup", opDup, asmDefault, disDefault, oneAny, twoAny, 1, modeAny, opSizeDefault},
	{0x4a, "dup2", opDup2, asmDefault, disDefault, twoAny, twoAny.plus(twoAny), 2, modeAny, opSizeDefault},

	{0x50, "concat", opConcat, asmDefault, disDefault, twoBytes, oneBytes, 2, modeAny, opSizeDefault},
	{0x51, "substring", opSubstring, assembleSubstring, disSubstring, oneBytes, oneBytes, 2, modeAny, opSize{1, 3, nil}},
	{0x52, "substring3", opSubstring3, asmDefault, disDefault, byteIntInt, oneBytes, 2, modeAny, opSizeDefault},

	{0x60, "balance", opBalance, asmDefault, disDefault, oneInt, oneInt, 2, runModeApplication, opSizeDefault},
	{0x61, "app_opted_in", opAppCheckOptedIn, asmDefault, disDefault, twoInts, oneInt, 2, runModeApplication, opSizeDefault},
	{0x62, "app_local_get", opAppGetLocalState, asmDefault, disDefault, oneInt.plus(oneBytes), oneAny, 2, runModeApplication, opSizeDefault},
	{0x63, "app_local_get_ex", opAppGetLocalStateEx, asmDefault, disDefault, twoInts.plus(oneBytes), oneAny.plus(oneInt), 2, runModeApplication, opSizeDefault},
	{0x64, "app_global_get", opAppGetGlobalState, asmDefault, disDefault, oneBytes, oneAny, 2, runModeApplication, opSizeDefault},
	{0x65, "app_global_get_ex", opAppGetGlobalStateEx, asmDefault, disDefault, oneInt.plus(oneBytes), oneAny.plus(oneInt), 2, runModeApplication, opSizeDefault},
	{0x66, "app_local_put", opAppPutLocalState, asmDefault, disDefault, oneInt.plus(oneBytes).plus(oneAny), nil, 2, runModeApplication, opSizeDefault},
	{0x67, "app_global_put", opAppPutGlobalState, asmDefault, disDefault, oneBytes.plus(oneAny), nil, 2, runModeApplication, opSizeDefault},
	{0x68, "app_local_del", opAppDeleteLocalState, asmDefault, disDefault, oneInt.plus(oneBytes), nil, 2, runModeApplication, opSizeDefault},
	{0x69, "app_global_del", opAppDeleteGlobalState, asmDefault, disDefault, oneBytes, nil, 2, runModeApplication, opSizeDefault},

	{0x70, "asset_holding_get", opAssetHoldingGet, assembleAssetHolding, disAssetHolding, twoInts, oneAny.plus(oneInt), 2, runModeApplication, opSize{1, 2, nil}},
	{0x71, "asset_params_get", opAssetParamsGet, assembleAssetParams, disAssetParams, oneInt, oneAny.plus(oneInt), 2, runModeApplication, opSize{1, 2, nil}},

	{0x72, "assert", opAssert, asmDefault, disDefault, oneInt, nil, 3, modeAny, opSizeDefault},
	{0x73, "min_balance", opMinBalance, asmDefault, disDefault, oneInt, oneInt, 3, runModeApplication, opSizeDefault},
}

type sortByOpcode []OpSpec

func (a sortByOpcode) Len() int           { return len(a) }
func (a sortByOpcode) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a sortByOpcode) Less(i, j int) bool { return a[i].Opcode < a[j].Opcode }

// OpcodesByVersion returns list of opcodes available in a specific version of TEAL
// by copying v1 opcodes to v2, and then on to v3 to create a full list
func OpcodesByVersion(version uint64) []OpSpec {
	// for updated opcodes use the lowest version opcode was introduced in
	maxOpcode := 0
	for i := 0; i < len(OpSpecs); i++ {
		if int(OpSpecs[i].Opcode) > maxOpcode {
			maxOpcode = int(OpSpecs[i].Opcode)
		}
	}
	updated := make([]int, maxOpcode+1)
	for idx := range OpSpecs {
		op := OpSpecs[idx].Opcode
		cv := updated[op]
		if cv == 0 {
			cv = int(OpSpecs[idx].Version)
		} else {
			if int(OpSpecs[idx].Version) < cv {
				cv = int(OpSpecs[idx].Version)
			}
		}
		updated[op] = cv
	}

	subv := make(map[byte]OpSpec)
	for idx := range OpSpecs {
		if OpSpecs[idx].Version <= version {
			op := OpSpecs[idx].Opcode
			subv[op] = OpSpecs[idx]
			// if the opcode was updated then assume backward compatibility
			// and set version to minimum available
			if updated[op] < int(OpSpecs[idx].Version) {
				copy := OpSpecs[idx]
				copy.Version = uint64(updated[op])
				subv[op] = copy
			}
		}
	}
	result := make([]OpSpec, 0, len(subv))
	for _, v := range subv {
		result = append(result, v)
	}
	sort.Sort(sortByOpcode(result))
	return result
}

// direct opcode bytes
var opsByOpcode [LogicVersion + 1][256]OpSpec
var opsByName [LogicVersion + 1]map[string]OpSpec

// Migration from TEAL v1 to TEAL v2.
// TEAL v1 allowed execution of program with version 0.
// With TEAL v2 opcode versions are introduced and they are bound to every opcode.
// There is no opcodes with version 0 so that TEAL v2 evaluator rejects any program with version 0.
// To preserve backward compatibility version 0 array is populated with TEAL v1 opcodes
// with the version overwritten to 0.
func init() {
	// First, initialize baseline v1 opcodes.
	// Zero (empty) version is an alias for TEAL v1 opcodes and needed for compatibility with v1 code.
	opsByName[0] = make(map[string]OpSpec, 256)
	opsByName[1] = make(map[string]OpSpec, 256)
	for _, oi := range OpSpecs {
		if oi.Version == 1 {
			cp := oi
			cp.Version = 0
			opsByOpcode[0][oi.Opcode] = cp
			opsByName[0][oi.Name] = cp

			opsByOpcode[1][oi.Opcode] = oi
			opsByName[1][oi.Name] = oi
		}
	}
	// Start from v2 TEAL and higher,
	// copy lower version opcodes and overwrite matching version
	for v := uint64(2); v <= EvalMaxVersion; v++ {
		opsByName[v] = make(map[string]OpSpec, 256)

		// Copy opcodes from lower version
		for opName, oi := range opsByName[v-1] {
			opsByName[v][opName] = oi
		}
		for op, oi := range opsByOpcode[v-1] {
			opsByOpcode[v][op] = oi
		}

		// Update tables with opcodes from the current version
		for _, oi := range OpSpecs {
			if oi.Version == v {
				opsByOpcode[v][oi.Opcode] = oi
				opsByName[v][oi.Name] = oi
			}
		}
	}
}
