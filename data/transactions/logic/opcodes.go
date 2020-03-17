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

package logic

import "sort"

// LogicVersion defines default assembler and max eval versions
const LogicVersion = 2

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
	Modes   uint64          // if non-zero, then (mode & Modes) != 0 to allow
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
var threeInts = StackTypes{StackUint64, StackUint64, StackUint64}

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
	{0x31, "txn", opTxn, assembleTxn, disTxn, nil, oneAny, 1, modeAny, opSize{1, 2, nil}},             // TODO: check output type by subfield retrieved in txn,global,account,txid
	{0x31, "txn", opTxn, assembleTxn2, disTxn, nil, oneAny, 2, modeAny, opSize{1, 2, nil}},            // TODO: check output type by subfield retrieved in txn,global,account,txid
	{0x32, "global", opGlobal, assembleGlobal, disGlobal, nil, oneAny, 1, modeAny, opSize{1, 2, nil}}, // TODO: check output type against specific field
	{0x33, "gtxn", opGtxn, assembleGtxn, disGtxn, nil, oneAny, 1, modeAny, opSize{1, 3, nil}},         // TODO: check output type by subfield retrieved in txn,global,account,txid
	{0x33, "gtxn", opGtxn, assembleGtxn2, disGtxn, nil, oneAny, 2, modeAny, opSize{1, 3, nil}},        // TODO: check output type by subfield retrieved in txn,global,account,txid
	{0x34, "load", opLoad, assembleLoad, disLoad, nil, oneAny, 1, modeAny, opSize{1, 2, nil}},
	{0x35, "store", opStore, assembleStore, disStore, oneAny, nil, 1, modeAny, opSize{1, 2, nil}},
	{0x36, "txna", opTxna, assembleTxna, disTxna, nil, oneAny, 2, modeAny, opSize{1, 3, nil}},     // TODO: check output type by subfield retrieved in txn,global,account,txid
	{0x37, "gtxna", opGtxna, assembleGtxna, disGtxna, nil, oneAny, 2, modeAny, opSize{1, 4, nil}}, // TODO: check output type by subfield retrieved in txn,global,account,txid

	{0x40, "bnz", opBnz, assembleBnz, disBnz, oneInt, nil, 1, modeAny, opSize{1, 3, checkBnz}},
	{0x48, "pop", opPop, asmDefault, disDefault, oneAny, nil, 1, modeAny, opSizeDefault},
	{0x49, "dup", opDup, asmDefault, disDefault, oneAny, twoAny, 1, modeAny, opSizeDefault},
	{0x50, "concat", opConcat, asmDefault, disDefault, twoBytes, oneBytes, 2, modeAny, opSizeDefault},
	{0x51, "substring", opSubstring, assembleSubstring, disSubstring, oneBytes, oneBytes, 2, modeAny, opSize{1, 3, nil}},
	{0x52, "substring3", opSubstring3, asmDefault, disDefault, byteIntInt, oneBytes, 2, modeAny, opSizeDefault},

	{0x60, "balance", opBalance, asmDefault, disDefault, oneInt, oneInt, 2, runModeApplication, opSizeDefault},
	{0x61, "app_opted_in", opAppCheckOptedIn, asmDefault, disDefault, twoInts, oneInt, 2, runModeApplication, opSizeDefault},
	{0x62, "app_read_local", opAppReadLocalState, asmDefault, disDefault, twoInts.plus(oneBytes), oneInt.plus(oneAny), 2, runModeApplication, opSizeDefault},
	{0x63, "app_read_global", opAppReadGlobalState, asmDefault, disDefault, oneBytes, oneInt.plus(oneAny), 2, runModeApplication, opSizeDefault},
	{0x64, "app_write_local", opAppWriteLocalState, asmDefault, disDefault, oneInt.plus(oneBytes).plus(oneAny), nil, 2, runModeApplication, opSizeDefault},
	{0x65, "app_write_global", opAppWriteGlobalState, asmDefault, disDefault, oneBytes.plus(oneAny), nil, 2, runModeApplication, opSizeDefault},
	{0x66, "app_delete_local", opAppDeleteLocalState, asmDefault, disDefault, oneInt.plus(oneBytes), nil, 2, runModeApplication, opSizeDefault},
	{0x67, "app_delete_global", opAppDeleteGlobalState, asmDefault, disDefault, oneBytes, nil, 2, runModeApplication, opSizeDefault},

	{0x70, "asset_read_holding", opAssetReadHolding, assembleAssetHolding, disAssetHolding, twoInts, oneInt.plus(oneAny), 2, runModeApplication, opSize{1, 2, nil}},
	{0x71, "asset_read_params", opAssetReadParams, assembleAssetParams, disAssetParams, twoInts, oneInt.plus(oneAny), 2, runModeApplication, opSize{1, 2, nil}},
}

type sortByOpcode []OpSpec

func (a sortByOpcode) Len() int           { return len(a) }
func (a sortByOpcode) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a sortByOpcode) Less(i, j int) bool { return a[i].Opcode < a[j].Opcode }

// OpcodesByVersion returns list of opcodes available in a specific version of TEAL
func OpcodesByVersion(version uint64) []OpSpec {
	sub := make(map[byte]OpSpec)
	for idx := range OpSpecs {
		if OpSpecs[idx].Version <= version {
			sub[OpSpecs[idx].Opcode] = OpSpecs[idx]
		}
	}
	result := make([]OpSpec, 0, len(sub))
	for _, v := range sub {
		result = append(result, v)
	}
	sort.Sort(sortByOpcode(result))
	return result
}

// direct opcode bytes
var opsByOpcode [][]OpSpec
var opsByName []map[string]OpSpec

func init() {
	opsByOpcode = make([][]OpSpec, LogicVersion+1)
	opsByName = make([]map[string]OpSpec, LogicVersion+1)

	for v := uint64(0); v <= EvalMaxVersion; v++ {
		opsByOpcode[v] = make([]OpSpec, 256)
		opsByName[v] = make(map[string]OpSpec, 256)

		// for compatibility reason treat zero (empty) version as version 1
		// higher version includes all opcodes from lower one
		for _, oi := range OpSpecs {
			if oi.Version <= v || v == 0 && oi.Version == 1 {
				opsByOpcode[v][oi.Opcode] = oi
				opsByName[v][oi.Name] = oi
			}
		}
	}
}
