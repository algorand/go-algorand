// Copyright (C) 2019 Algorand, Inc.
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
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

type stackValue struct {
	Uint  uint64
	Bytes []byte
}

func (sv *stackValue) argType() byte {
	if sv.Bytes != nil {
		return opBytes
	}
	return opUint
}

func (sv *stackValue) typeName() string {
	if sv.Bytes != nil {
		return "[]byte"
	}
	return "uint64"
}

func (sv *stackValue) String() string {
	if sv.Bytes != nil {
		return hex.EncodeToString(sv.Bytes)
	}
	return fmt.Sprintf("%d 0x%d", sv.Uint, sv.Uint)
}

// EvalParams contains data that comes into condition evaluation.
type EvalParams struct {
	// the transaction being evaluated
	Txn *transactions.SignedTxn

	Block *bookkeeping.Block

	Trace io.Writer
}

type evalContext struct {
	EvalParams

	stack   []stackValue
	program []byte // txn.Lsig.Logic ?
	pc      int
	nextpc  int
	err     error
	intc    []uint64
	bytec   [][]byte
}

type opFunc func(cx *evalContext)

const (
	opNone = iota
	opAny
	opUint
	opBytes
)

func argTypeName(argType byte) string {
	switch argType {
	case opNone:
		return "None"
	case opAny:
		return "*"
	case opUint:
		return "uint64"
	case opBytes:
		return "[]byte"
	}
	return "internal error"
}

type opSpec struct {
	opcode  byte
	mask    byte // allow for immediate value in opcode bits, mask the opcode part that is constant
	name    string
	op      opFunc // evaluate the op
	args    []byte // what gets popped from the stack
	returns byte   // what gets pushed to the stack
}

// Eval checks to see if a transaction passes logic
func Eval(logic []byte, params EvalParams) bool {
	var cx evalContext
	cx.EvalParams = params
	cx.stack = make([]stackValue, 0, 10)
	cx.program = logic
	for (cx.err == nil) && (cx.pc < len(cx.program)) {
		cx.step()
	}
	if cx.err != nil {
		if cx.Trace != nil {
			fmt.Fprintf(cx.Trace, "%3d %s\n", cx.pc, cx.err)
		}
		return false
	}
	if len(cx.stack) != 1 {
		if cx.Trace != nil {
			fmt.Fprintf(cx.Trace, "end stack:\n")
			for i, sv := range cx.stack {
				fmt.Fprintf(cx.Trace, "[%d] %s\n", i, sv.String())
			}
		}
		return false
	}
	return cx.stack[0].Bytes == nil && cx.stack[0].Uint != 0
}

// ops, some of which have a range of opcode for immediate value
//
// Any changes should be reflected in README.md which serves as the language spec.
var opSpecs = []opSpec{
	{0x00, 0xff, "err", opErr, nil, opNone},
	{0x01, 0xff, "sha256", opSHA256, []byte{opBytes}, opBytes},
	{0x02, 0xff, "keccak256", opKeccak256, []byte{opBytes}, opBytes},
	{0x03, 0xff, "sha512_256", opSHA512_256, []byte{opBytes}, opBytes},
	{0x08, 0xff, "+", opPlus, []byte{opUint, opUint}, opUint},
	{0x09, 0xff, "-", opMinus, []byte{opUint, opUint}, opUint},
	{0x0a, 0xff, "/", opDiv, []byte{opUint, opUint}, opUint},
	{0x0b, 0xff, "*", opMul, []byte{opUint, opUint}, opUint},
	{0x0c, 0xff, "<", opLt, []byte{opUint, opUint}, opUint},
	{0x0d, 0xff, ">", opGt, []byte{opUint, opUint}, opUint},
	{0x0e, 0xff, "<=", opLe, []byte{opUint, opUint}, opUint},
	{0x0f, 0xff, ">=", opGe, []byte{opUint, opUint}, opUint},
	{0x10, 0xff, "&&", opAnd, []byte{opUint, opUint}, opUint},
	{0x11, 0xff, "||", opOr, []byte{opUint, opUint}, opUint},
	{0x12, 0xff, "==", opEq, []byte{opAny, opAny}, opUint},
	{0x13, 0xff, "!=", opNeq, []byte{opAny, opAny}, opUint},
	{0x14, 0xff, "!", opNot, []byte{opUint}, opUint},
	{0x15, 0xff, "len", opLen, []byte{opBytes}, opUint},
	// TODO: signed
	{0x17, 0xff, "btoi", opBtoi, []byte{opBytes}, opUint},
	{0x18, 0xff, "%", opModulo, []byte{opUint, opUint}, opUint},
	{0x19, 0xff, "|", opBitOr, []byte{opUint, opUint}, opUint},
	{0x1a, 0xff, "&", opBitAnd, []byte{opUint, opUint}, opUint},
	{0x1b, 0xff, "^", opBitXor, []byte{opUint, opUint}, opUint},
	{0x1c, 0xff, "~", opBitNot, []byte{opUint}, opUint},

	{0x20, 0xff, "intcblock", opIntConstBlock, nil, opNone},
	{0x21, 0xff, "intc", opIntConstLoad, nil, opUint},
	{0x22, 0xff, "intc_0", opIntConst0, nil, opUint},
	{0x23, 0xff, "intc_1", opIntConst1, nil, opUint},
	{0x24, 0xff, "intc_2", opIntConst2, nil, opUint},
	{0x25, 0xff, "intc_3", opIntConst3, nil, opUint},
	{0x26, 0xff, "bytecblock", opByteConstBlock, nil, opNone},
	{0x27, 0xff, "bytec", opByteConstLoad, nil, opBytes},
	{0x28, 0xff, "bytec_0", opByteConst0, nil, opBytes},
	{0x29, 0xff, "bytec_1", opByteConst1, nil, opBytes},
	{0x2a, 0xff, "bytec_2", opByteConst2, nil, opBytes},
	{0x2b, 0xff, "bytec_3", opByteConst3, nil, opBytes},
	{0x2c, 0xff, "arg", opArg, nil, opBytes},
	{0x2d, 0xff, "arg_0", opArg0, nil, opBytes},
	{0x2e, 0xff, "arg_1", opArg1, nil, opBytes},
	{0x2f, 0xff, "arg_2", opArg2, nil, opBytes},
	{0x30, 0xff, "arg_3", opArg3, nil, opBytes},
	{0x31, 0xff, "txn", opTxn, nil, opAny},       // TODO: check output type by subfield retrieved in txn,global,account,txid
	{0x32, 0xff, "global", opGlobal, nil, opAny}, // TODO: check output type against specific field

	{0x40, 0xff, "bnz", opBnz, []byte{opUint}, opNone},
	{0x48, 0xff, "pop", opPop, []byte{opAny}, opNone},
	{0x49, 0xff, "dup", opDup, []byte{opAny}, opAny},
}

// direct opcode bytes
var opsByOpcode []opSpec

func init() {
	opsByOpcode = make([]opSpec, 256)
	for _, oi := range opSpecs {
		if oi.mask == 0xff {
			opsByOpcode[oi.opcode] = oi
		} else {
			if oi.opcode&oi.mask != oi.opcode {
				panic("bad opcode")
			}
			for i := 0; i < 256; i++ {
				opcode := byte(i)
				if opcode&oi.mask == oi.opcode {
					if opsByOpcode[opcode].mask != 0 {
						panic("colliding opcodes")
					}
					opsByOpcode[opcode] = oi
				}
			}
		}
	}
}

func opCompat(expected, got byte) bool {
	if expected == opAny {
		return true
	}
	return expected == got
}

// MaxStackDepth should move to consensus params
const MaxStackDepth = 1000

func (cx *evalContext) step() {
	opcode := cx.program[cx.pc]
	argsTypes := opsByOpcode[opcode].args
	if len(argsTypes) >= 0 {
		// check args for stack underflow and types
		if len(cx.stack) < len(argsTypes) {
			cx.err = fmt.Errorf("stack underflow in %s", opsByOpcode[opcode].name)
			return
		}
		first := len(cx.stack) - len(argsTypes)
		for i, argType := range argsTypes {
			if !opCompat(argType, cx.stack[first+i].argType()) {
				cx.err = fmt.Errorf("%s arg %d wanted %s but got %s", opsByOpcode[opcode].name, i, argTypeName(argType), cx.stack[first+i].typeName())
			}
		}
	}
	opsByOpcode[opcode].op(cx)
	if cx.Trace != nil {
		if len(cx.stack) == 0 {
			fmt.Fprintf(cx.Trace, "%3d %s => %s\n", cx.pc, opsByOpcode[opcode].name, "<empty stack>")
		} else {
			fmt.Fprintf(cx.Trace, "%3d %s => %s\n", cx.pc, opsByOpcode[opcode].name, cx.stack[len(cx.stack)-1].String())
		}
	}
	if cx.err != nil {
		return
	}
	if len(cx.stack) > MaxStackDepth {
		cx.err = errors.New("stack overflow")
		return
	}
	if cx.nextpc != 0 {
		cx.pc = cx.nextpc
		cx.nextpc = 0
	} else {
		cx.pc++
	}
}

func opErr(cx *evalContext) {
	cx.err = errors.New("error")
}

func opSHA256(cx *evalContext) {
	last := len(cx.stack) - 1
	hash := sha256.Sum256(cx.stack[last].Bytes)
	cx.stack[last].Bytes = hash[:]
}

// The Keccak256 variant of SHA-3 is implemented for compatibility with Ethereum
func opKeccak256(cx *evalContext) {
	last := len(cx.stack) - 1
	hasher := sha3.NewLegacyKeccak256()
	hash := hasher.Sum(cx.stack[last].Bytes)
	cx.stack[last].Bytes = hash[:]
}

// This is the hash commonly used in Algorand in crypto/util.go Hash()
//
// It is explicitly implemented here in terms of the specific hash for
// stability and portability in case the rest of Algorand ever moves
// to a different default hash. For stability of this language, at
// that time a new opcode should be made with the new hash.
func opSHA512_256(cx *evalContext) {
	last := len(cx.stack) - 1
	hash := sha512.Sum512_256(cx.stack[last].Bytes)
	cx.stack[last].Bytes = hash[:]
}

func opPlus(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint += cx.stack[last].Uint
	if cx.stack[prev].Uint < cx.stack[last].Uint {
		cx.err = errors.New("+ overflowed")
		return
	}
	cx.stack = cx.stack[:last]
}

func opMinus(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint > cx.stack[prev].Uint {
		cx.err = errors.New("- would result negative")
		return
	}
	cx.stack[prev].Uint -= cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opDiv(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint == 0 {
		cx.err = errors.New("/ 0")
		return
	}
	cx.stack[prev].Uint /= cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opModulo(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	if cx.stack[last].Uint == 0 {
		cx.err = errors.New("% 0")
		return
	}
	cx.stack[prev].Uint = cx.stack[prev].Uint % cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opMul(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	a := cx.stack[prev].Uint
	b := cx.stack[last].Uint
	v := a * b
	if v/a != b {
		cx.err = errors.New("* overflowed")
		return
	}
	cx.stack = cx.stack[:last]
}

func opLt(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := cx.stack[prev].Uint < cx.stack[last].Uint
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opGt(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := cx.stack[prev].Uint > cx.stack[last].Uint
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opLe(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := cx.stack[prev].Uint <= cx.stack[last].Uint
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opGe(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := cx.stack[prev].Uint >= cx.stack[last].Uint
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opAnd(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := (cx.stack[prev].Uint != 0) && (cx.stack[last].Uint != 0)
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opOr(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cond := (cx.stack[prev].Uint != 0) || (cx.stack[last].Uint != 0)
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opEq(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	ta := cx.stack[prev].argType()
	tb := cx.stack[last].argType()
	if ta != tb {
		cx.err = fmt.Errorf("cannot compare (%s == %s)", cx.stack[prev].typeName(), cx.stack[last].typeName())
		return
	}
	var cond bool
	if ta == opBytes {
		cond = bytes.Compare(cx.stack[prev].Bytes, cx.stack[last].Bytes) == 0
	} else {
		cond = cx.stack[prev].Uint == cx.stack[last].Uint
	}
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack[prev].Bytes = nil
	cx.stack = cx.stack[:last]
}

func opNeq(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	ta := cx.stack[prev].argType()
	tb := cx.stack[last].argType()
	if ta != tb {
		cx.err = fmt.Errorf("cannot compare (%s == %s)", cx.stack[prev].typeName(), cx.stack[last].typeName())
		return
	}
	var cond bool
	if ta == opBytes {
		cond = bytes.Compare(cx.stack[prev].Bytes, cx.stack[last].Bytes) != 0
	} else {
		cond = cx.stack[prev].Uint != cx.stack[last].Uint
	}
	if cond {
		cx.stack[prev].Uint = 1
	} else {
		cx.stack[prev].Uint = 0
	}
	cx.stack = cx.stack[:last]
}

func opNot(cx *evalContext) {
	last := len(cx.stack) - 1
	cond := cx.stack[last].Uint == 0
	if cond {
		cx.stack[last].Uint = 1
	} else {
		cx.stack[last].Uint = 0
	}
}

func opLen(cx *evalContext) {
	last := len(cx.stack) - 1
	cx.stack[last].Uint = uint64(len(cx.stack[last].Bytes))
	cx.stack[last].Bytes = nil
}

func opBtoi(cx *evalContext) {
	last := len(cx.stack) - 1
	ibytes := cx.stack[last].Bytes
	if len(ibytes) > 8 {
		cx.err = fmt.Errorf("btoi arg too long, got [%d]bytes", len(ibytes))
		return
	}
	value := uint64(0)
	for _, b := range ibytes {
		value = value << 8
		value = value | (uint64(b) & 0x0ff)
	}
	cx.stack[last].Uint = value
	cx.stack[last].Bytes = nil
}

func opBitOr(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint = cx.stack[prev].Uint | cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opBitAnd(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint = cx.stack[prev].Uint & cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opBitXor(cx *evalContext) {
	last := len(cx.stack) - 1
	prev := last - 1
	cx.stack[prev].Uint = cx.stack[prev].Uint ^ cx.stack[last].Uint
	cx.stack = cx.stack[:last]
}

func opBitNot(cx *evalContext) {
	last := len(cx.stack) - 1
	cx.stack[last].Uint = cx.stack[last].Uint ^ 0xffffffffffffffff
}

func opIntConstBlock(cx *evalContext) {
	cx.intc, cx.nextpc, cx.err = parseIntcblock(cx.program, cx.pc)
}

func opIntConstN(cx *evalContext, n uint) {
	if n >= uint(len(cx.intc)) {
		cx.err = fmt.Errorf("intc [%d] beyond %d constants", n, len(cx.intc))
		return
	}
	cx.stack = append(cx.stack, stackValue{Uint: cx.intc[n]})
}
func opIntConstLoad(cx *evalContext) {
	n := uint(cx.program[cx.pc+1])
	opIntConstN(cx, n)
	cx.nextpc = cx.pc + 2
}
func opIntConst0(cx *evalContext) {
	opIntConstN(cx, 0)
}
func opIntConst1(cx *evalContext) {
	opIntConstN(cx, 1)
}
func opIntConst2(cx *evalContext) {
	opIntConstN(cx, 2)
}
func opIntConst3(cx *evalContext) {
	opIntConstN(cx, 3)
}

func opByteConstBlock(cx *evalContext) {
	cx.bytec, cx.nextpc, cx.err = parseBytecBlock(cx.program, cx.pc)
}
func opByteConstN(cx *evalContext, n uint) {
	if n >= uint(len(cx.bytec)) {
		cx.err = fmt.Errorf("bytec [%d] beyond %d constants", n, len(cx.bytec))
		return
	}
	cx.stack = append(cx.stack, stackValue{Bytes: cx.bytec[n]})
}
func opByteConstLoad(cx *evalContext) {
	n := uint(cx.program[cx.pc+1])
	opByteConstN(cx, n)
	cx.nextpc = cx.pc + 2
}
func opByteConst0(cx *evalContext) {
	opByteConstN(cx, 0)
}
func opByteConst1(cx *evalContext) {
	opByteConstN(cx, 1)
}
func opByteConst2(cx *evalContext) {
	opByteConstN(cx, 2)
}
func opByteConst3(cx *evalContext) {
	opByteConstN(cx, 3)
}

func opArgN(cx *evalContext, n uint64) {
	if n >= uint64(len(cx.Txn.Lsig.Args)) {
		cx.err = fmt.Errorf("cannot load arg[%d] of %d", n, len(cx.Txn.Lsig.Args))
		return
	}
	cx.stack = append(cx.stack, stackValue{Bytes: cx.Txn.Lsig.Args[n]})
}
func opArg(cx *evalContext) {
	n := uint64(cx.program[cx.pc+1])
	opArgN(cx, n)
	cx.nextpc = cx.pc + 2
}
func opArg0(cx *evalContext) {
	opArgN(cx, 0)
}
func opArg1(cx *evalContext) {
	opArgN(cx, 1)
}
func opArg2(cx *evalContext) {
	opArgN(cx, 2)
}
func opArg3(cx *evalContext) {
	opArgN(cx, 3)
}

func opBnz(cx *evalContext) {
	last := len(cx.stack) - 1
	cx.nextpc = cx.pc + 2
	isNonZero := cx.stack[last].Uint != 0
	cx.stack = cx.stack[:last] // pop
	if isNonZero {
		cx.nextpc += int(cx.program[cx.pc+1])
	}
}

func opPop(cx *evalContext) {
	last := len(cx.stack) - 1
	cx.stack = cx.stack[:last]
}

func opDup(cx *evalContext) {
	last := len(cx.stack) - 1
	sv := cx.stack[last]
	cx.stack = append(cx.stack, sv)
}

func (cx *evalContext) txnFieldToStack(txn *transactions.SignedTxn, field uint64) (sv stackValue, err error) {
	err = nil
	switch field {
	case 0:
		sv.Bytes = txn.Txn.Sender[:]
	case 1:
		sv.Uint = txn.Txn.Fee.Raw
	case 2:
		sv.Uint = uint64(txn.Txn.FirstValid)
	case 3:
		sv.Uint = uint64(txn.Txn.LastValid)
	case 4:
		sv.Bytes = txn.Txn.Note
	case 5:
		sv.Bytes = txn.Txn.Receiver[:]
	case 6:
		sv.Uint = txn.Txn.Amount.Raw
	case 7:
		sv.Bytes = txn.Txn.CloseRemainderTo[:]
	case 8:
		sv.Bytes = txn.Txn.VotePK[:]
	case 9:
		sv.Bytes = txn.Txn.SelectionPK[:]
	case 10:
		sv.Uint = uint64(txn.Txn.VoteFirst)
	case 11:
		sv.Uint = uint64(txn.Txn.VoteLast)
	case 12:
		sv.Uint = txn.Txn.VoteKeyDilution
	default:
		err = fmt.Errorf("invalid txn field %d", field)
	}
	return
}

func opTxn(cx *evalContext) {
	value := uint64(cx.program[cx.pc+1])
	sv, err := cx.txnFieldToStack(cx.Txn, value)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = cx.pc + 2
}

func opGlobal(cx *evalContext) {
	gindex := uint64(cx.program[cx.pc+1])
	var sv stackValue
	switch gindex {
	case 0:
		if cx.Block != nil {
			sv.Uint = uint64(cx.Block.Round())
		}
	case 1:
		sv.Uint = config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee
	case 2:
		sv.Uint = config.Consensus[protocol.ConsensusCurrentVersion].MinBalance
	case 3:
		sv.Uint = config.Consensus[protocol.ConsensusCurrentVersion].MaxTxnLife
	case 4:
		if cx.Block != nil {
			sv.Uint = uint64(cx.Block.BlockHeader.TimeStamp)
		}
	default:
		cx.err = fmt.Errorf("invalid global[%d]", gindex)
		return
	}
	cx.stack = append(cx.stack, sv)
	cx.nextpc = cx.pc + 2
}
