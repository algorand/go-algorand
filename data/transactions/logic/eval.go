package logic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
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

type EvalParams struct {
	// the transaction being evaluated
	Txn *transactions.SignedTxn

	// round for which eval is happenning
	Round basics.Round

	Trace io.Writer
}

type evalContext struct {
	EvalParams

	stack   []stackValue
	program []byte // txn.Lsig.Logic ?
	pc      int
	err     error
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
	mask    byte
	name    string
	op      opFunc
	args    []byte
	returns byte
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
		return false
	}
	if len(cx.stack) != 1 {
		return false
	}
	return cx.stack[0].Bytes == nil && cx.stack[0].Uint != 0
}

// ops, some of which have a range of opcode for immediate value
var opSpecs = []opSpec{
	{0x00, 0xff, "err", opErr, nil, opNone},
	{0x01, 0xff, "sha256", opSHA256, []byte{opBytes}, opBytes},
	{0x02, 0xff, "keccak256", opKeccak256, []byte{opBytes}, opBytes},
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

	{0x20, 0xf8, "int", opInt, nil, opUint},
	{0x28, 0xf8, "byte", opByte, nil, opBytes},
	{0x30, 0xf8, "arg", opArg, nil, opBytes},
	{0x38, 0xf8, "txn", opTxn, nil, opAny}, // TODO: check output type by subfield retrieved in txn,global,account,txid
	{0x40, 0xf8, "global", opGlobal, nil, opAny},
	{0x48, 0xf8, "account", opAccount, nil, opAny},
	{0x50, 0xf8, "txid", opTxid, nil, opAny},
}

// direct opcode bytes
var ops []opSpec

func init() {
	ops = make([]opSpec, 256)
	for _, oi := range opSpecs {
		if oi.mask == 0xff {
			ops[oi.opcode] = oi
		} else {
			if oi.opcode&oi.mask != oi.opcode {
				panic("bad opcode")
			}
			for i := 0; i < 256; i++ {
				opcode := byte(i)
				if opcode&oi.mask == oi.opcode {
					if ops[opcode].mask != 0 {
						panic("colliding opcodes")
					}
					ops[opcode] = oi
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

func (cx *evalContext) step() {
	opcode := cx.program[cx.pc]
	argsTypes := ops[opcode].args
	if len(argsTypes) >= 0 {
		// check args for stack underflow and types
		if len(cx.stack) < len(argsTypes) {
			cx.err = fmt.Errorf("stack underflow in %s", ops[opcode].name)
			return
		}
		first := len(cx.stack) - len(argsTypes)
		for i, argType := range argsTypes {
			if !opCompat(argType, cx.stack[first+i].argType()) {
				cx.err = fmt.Errorf("%s arg %d wanted %s but got %s", ops[opcode].name, i, argTypeName(argType), cx.stack[first+i].typeName())
			}
		}
	}
	ops[opcode].op(cx)
	if cx.Trace != nil {
		fmt.Fprintf(cx.Trace, "%3d %s => %s\n", cx.pc, ops[opcode].name, cx.stack[len(cx.stack)-1].String())
	}
	if cx.err == nil {
		cx.pc++
	}
}

func (cx *evalContext) lookup(addr basics.Address) (data basics.AccountData, err error) {
	err = errors.New("TODO WRITEME")
	return
}

func (cx *evalContext) getTransaction(txid []byte) (txn *transactions.SignedTxn, err error) {
	err = errors.New("TODO WRITEME")
	return
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
	value := uint64(0)
	for _, b := range ibytes {
		value = value << 8
		value = value | (uint64(b) & 0x0ff)
	}
	cx.stack[last].Uint = value
	cx.stack[last].Bytes = nil
}

func opInt(cx *evalContext) {
	dataLen := int(cx.program[cx.pc] & 0x07)
	value := uint64(0)
	for i := 0; i < dataLen; i++ {
		value = value << 8
		value = value | (uint64(cx.program[cx.pc+1+i]) & 0x0ff)
	}
	cx.stack = append(cx.stack, stackValue{Uint: value})
	cx.pc += dataLen
}

func opByte(cx *evalContext) {
	dataLen := int(cx.program[cx.pc] & 0x07)
	value := uint64(0)
	for i := 0; i < dataLen; i++ {
		value = value << 8
		value = value | (uint64(cx.program[cx.pc+1+i]) & 0x0ff)
	}
	start := cx.pc + 1 + dataLen
	end := uint64(start) + value
	cx.stack = append(cx.stack, stackValue{Bytes: cx.program[start:end]})
	cx.pc = int(end - 1)
}

func opArg(cx *evalContext) {
	dataLen := int(cx.program[cx.pc] & 0x07)
	value := uint64(0)
	for i := 0; i < dataLen; i++ {
		value = value << 8
		value = value | (uint64(cx.program[cx.pc+1+i]) & 0x0ff)
	}
	if value >= uint64(len(cx.Txn.Lsig.Args)) {
		cx.err = fmt.Errorf("cannot load arg[%d] of %d", value, len(cx.Txn.Lsig.Args))
		return
	}
	cx.stack = append(cx.stack, stackValue{Bytes: cx.Txn.Lsig.Args[value]})
	cx.pc += dataLen
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
		err = fmt.Errorf("invalid arg field %d", field)
	}
	return
}

func opTxn(cx *evalContext) {
	dataLen := int(cx.program[cx.pc] & 0x07)
	value := uint64(0)
	for i := 0; i < dataLen; i++ {
		value = value << 8
		value = value | (uint64(cx.program[cx.pc+1+i]) & 0x0ff)
	}
	sv, err := cx.txnFieldToStack(cx.Txn, value)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack = append(cx.stack, sv)
	cx.pc += dataLen
}

func opGlobal(cx *evalContext) {
	dataLen := int(cx.program[cx.pc] & 0x07)
	value := uint64(0)
	for i := 0; i < dataLen; i++ {
		value = value << 8
		value = value | (uint64(cx.program[cx.pc+1+i]) & 0x0ff)
	}
	var sv stackValue
	switch value {
	case 0:
		sv.Uint = uint64(cx.Round)
	case 1:
		sv.Uint = config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee
	case 2:
		sv.Uint = config.Consensus[protocol.ConsensusCurrentVersion].MinBalance
	case 3:
		sv.Uint = config.Consensus[protocol.ConsensusCurrentVersion].MaxTxnLife
	default:
		cx.err = fmt.Errorf("invalid global[%d]", value)
		return
	}
	cx.stack = append(cx.stack, sv)
	cx.pc += dataLen
}

func opAccount(cx *evalContext) {
	dataLen := int(cx.program[cx.pc] & 0x07)
	value := uint64(0)
	for i := 0; i < dataLen; i++ {
		value = value << 8
		value = value | (uint64(cx.program[cx.pc+1+i]) & 0x0ff)
	}
	// pop account addr
	last := len(cx.stack) - 1
	addrb := cx.stack[last].Bytes
	var addr basics.Address
	if len(addrb) == len(addr) {
		copy(addr[:], addrb)
	} else {
		cx.err = errors.New("address argument wrong length")
		return
	}
	data, err := cx.lookup(addr)
	if err != nil {
		cx.err = err
		return
	}
	var sv stackValue
	switch value {
	case 0:
		sv.Uint = data.MicroAlgos.Raw
	default:
		cx.err = fmt.Errorf("invalid account field %d", value)
		return
	}
	cx.stack[last] = sv
	cx.pc += dataLen
}

func opTxid(cx *evalContext) {
	dataLen := int(cx.program[cx.pc] & 0x07)
	value := uint64(0)
	for i := 0; i < dataLen; i++ {
		value = value << 8
		value = value | (uint64(cx.program[cx.pc+1+i]) & 0x0ff)
	}
	// pop txid addr
	last := len(cx.stack) - 1
	txid := cx.stack[last].Bytes
	txn, err := cx.getTransaction(txid)
	if err != nil {
		cx.err = err
		return
	}
	sv, err := cx.txnFieldToStack(txn, value)
	if err != nil {
		cx.err = err
		return
	}
	cx.stack[last] = sv
	cx.pc += dataLen
}
