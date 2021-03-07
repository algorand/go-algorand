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
	"bufio"
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/data/basics"
)

// Writer is what we want here. Satisfied by bufio.Buffer
type Writer interface {
	Write([]byte) (int, error)
	WriteByte(c byte) error
}

type labelReference struct {
	sourceLine int

	// position of the opcode start that refers to the label
	position int

	label string
}

// OpStream is destination for program and scratch space
type OpStream struct {
	Version  uint64
	Trace    io.Writer
	Warnings []error      // informational warnings, shouldn't stop assembly
	Errors   []*lineError // errors that should prevent final assembly
	Program  []byte       // Final program bytes. Will stay nil if any errors

	// Running bytes as they are assembled. jumps must be resolved
	// and cblocks added before these bytes become a legal program.
	pending bytes.Buffer

	intc        []uint64 // observed ints in code. We'll put them into a intcblock
	noIntcBlock bool     // prevent prepending intcblock because asm has one

	bytec        [][]byte // observed bytes in code. We'll put them into a bytecblock
	noBytecBlock bool     // prevent prepending bytecblock because asm has one

	// Keep a stack of the types of what we would push and pop to typecheck a program
	typeStack []StackType

	// current sourceLine during assembly
	sourceLine int

	// map label string to position within pending buffer
	labels map[string]int

	// track references in order to patch in jump offsets
	labelReferences []labelReference

	// map opcode offsets to source line
	OffsetToLine map[int]int

	// indicates whether the pragra version was speficied in the source. It allows us to
	// ensure the pragma version appears only once, as well as allow us to diffrenciate
	// between default version and requested version.
	pragraVersionFound bool
}

// GetVersion returns the LogicSigVersion we're building to
func (ops *OpStream) GetVersion() uint64 {
	if ops.Version == 0 {
		ops.Version = AssemblerDefaultVersion
	}
	return ops.Version
}

// createLabel inserts a label reference to point to the next
// instruction, reporting an error for a duplicate.
func (ops *OpStream) createLabel(label string) {
	if ops.labels == nil {
		ops.labels = make(map[string]int)
	}
	if _, ok := ops.labels[label]; ok {
		ops.errorf("duplicate label %s", label)
	}
	ops.labels[label] = ops.pending.Len()
}

// RecordSourceLine adds an entry to pc to line mapping
func (ops *OpStream) RecordSourceLine() {
	if ops.OffsetToLine == nil {
		ops.OffsetToLine = make(map[int]int)
	}
	ops.OffsetToLine[ops.pending.Len()] = ops.sourceLine - 1
}

// ReferToLabel records an opcode label refence to resolve later
func (ops *OpStream) ReferToLabel(pc int, label string) {
	ops.labelReferences = append(ops.labelReferences, labelReference{ops.sourceLine, pc, label})
}

func (ops *OpStream) tpush(argType StackType) {
	ops.typeStack = append(ops.typeStack, argType)
}

func (ops *OpStream) tpusha(argType []StackType) {
	ops.typeStack = append(ops.typeStack, argType...)
}

func (ops *OpStream) tpop() (argType StackType) {
	if len(ops.typeStack) == 0 {
		argType = StackNone
		return
	}
	last := len(ops.typeStack) - 1
	argType = ops.typeStack[last]
	ops.typeStack = ops.typeStack[:last]
	return
}

// Intc writes opcodes for loading a uint64 constant onto the stack.
func (ops *OpStream) Intc(constIndex uint) {
	switch constIndex {
	case 0:
		ops.pending.WriteByte(0x22) // intc_0
	case 1:
		ops.pending.WriteByte(0x23) // intc_1
	case 2:
		ops.pending.WriteByte(0x24) // intc_2
	case 3:
		ops.pending.WriteByte(0x25) // intc_3
	default:
		if constIndex > 0xff {
			ops.error("cannot have more than 256 int constants")
		}
		ops.pending.WriteByte(0x21) // intc
		ops.pending.WriteByte(uint8(constIndex))
	}
	if constIndex >= uint(len(ops.intc)) {
		ops.errorf("intc %d is not defined", constIndex)
	} else {
		ops.trace("intc %d %d", constIndex, ops.intc[constIndex])
	}
}

// Uint writes opcodes for loading a uint literal
func (ops *OpStream) Uint(val uint64) {
	found := false
	var constIndex uint
	for i, cv := range ops.intc {
		if cv == val {
			constIndex = uint(i)
			found = true
			break
		}
	}
	if !found {
		constIndex = uint(len(ops.intc))
		ops.intc = append(ops.intc, val)
	}
	ops.Intc(constIndex)
}

// Bytec writes opcodes for loading a []byte constant onto the stack.
func (ops *OpStream) Bytec(constIndex uint) {
	switch constIndex {
	case 0:
		ops.pending.WriteByte(0x28) // bytec_0
	case 1:
		ops.pending.WriteByte(0x29) // bytec_1
	case 2:
		ops.pending.WriteByte(0x2a) // bytec_2
	case 3:
		ops.pending.WriteByte(0x2b) // bytec_3
	default:
		if constIndex > 0xff {
			ops.error("cannot have more than 256 byte constants")
		}
		ops.pending.WriteByte(0x27) // bytec
		ops.pending.WriteByte(uint8(constIndex))
	}
	if constIndex >= uint(len(ops.bytec)) {
		ops.errorf("bytec %d is not defined", constIndex)
	} else {
		ops.trace("bytec %d %s", constIndex, hex.EncodeToString(ops.bytec[constIndex]))
	}
}

// ByteLiteral writes opcodes and data for loading a []byte literal
// Values are accumulated so that they can be put into a bytecblock
func (ops *OpStream) ByteLiteral(val []byte) {
	found := false
	var constIndex uint
	for i, cv := range ops.bytec {
		if bytes.Compare(cv, val) == 0 {
			found = true
			constIndex = uint(i)
			break
		}
	}
	if !found {
		constIndex = uint(len(ops.bytec))
		ops.bytec = append(ops.bytec, val)
	}
	ops.Bytec(constIndex)
}

// Arg writes opcodes for loading from Lsig.Args
func (ops *OpStream) Arg(val uint64) error {
	switch val {
	case 0:
		ops.pending.WriteByte(0x2d) // arg_0
	case 1:
		ops.pending.WriteByte(0x2e) // arg_1
	case 2:
		ops.pending.WriteByte(0x2f) // arg_2
	case 3:
		ops.pending.WriteByte(0x30) // arg_3
	default:
		if val > 0xff {
			return ops.error("cannot have more than 256 args")
		}
		ops.pending.WriteByte(0x2c)
		ops.pending.WriteByte(uint8(val))
	}
	return nil
}

// Txn writes opcodes for loading a field from the current transaction
func (ops *OpStream) Txn(val uint64) {
	if val >= uint64(len(TxnFieldNames)) {
		ops.errorf("invalid txn field: %d", val)
	}
	ops.pending.WriteByte(0x31)
	ops.pending.WriteByte(uint8(val))
	ops.tpush(TxnFieldTypes[val])
}

// Txna writes opcodes for loading array field from the current transaction
func (ops *OpStream) Txna(fieldNum uint64, arrayFieldIdx uint64) {
	if fieldNum >= uint64(len(TxnFieldNames)) {
		ops.errorf("invalid txn field: %d", fieldNum)
		fieldNum = 0 // avoid further error in tpush as we forge ahead
	}
	if arrayFieldIdx > 255 {
		ops.errorf("txna array index beyond 255: %d", arrayFieldIdx)
	}
	ops.pending.WriteByte(0x36)
	ops.pending.WriteByte(uint8(fieldNum))
	ops.pending.WriteByte(uint8(arrayFieldIdx))
	ops.tpush(TxnFieldTypes[fieldNum])
}

// Gtxn writes opcodes for loading a field from the current transaction
func (ops *OpStream) Gtxn(gid, val uint64) {
	if val >= uint64(len(TxnFieldNames)) {
		ops.errorf("invalid gtxn field: %d", val)
		val = 0 // avoid further error in tpush as we forge ahead
	}
	if gid > 255 {
		ops.errorf("gtxn transaction index beyond 255: %d", gid)
	}
	ops.pending.WriteByte(0x33)
	ops.pending.WriteByte(uint8(gid))
	ops.pending.WriteByte(uint8(val))
	ops.tpush(TxnFieldTypes[val])
}

// Gtxna writes opcodes for loading an array field from the current transaction
func (ops *OpStream) Gtxna(gid, fieldNum uint64, arrayFieldIdx uint64) {
	if fieldNum >= uint64(len(TxnFieldNames)) {
		ops.errorf("invalid txn field: %d", fieldNum)
		fieldNum = 0 // avoid further error in tpush as we forge ahead
	}
	if gid > 255 {
		ops.errorf("gtxna group index beyond 255: %d", gid)
	}
	if arrayFieldIdx > 255 {
		ops.errorf("gtxna array index beyond 255: %d", arrayFieldIdx)
	}
	ops.pending.WriteByte(0x37)
	ops.pending.WriteByte(uint8(gid))
	ops.pending.WriteByte(uint8(fieldNum))
	ops.pending.WriteByte(uint8(arrayFieldIdx))
	ops.tpush(TxnFieldTypes[fieldNum])
}

// Gtxns writes opcodes for loading a field from the current transaction
func (ops *OpStream) Gtxns(fieldNum uint64) {
	if fieldNum >= uint64(len(TxnFieldNames)) {
		ops.errorf("invalid gtxns field: %d", fieldNum)
		fieldNum = 0 // avoid further error in tpush as we forge ahead
	}
	ops.pending.WriteByte(0x38)
	ops.pending.WriteByte(uint8(fieldNum))
	ops.tpush(TxnFieldTypes[fieldNum])
}

// Gtxnsa writes opcodes for loading an array field from the current transaction
func (ops *OpStream) Gtxnsa(fieldNum uint64, arrayFieldIdx uint64) {
	if fieldNum >= uint64(len(TxnFieldNames)) {
		ops.errorf("invalid gtxnsa field: %d", fieldNum)
		fieldNum = 0 // avoid further error in tpush as we forge ahead
	}
	if arrayFieldIdx > 255 {
		ops.errorf("gtxnsa array index beyond 255: %d", arrayFieldIdx)
	}
	ops.pending.WriteByte(0x39)
	ops.pending.WriteByte(uint8(fieldNum))
	ops.pending.WriteByte(uint8(arrayFieldIdx))
	ops.tpush(TxnFieldTypes[fieldNum])
}

// Global writes opcodes for loading an evaluator-global field
func (ops *OpStream) Global(val GlobalField) {
	ops.pending.WriteByte(0x32)
	ops.pending.WriteByte(uint8(val))
	ops.trace("%s (%s)", GlobalFieldNames[val], GlobalFieldTypes[val].String())
	ops.tpush(GlobalFieldTypes[val])
}

// AssetHolding writes opcodes for accessing data from AssetHolding
func (ops *OpStream) AssetHolding(val uint64) {
	if val >= uint64(len(AssetHoldingFieldNames)) {
		ops.errorf("invalid asset holding field: %d", val)
		val = 0 // avoid further error in tpush as we forge ahead
	}
	ops.pending.WriteByte(OpsByName[ops.Version]["asset_holding_get"].Opcode)
	ops.pending.WriteByte(uint8(val))
	ops.tpush(AssetHoldingFieldTypes[val])
	ops.tpush(StackUint64)
}

// AssetParams writes opcodes for accessing data from AssetParams
func (ops *OpStream) AssetParams(val uint64) {
	if val >= uint64(len(AssetParamsFieldNames)) {
		ops.errorf("invalid asset params field: %d", val)
		val = 0 // avoid further error in tpush as we forge ahead
	}
	ops.pending.WriteByte(OpsByName[ops.Version]["asset_params_get"].Opcode)
	ops.pending.WriteByte(uint8(val))
	ops.tpush(AssetParamsFieldTypes[val])
	ops.tpush(StackUint64)
}

func assembleInt(ops *OpStream, spec *OpSpec, args []string) error {
	ops.checkArgs(*spec)
	if len(args) != 1 {
		return ops.error("int needs one argument")
	}
	// check friendly TypeEnum constants
	te, isTypeEnum := txnTypeConstToUint64[args[0]]
	if isTypeEnum {
		ops.Uint(te)
		return nil
	}
	// check raw transaction type strings
	tt, isTypeStr := txnTypeIndexes[args[0]]
	if isTypeStr {
		ops.Uint(tt)
		return nil
	}
	// check OnCompetion constants
	oc, isOCStr := onCompletionConstToUint64[args[0]]
	if isOCStr {
		ops.Uint(oc)
		return nil
	}
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	ops.Uint(val)
	return nil
}

// Explicit invocation of const lookup and push
func assembleIntC(ops *OpStream, spec *OpSpec, args []string) error {
	ops.checkArgs(*spec)
	if len(args) != 1 {
		return ops.error("intc operation needs one argument")
	}
	constIndex, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	ops.Intc(uint(constIndex))
	return nil
}
func assembleByteC(ops *OpStream, spec *OpSpec, args []string) error {
	ops.checkArgs(*spec)
	if len(args) != 1 {
		ops.error("bytec operation needs one argument")
	}
	constIndex, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		ops.error(err)
	}
	ops.Bytec(uint(constIndex))
	return nil
}

func asmPushInt(ops *OpStream, spec *OpSpec, args []string) error {
	ops.checkArgs(*spec)
	if len(args) != 1 {
		ops.errorf("%s needs one argument", spec.Name)
	}
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		ops.error(err)
	}
	ops.pending.WriteByte(spec.Opcode)
	var scratch [binary.MaxVarintLen64]byte
	vlen := binary.PutUvarint(scratch[:], val)
	ops.pending.Write(scratch[:vlen])
	return nil
}
func asmPushBytes(ops *OpStream, spec *OpSpec, args []string) error {
	ops.checkArgs(*spec)
	if len(args) != 1 {
		ops.errorf("%s needs one argument", spec.Name)
	}
	val, _, err := parseBinaryArgs(args)
	if err != nil {
		return ops.error(err)
	}
	ops.pending.WriteByte(spec.Opcode)
	var scratch [binary.MaxVarintLen64]byte
	vlen := binary.PutUvarint(scratch[:], uint64(len(val)))
	ops.pending.Write(scratch[:vlen])
	ops.pending.Write(val)
	return nil
}

func base32DecdodeAnyPadding(x string) (val []byte, err error) {
	val, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(x)
	if err != nil {
		// try again with standard padding
		var e2 error
		val, e2 = base32.StdEncoding.DecodeString(x)
		if e2 == nil {
			err = nil
		}
	}
	return
}

func parseBinaryArgs(args []string) (val []byte, consumed int, err error) {
	arg := args[0]
	if strings.HasPrefix(arg, "base32(") || strings.HasPrefix(arg, "b32(") {
		open := strings.IndexRune(arg, '(')
		close := strings.IndexRune(arg, ')')
		if close == -1 {
			err = errors.New("byte base32 arg lacks close paren")
			return
		}
		val, err = base32DecdodeAnyPadding(arg[open+1 : close])
		if err != nil {
			return
		}
		consumed = 1
	} else if strings.HasPrefix(arg, "base64(") || strings.HasPrefix(arg, "b64(") {
		open := strings.IndexRune(arg, '(')
		close := strings.IndexRune(arg, ')')
		if close == -1 {
			err = errors.New("byte base64 arg lacks close paren")
			return
		}
		val, err = base64.StdEncoding.DecodeString(arg[open+1 : close])
		if err != nil {
			return
		}
		consumed = 1
	} else if strings.HasPrefix(arg, "0x") {
		val, err = hex.DecodeString(arg[2:])
		if err != nil {
			return
		}
		consumed = 1
	} else if arg == "base32" || arg == "b32" {
		if len(args) < 2 {
			err = fmt.Errorf("need literal after 'byte %s'", arg)
			return
		}
		val, err = base32DecdodeAnyPadding(args[1])
		if err != nil {
			return
		}
		consumed = 2
	} else if arg == "base64" || arg == "b64" {
		if len(args) < 2 {
			err = fmt.Errorf("need literal after 'byte %s'", arg)
			return
		}
		val, err = base64.StdEncoding.DecodeString(args[1])
		if err != nil {
			return
		}
		consumed = 2
	} else if len(arg) > 1 && arg[0] == '"' && arg[len(arg)-1] == '"' {
		val, err = parseStringLiteral(arg)
		consumed = 1
	} else {
		err = fmt.Errorf("byte arg did not parse: %v", arg)
		return
	}
	return
}

func parseStringLiteral(input string) (result []byte, err error) {
	start := 0
	end := len(input) - 1
	if input[start] != '"' || input[end] != '"' {
		return nil, fmt.Errorf("no quotes")
	}
	start++

	escapeSeq := false
	hexSeq := false
	result = make([]byte, 0, end-start+1)

	// skip first and last quotes
	pos := start
	for pos < end {
		char := input[pos]
		if char == '\\' && !escapeSeq {
			if hexSeq {
				return nil, fmt.Errorf("escape seq inside hex number")
			}
			escapeSeq = true
			pos++
			continue
		}
		if escapeSeq {
			escapeSeq = false
			switch char {
			case 'n':
				char = '\n'
			case 'r':
				char = '\r'
			case 't':
				char = '\t'
			case '\\':
				char = '\\'
			case '"':
				char = '"'
			case 'x':
				hexSeq = true
				pos++
				continue
			default:
				return nil, fmt.Errorf("invalid escape seq \\%c", char)
			}
		}
		if hexSeq {
			hexSeq = false
			if pos >= len(input)-2 { // count a closing quote
				return nil, fmt.Errorf("non-terminated hex seq")
			}
			num, err := strconv.ParseUint(input[pos:pos+2], 16, 8)
			if err != nil {
				return nil, err
			}
			char = uint8(num)
			pos++
		}

		result = append(result, char)
		pos++
	}
	if escapeSeq || hexSeq {
		return nil, fmt.Errorf("non-terminated escape seq")
	}

	return
}

// byte {base64,b64,base32,b32}(...)
// byte {base64,b64,base32,b32} ...
// byte 0x....
// byte "this is a string\n"
func assembleByte(ops *OpStream, spec *OpSpec, args []string) error {
	ops.checkArgs(*spec)
	if len(args) == 0 {
		return ops.error("byte operation needs byte literal argument")
	}
	val, _, err := parseBinaryArgs(args)
	if err != nil {
		return ops.error(err)
	}
	ops.ByteLiteral(val)
	return nil
}

func assembleIntCBlock(ops *OpStream, spec *OpSpec, args []string) error {
	ops.pending.WriteByte(0x20) // intcblock
	var scratch [binary.MaxVarintLen64]byte
	l := binary.PutUvarint(scratch[:], uint64(len(args)))
	ops.pending.Write(scratch[:l])
	ops.intc = make([]uint64, len(args))
	for i, xs := range args {
		cu, err := strconv.ParseUint(xs, 0, 64)
		if err != nil {
			ops.error(err)
		}
		l = binary.PutUvarint(scratch[:], cu)
		ops.pending.Write(scratch[:l])
		ops.intc[i] = cu
	}
	ops.noIntcBlock = true
	return nil
}

func assembleByteCBlock(ops *OpStream, spec *OpSpec, args []string) error {
	ops.pending.WriteByte(0x26) // bytecblock
	bvals := make([][]byte, 0, len(args))
	rest := args
	for len(rest) > 0 {
		val, consumed, err := parseBinaryArgs(rest)
		if err != nil {
			// Would be nice to keep going, as in
			// intcblock, but parseBinaryArgs would have
			// to return a useful consumed value even in
			// the face of errors.  Hard.
			ops.error(err)
			return nil
		}
		bvals = append(bvals, val)
		rest = rest[consumed:]
	}
	var scratch [binary.MaxVarintLen64]byte
	l := binary.PutUvarint(scratch[:], uint64(len(bvals)))
	ops.pending.Write(scratch[:l])
	for _, bv := range bvals {
		l := binary.PutUvarint(scratch[:], uint64(len(bv)))
		ops.pending.Write(scratch[:l])
		ops.pending.Write(bv)
	}
	ops.bytec = bvals
	ops.noBytecBlock = true
	return nil
}

// addr A1EU...
// parses base32-with-checksum account address strings into a byte literal
func assembleAddr(ops *OpStream, spec *OpSpec, args []string) error {
	ops.checkArgs(*spec)
	if len(args) != 1 {
		return ops.error("addr operation needs one argument")
	}
	addr, err := basics.UnmarshalChecksumAddress(args[0])
	if err != nil {
		return ops.error(err)
	}
	ops.ByteLiteral(addr[:])
	return nil
}

func assembleArg(ops *OpStream, spec *OpSpec, args []string) error {
	ops.checkArgs(*spec)
	if len(args) != 1 {
		return ops.error("arg operation needs one argument")
	}
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	ops.Arg(val)
	return nil
}

func assembleBranch(ops *OpStream, spec *OpSpec, args []string) error {
	ops.checkArgs(*spec)
	if len(args) != 1 {
		return ops.error("branch operation needs label argument")
	}

	ops.ReferToLabel(ops.pending.Len(), args[0])
	ops.pending.WriteByte(spec.Opcode)
	// zero bytes will get replaced with actual offset in resolveLabels()
	ops.pending.WriteByte(0)
	ops.pending.WriteByte(0)
	return nil
}

func assembleSubstring(ops *OpStream, spec *OpSpec, args []string) error {
	asmDefault(ops, spec, args)
	// Having run asmDefault, only need to check extra constraints.
	start, _ := strconv.ParseUint(args[0], 0, 64)
	end, _ := strconv.ParseUint(args[1], 0, 64)
	if end < start {
		return ops.error("substring end is before start")
	}
	return nil
}

func assembleTxn(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.error("txn expects one argument")
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("txn unknown field: %v", args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if ok {
		return ops.errorf("found array field %v in txn op", args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("field %s available in version %d. Missed #pragma version?", args[0], fs.version)
	}
	val := fs.field
	ops.Txn(uint64(val))
	return nil
}

// assembleTxn2 delegates to assembleTxn or assembleTxna depending on number of operands
func assembleTxn2(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 1 {
		return assembleTxn(ops, spec, args)
	}
	if len(args) == 2 {
		return assembleTxna(ops, spec, args)
	}
	return ops.error("txn expects one or two arguments")
}

func assembleTxna(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 2 {
		return ops.error("txna expects two arguments")
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("txna unknown field: %v", args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if !ok {
		return ops.errorf("txna unknown field: %v", args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("txna %s available in version %d. Missed #pragma version?", args[0], fs.version)
	}
	arrayFieldIdx, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	fieldNum := fs.field
	ops.Txna(uint64(fieldNum), uint64(arrayFieldIdx))
	return nil
}

func assembleGtxn(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 2 {
		return ops.error("gtxn expects two arguments")
	}
	gtid, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	fs, ok := txnFieldSpecByName[args[1]]
	if !ok {
		return ops.errorf("gtxn unknown field: %v", args[1])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if ok {
		return ops.errorf("found array field %v in gtxn op", args[1])
	}
	if fs.version > ops.Version {
		return ops.errorf("field %s available in version %d. Missed #pragma version?", args[1], fs.version)
	}
	val := fs.field
	ops.Gtxn(gtid, uint64(val))
	return nil
}

func assembleGtxn2(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 2 {
		return assembleGtxn(ops, spec, args)
	}
	if len(args) == 3 {
		return assembleGtxna(ops, spec, args)
	}
	return ops.error("gtxn expects two or three arguments")
}

func assembleGtxna(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 3 {
		return ops.error("gtxna expects three arguments")
	}
	gtid, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	fs, ok := txnFieldSpecByName[args[1]]
	if !ok {
		return ops.errorf("gtxna unknown field: %v", args[1])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if !ok {
		return ops.errorf("gtxna unknown field: %v", args[1])
	}
	if fs.version > ops.Version {
		return ops.errorf("gtxna %s available in version %d. Missed #pragma version?", args[1], fs.version)
	}
	arrayFieldIdx, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	fieldNum := fs.field
	ops.Gtxna(gtid, uint64(fieldNum), uint64(arrayFieldIdx))
	return nil
}

func assembleGtxns(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 2 {
		return assembleGtxnsa(ops, spec, args)
	}
	if len(args) != 1 {
		return ops.error("gtxns expects one or two immediate arguments")
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("gtxns unknown field: %v", args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if ok {
		return ops.errorf("found array field %v in gtxns op", args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("field %s available in version %d. Missed #pragma version?", args[0], fs.version)
	}
	val := fs.field
	ops.Gtxns(uint64(val))
	return nil
}

func assembleGtxnsa(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 2 {
		return ops.error("gtxnsa expects two immediate arguments")
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("gtxnsa unknown field: %v", args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if !ok {
		return ops.errorf("gtxnsa unknown field: %v", args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("gtxnsa %s available in version %d. Missed #pragma version?", args[0], fs.version)
	}
	arrayFieldIdx, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	fieldNum := fs.field
	ops.Gtxnsa(uint64(fieldNum), uint64(arrayFieldIdx))
	return nil
}

func assembleGlobal(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		ops.error("global expects one argument")
		args = []string{GlobalFieldNames[0]}
	}
	fs, ok := globalFieldSpecByName[args[0]]
	if !ok {
		ops.errorf("global unknown field: %v", args[0])
		fs, _ = globalFieldSpecByName[GlobalFieldNames[0]]
	}
	if fs.version > ops.Version {
		ops.errorf("global %s available in version %d. Missed #pragma version?", args[0], fs.version)
	}
	ops.Global(fs.gfield)
	return nil
}

func assembleAssetHolding(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		ops.error("asset_holding_get expects one argument")
		args = []string{AssetHoldingFieldNames[0]}
	}
	val, ok := assetHoldingFields[args[0]]
	if !ok {
		ops.errorf("asset_holding_get unknown arg: %v", args[0])
		val = 0
	}
	ops.AssetHolding(val)
	return nil
}

func assembleAssetParams(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		ops.error("asset_params_get expects one argument")
		args = []string{AssetParamsFieldNames[0]}
	}
	val, ok := assetParamsFields[args[0]]
	if !ok {
		ops.errorf("asset_params_get unknown arg: %v", args[0])
		val = 0
	}
	ops.AssetParams(val)
	return nil
}

type assembleFunc func(*OpStream, *OpSpec, []string) error

// Basic assembly. Any extra bytes of opcode are encoded as byte immediates.
func asmDefault(ops *OpStream, spec *OpSpec, args []string) error {
	ops.checkArgs(*spec)
	if len(args) != spec.Details.Size-1 {
		ops.errorf("%s expects %d immediate arguments", spec.Name, spec.Details.Size)
	}
	ops.pending.WriteByte(spec.Opcode)
	for i := 0; i < spec.Details.Size-1; i++ {
		val, err := strconv.ParseUint(args[i], 0, 64)
		if err != nil {
			return ops.error(err)
		}
		if val > 255 {
			return ops.errorf("%s outside 0..255: %d", spec.Name, val)
		}
		ops.pending.WriteByte(byte(val))
	}
	return nil
}

// keywords handle parsing and assembling special asm language constructs like 'addr'
// We use OpSpec here, but somewhat degenerate, since they don't have opcodes or eval functions
var keywords = map[string]OpSpec{
	"int":  {0, "int", nil, assembleInt, nil, nil, oneInt, 1, modeAny, opDetails{1, 2, nil, nil}},
	"byte": {0, "byte", nil, assembleByte, nil, nil, oneBytes, 1, modeAny, opDetails{1, 2, nil, nil}},
	// parse basics.Address, actually just another []byte constant
	"addr": {0, "addr", nil, assembleAddr, nil, nil, oneBytes, 1, modeAny, opDetails{1, 2, nil, nil}},
}

type lineError struct {
	Line int
	Err  error
}

func (le *lineError) Error() string {
	return fmt.Sprintf("%d: %s", le.Line, le.Err.Error())
}

func (le *lineError) Unwrap() error {
	return le.Err
}

func typecheck(expected, got StackType) bool {
	// Some ops push 'any' and we wait for run time to see what it is.
	// Some of those 'any' are based on fields that we _could_ know now but haven't written a more detailed system of typecheck for (yet).
	if expected == StackAny && got == StackNone { // Any is lenient, but stack can't be empty
		return false
	}
	if (expected == StackAny) || (got == StackAny) {
		return true
	}
	return expected == got
}

var spaces = [256]uint8{'\t': 1, ' ': 1}

func fieldsFromLine(line string) []string {
	var fields []string

	i := 0
	for i < len(line) && spaces[line[i]] != 0 {
		i++
	}

	start := i
	inString := false
	inBase64 := false
	for i < len(line) {
		if spaces[line[i]] == 0 { // if not space
			switch line[i] {
			case '"': // is a string literal?
				if !inString {
					if i == 0 || i > 0 && spaces[line[i-1]] != 0 {
						inString = true
					}
				} else {
					if line[i-1] != '\\' { // if not escape symbol
						inString = false
					}
				}
			case '/': // is a comment?
				if i < len(line)-1 && line[i+1] == '/' && !inBase64 && !inString {
					if start != i { // if a comment without whitespace
						fields = append(fields, line[start:i])
					}
					return fields
				}
			case '(': // is base64( seq?
				prefix := line[start:i]
				if prefix == "base64" || prefix == "b64" {
					inBase64 = true
				}
			case ')': // is ) as base64( completion
				if inBase64 {
					inBase64 = false
				}
			default:
			}
			i++
			continue
		}
		if !inString {
			field := line[start:i]
			fields = append(fields, field)
			if field == "base64" || field == "b64" {
				inBase64 = true
			} else if inBase64 {
				inBase64 = false
			}
		}
		i++

		if !inString {
			for i < len(line) && spaces[line[i]] != 0 {
				i++
			}
			start = i
		}
	}

	// add rest of the string if any
	if start < len(line) {
		fields = append(fields, line[start:i])
	}

	return fields
}

func (ops *OpStream) trace(format string, args ...interface{}) {
	if ops.Trace == nil {
		return
	}
	fmt.Fprintf(ops.Trace, format, args...)
}

// checks (and pops) arg types from arg type stack
func (ops *OpStream) checkArgs(spec OpSpec) {
	firstPop := true
	for i := len(spec.Args) - 1; i >= 0; i-- {
		argType := spec.Args[i]
		stype := ops.tpop()
		if firstPop {
			firstPop = false
			ops.trace("pops(%s", argType.String())
		} else {
			ops.trace(", %s", argType.String())
		}
		if !typecheck(argType, stype) {
			err := fmt.Errorf("%s arg %d wanted type %s got %s", spec.Name, i, argType.String(), stype.String())
			if len(ops.labelReferences) > 0 {
				ops.warnf("%w; but branches have happened and assembler does not precisely track types in this case", err)
			} else {
				ops.error(err)
			}
		}
	}
	if !firstPop {
		ops.trace(")")
	}

	if len(spec.Returns) > 0 {
		ops.tpusha(spec.Returns)
		ops.trace(" pushes(%s", spec.Returns[0].String())
		if len(spec.Returns) > 1 {
			for _, rt := range spec.Returns[1:] {
				ops.trace(", %s", rt.String())
			}
		}
		ops.trace(")")
	}
}

// assemble reads text from an input and accumulates the program
func (ops *OpStream) assemble(fin io.Reader) error {
	if ops.Version > LogicVersion && ops.Version != assemblerNoVersion {
		return ops.errorf("Can not assemble version %d", ops.Version)
	}
	scanner := bufio.NewScanner(fin)
	ops.sourceLine = 0
	for scanner.Scan() {
		ops.sourceLine++
		line := scanner.Text()
		if len(line) == 0 {
			ops.trace("%d: 0 line\n", ops.sourceLine)
			continue
		}
		if strings.HasPrefix(line, "//") {
			ops.trace("%d: // line\n", ops.sourceLine)
			continue
		}
		if strings.HasPrefix(line, "#pragma") {
			ops.trace("%d: #pragma line\n", ops.sourceLine)
			ops.pragma(line)
			continue
		}
		fields := fieldsFromLine(line)
		if len(fields) == 0 {
			ops.trace("%d: no fields\n", ops.sourceLine)
			continue
		}
		// we're going to process opcodes, so fix the Version
		if ops.Version == assemblerNoVersion {
			ops.Version = AssemblerDefaultVersion
		}
		opstring := fields[0]
		spec, ok := OpsByName[ops.Version][opstring]
		if !ok {
			spec, ok = keywords[opstring]
		}
		if ok {
			ops.trace("%3d: %s\t", ops.sourceLine, opstring)
			ops.RecordSourceLine()
			spec.asm(ops, &spec, fields[1:])
			ops.trace("\n")
			continue
		}
		if opstring[len(opstring)-1] == ':' {
			ops.createLabel(opstring[:len(opstring)-1])
			continue
		}
		// unknown opcode, let's report a good error if version problem
		spec, ok = OpsByName[AssemblerMaxVersion][opstring]
		if ok {
			ops.errorf("%s opcode was introduced in TEAL v%d", opstring, spec.Version)
		} else {
			ops.errorf("unknown opcode: %s", opstring)
		}
	}

	// backward compatibility: do not allow jumps behind last instruction in TEAL v1
	if ops.Version <= 1 {
		for label, dest := range ops.labels {
			if dest == ops.pending.Len() {
				ops.errorf("label %v is too far away", label)
			}
		}
	}

	// TODO: warn if expected resulting stack is not len==1 ?
	ops.resolveLabels()
	program := ops.prependCBlocks()
	if ops.Errors != nil {
		l := len(ops.Errors)
		if l == 1 {
			return errors.New("1 error")
		}
		return fmt.Errorf("%d errors", l)
	}
	ops.Program = program
	return nil
}

func (ops *OpStream) pragma(line string) error {
	fields := strings.Split(line, " ")
	if fields[0] != "#pragma" {
		return ops.errorf("invalid syntax: %s", fields[0])
	}
	if len(fields) < 2 {
		return ops.error("empty pragma")
	}
	key := fields[1]
	switch key {
	case "version":
		if len(fields) < 3 {
			return ops.error("no version value")
		}
		value := fields[2]
		var ver uint64
		if ops.pending.Len() > 0 {
			return ops.error("#pragma version is only allowed before instructions")
		}
		ver, err := strconv.ParseUint(value, 0, 64)
		if err != nil {
			return ops.errorf("bad #pragma version: %#v", value)
		}
		if ver < 1 || ver > AssemblerMaxVersion {
			return ops.errorf("unsupported version: %d", ver)
		}
		if ops.pragraVersionFound {
			return ops.errorf("pragma version can appear only once in a TEAL program")
		}

		// We initialize Version with assemblerNoVersion as a marker for
		// non-specified version because version 0 is valid
		// version for TEAL v1.
		if ops.Version == assemblerNoVersion {
			ops.Version = ver
		} else if ops.Version < ver {
			return ops.errorf("version mismatch: assembling v%d with v%d assembler", ver, ops.Version)
		} else {
			// ops.Version is already correct, or needed to be upped.
			ops.Version = ver
		}
		ops.pragraVersionFound = true
		return nil
	default:
		return ops.errorf("unsupported pragma directive: %#v", key)
	}
}

func (ops *OpStream) resolveLabels() {
	saved := ops.sourceLine
	raw := ops.pending.Bytes()
	reported := make(map[string]bool)
	for _, lr := range ops.labelReferences {
		ops.sourceLine = lr.sourceLine
		dest, ok := ops.labels[lr.label]
		if !ok {
			if !reported[lr.label] {
				ops.errorf("reference to undefined label %v", lr.label)
			}
			reported[lr.label] = true
			continue
		}
		// all branch instructions (currently) are opcode byte and 2 offset bytes, and the destination is relative to the next pc as if the branch was a no-op
		naturalPc := lr.position + 3
		if dest < naturalPc {
			ops.errorf("label %v is before reference but only forward jumps are allowed", lr.label)
			continue
		}
		jump := dest - naturalPc
		if jump > 0x7fff {
			ops.errorf("label %v is too far away", lr.label)
			continue
		}
		raw[lr.position+1] = uint8(jump >> 8)
		raw[lr.position+2] = uint8(jump & 0x0ff)
	}
	ops.pending.Reset()
	ops.pending.Write(raw)
	ops.sourceLine = saved
}

// AssemblerDefaultVersion what version of code do we emit by default
// AssemblerDefaultVersion is set to 1 on puprose
// to prevent accidental building of v1 official templates with version 2
// because these templates are not aware of rekeying.
const AssemblerDefaultVersion = 1

// AssemblerMaxVersion is a maximum supported assembler version
const AssemblerMaxVersion = LogicVersion
const assemblerNoVersion = (^uint64(0))

// prependCBlocks completes the assembly by inserting cblocks if needed.
func (ops *OpStream) prependCBlocks() []byte {
	var scratch [binary.MaxVarintLen64]byte
	prebytes := bytes.Buffer{}
	vlen := binary.PutUvarint(scratch[:], ops.GetVersion())
	prebytes.Write(scratch[:vlen])
	if len(ops.intc) > 0 && !ops.noIntcBlock {
		prebytes.WriteByte(0x20) // intcblock
		vlen := binary.PutUvarint(scratch[:], uint64(len(ops.intc)))
		prebytes.Write(scratch[:vlen])
		for _, iv := range ops.intc {
			vlen = binary.PutUvarint(scratch[:], iv)
			prebytes.Write(scratch[:vlen])
		}
	}
	if len(ops.bytec) > 0 && !ops.noBytecBlock {
		prebytes.WriteByte(0x26) // bytecblock
		vlen := binary.PutUvarint(scratch[:], uint64(len(ops.bytec)))
		prebytes.Write(scratch[:vlen])
		for _, bv := range ops.bytec {
			vlen = binary.PutUvarint(scratch[:], uint64(len(bv)))
			prebytes.Write(scratch[:vlen])
			prebytes.Write(bv)
		}
	}

	pbl := prebytes.Len()
	outl := ops.pending.Len()
	out := make([]byte, pbl+outl)
	pl, err := prebytes.Read(out)
	if pl != pbl || err != nil {
		ops.errorf("wat: %d prebytes, %d to buffer? err=%w", pbl, pl, err)
		return nil
	}
	ol, err := ops.pending.Read(out[pl:])
	if ol != outl || err != nil {
		ops.errorf("%d program bytes but %d to buffer. err=%w", outl, ol, err)
		return nil
	}

	// fixup offset to line mapping
	newOffsetToLine := make(map[int]int, len(ops.OffsetToLine))
	for o, l := range ops.OffsetToLine {
		newOffsetToLine[o+pbl] = l
	}
	ops.OffsetToLine = newOffsetToLine

	return out
}

func (ops *OpStream) error(problem interface{}) error {
	var le *lineError
	switch p := problem.(type) {
	case string:
		le = &lineError{Line: ops.sourceLine, Err: errors.New(p)}
	case error:
		le = &lineError{Line: ops.sourceLine, Err: p}
	default:
		le = &lineError{Line: ops.sourceLine, Err: fmt.Errorf("%#v", p)}
	}
	ops.Errors = append(ops.Errors, le)
	return le
}

func (ops *OpStream) errorf(format string, a ...interface{}) error {
	return ops.error(fmt.Errorf(format, a...))
}

func (ops *OpStream) warn(problem interface{}) error {
	var le *lineError
	switch p := problem.(type) {
	case string:
		le = &lineError{Line: ops.sourceLine, Err: errors.New(p)}
	case error:
		le = &lineError{Line: ops.sourceLine, Err: p}
	default:
		le = &lineError{Line: ops.sourceLine, Err: fmt.Errorf("%#v", p)}
	}
	warning := fmt.Errorf("warning: %w", le)
	ops.Warnings = append(ops.Warnings, warning)
	return warning
}
func (ops *OpStream) warnf(format string, a ...interface{}) error {
	return ops.warn(fmt.Errorf(format, a...))
}

// ReportProblems issues accumulated warnings and errors to stderr.
func (ops *OpStream) ReportProblems(fname string) {
	for i, e := range ops.Errors {
		if i > 9 {
			break
		}
		fmt.Fprintf(os.Stderr, "%s: %s\n", fname, e)
	}
	for i, w := range ops.Warnings {
		if i > 9 {
			break
		}
		fmt.Fprintf(os.Stderr, "%s: %s\n", fname, w)
	}
}

// AssembleString takes an entire program in a string and assembles it to bytecode using AssemblerDefaultVersion
func AssembleString(text string) (*OpStream, error) {
	return AssembleStringWithVersion(text, assemblerNoVersion)
}

// AssembleStringWithVersion takes an entire program in a string and
// assembles it to bytecode using the assembler version specified.  If
// version is assemblerNoVersion it uses #pragma version or fallsback
// to AssemblerDefaultVersion.  OpStream is returned to allow access
// to warnings, (multiple) errors, or the PC to source line mapping.
// Note that AssemblerDefaultVersion is not the latest supported version,
// and therefore we might need to pass in explicitly a higher version.
func AssembleStringWithVersion(text string, version uint64) (*OpStream, error) {
	sr := strings.NewReader(text)
	ops := OpStream{Version: version}
	err := ops.assemble(sr)
	return &ops, err
}

type disassembleState struct {
	program       []byte
	pc            int
	out           io.Writer
	labelCount    int
	pendingLabels map[int]string

	nextpc int
	err    error
}

func (dis *disassembleState) putLabel(label string, target int) {
	if dis.pendingLabels == nil {
		dis.pendingLabels = make(map[int]string)
	}
	dis.pendingLabels[target] = label
}

func (dis *disassembleState) outputLabelIfNeeded() (err error) {
	if label, hasLabel := dis.pendingLabels[dis.pc]; hasLabel {
		_, err = fmt.Fprintf(dis.out, "%s:\n", label)
	}
	return
}

type disassembleFunc func(dis *disassembleState, spec *OpSpec)

// Basic disasemble, and extra bytes of opcode are decoded as bytes integers.
func disDefault(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + spec.Details.Size - 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	dis.nextpc = dis.pc + spec.Details.Size
	_, dis.err = fmt.Fprintf(dis.out, "%s", spec.Name)
	if dis.err != nil {
		return
	}
	for s := 1; s < spec.Details.Size; s++ {
		b := uint(dis.program[dis.pc+s])
		_, dis.err = fmt.Fprintf(dis.out, " %d", b)
		if dis.err != nil {
			return
		}
	}
	_, dis.err = fmt.Fprintf(dis.out, "\n")
}

var errShortIntcblock = errors.New("intcblock ran past end of program")
var errTooManyIntc = errors.New("intcblock with too many items")

func parseIntcblock(program []byte, pc int) (intc []uint64, nextpc int, err error) {
	pos := pc + 1
	numInts, bytesUsed := binary.Uvarint(program[pos:])
	if bytesUsed <= 0 {
		err = fmt.Errorf("could not decode int const block size at pc=%d", pos)
		return
	}
	pos += bytesUsed
	if numInts > uint64(len(program)) {
		err = errTooManyIntc
		return
	}
	intc = make([]uint64, numInts)
	for i := uint64(0); i < numInts; i++ {
		if pos >= len(program) {
			err = errShortIntcblock
			return
		}
		intc[i], bytesUsed = binary.Uvarint(program[pos:])
		if bytesUsed <= 0 {
			err = fmt.Errorf("could not decode int const[%d] at pc=%d", i, pos)
			return
		}
		pos += bytesUsed
	}
	nextpc = pos
	return
}

func checkIntConstBlock(cx *evalContext) int {
	pos := cx.pc + 1
	numInts, bytesUsed := binary.Uvarint(cx.program[pos:])
	if bytesUsed <= 0 {
		cx.err = fmt.Errorf("could not decode int const block size at pc=%d", pos)
		return 1
	}
	pos += bytesUsed
	if numInts > uint64(len(cx.program)) {
		cx.err = errTooManyIntc
		return 0
	}
	//intc = make([]uint64, numInts)
	for i := uint64(0); i < numInts; i++ {
		if pos >= len(cx.program) {
			cx.err = errShortIntcblock
			return 0
		}
		_, bytesUsed = binary.Uvarint(cx.program[pos:])
		if bytesUsed <= 0 {
			cx.err = fmt.Errorf("could not decode int const[%d] at pc=%d", i, pos)
			return 1
		}
		pos += bytesUsed
	}
	cx.nextpc = pos
	return 1
}

var errShortBytecblock = errors.New("bytecblock ran past end of program")
var errTooManyItems = errors.New("bytecblock with too many items")

func parseBytecBlock(program []byte, pc int) (bytec [][]byte, nextpc int, err error) {
	pos := pc + 1
	numItems, bytesUsed := binary.Uvarint(program[pos:])
	if bytesUsed <= 0 {
		err = fmt.Errorf("could not decode []byte const block size at pc=%d", pos)
		return
	}
	pos += bytesUsed
	if numItems > uint64(len(program)) {
		err = errTooManyItems
		return
	}
	bytec = make([][]byte, numItems)
	for i := uint64(0); i < numItems; i++ {
		if pos >= len(program) {
			err = errShortBytecblock
			return
		}
		itemLen, bytesUsed := binary.Uvarint(program[pos:])
		if bytesUsed <= 0 {
			err = fmt.Errorf("could not decode []byte const[%d] at pc=%d", i, pos)
			return
		}
		pos += bytesUsed
		if pos >= len(program) {
			err = errShortBytecblock
			return
		}
		end := uint64(pos) + itemLen
		if end > uint64(len(program)) || end < uint64(pos) {
			err = errShortBytecblock
			return
		}
		bytec[i] = program[pos : pos+int(itemLen)]
		pos += int(itemLen)
	}
	nextpc = pos
	return
}

func checkByteConstBlock(cx *evalContext) int {
	pos := cx.pc + 1
	numItems, bytesUsed := binary.Uvarint(cx.program[pos:])
	if bytesUsed <= 0 {
		cx.err = fmt.Errorf("could not decode []byte const block size at pc=%d", pos)
		return 1
	}
	pos += bytesUsed
	if numItems > uint64(len(cx.program)) {
		cx.err = errTooManyItems
		return 0
	}
	//bytec = make([][]byte, numItems)
	for i := uint64(0); i < numItems; i++ {
		if pos >= len(cx.program) {
			cx.err = errShortBytecblock
			return 0
		}
		itemLen, bytesUsed := binary.Uvarint(cx.program[pos:])
		if bytesUsed <= 0 {
			cx.err = fmt.Errorf("could not decode []byte const[%d] at pc=%d", i, pos)
			return 1
		}
		pos += bytesUsed
		if pos >= len(cx.program) {
			cx.err = errShortBytecblock
			return 0
		}
		end := uint64(pos) + itemLen
		if end > uint64(len(cx.program)) || end < uint64(pos) {
			cx.err = errShortBytecblock
			return 0
		}
		//bytec[i] = program[pos : pos+int(itemLen)]
		pos += int(itemLen)
	}
	cx.nextpc = pos
	return 1
}

func disIntcblock(dis *disassembleState, spec *OpSpec) {
	var intc []uint64
	intc, dis.nextpc, dis.err = parseIntcblock(dis.program, dis.pc)
	if dis.err != nil {
		return
	}
	_, dis.err = fmt.Fprintf(dis.out, "intcblock")
	if dis.err != nil {
		return
	}
	for _, iv := range intc {
		_, dis.err = fmt.Fprintf(dis.out, " %d", iv)
		if dis.err != nil {
			return
		}
	}
	_, dis.err = dis.out.Write([]byte("\n"))
}

func disBytecblock(dis *disassembleState, spec *OpSpec) {
	var bytec [][]byte
	bytec, dis.nextpc, dis.err = parseBytecBlock(dis.program, dis.pc)
	if dis.err != nil {
		return
	}
	_, dis.err = fmt.Fprintf(dis.out, "bytecblock")
	if dis.err != nil {
		return
	}
	for _, bv := range bytec {
		_, dis.err = fmt.Fprintf(dis.out, " 0x%s", hex.EncodeToString(bv))
		if dis.err != nil {
			return
		}
	}
	_, dis.err = dis.out.Write([]byte("\n"))
}

func disPushInt(dis *disassembleState, spec *OpSpec) {
	pos := dis.pc + 1
	val, bytesUsed := binary.Uvarint(dis.program[pos:])
	if bytesUsed <= 0 {
		dis.err = fmt.Errorf("could not decode int at pc=%d", pos)
		return
	}
	pos += bytesUsed
	_, dis.err = fmt.Fprintf(dis.out, "%s %d\n", spec.Name, val)
	dis.nextpc = pos
}
func checkPushInt(cx *evalContext) int {
	opPushInt(cx)
	return 1
}

func disPushBytes(dis *disassembleState, spec *OpSpec) {
	pos := dis.pc + 1
	length, bytesUsed := binary.Uvarint(dis.program[pos:])
	if bytesUsed <= 0 {
		dis.err = fmt.Errorf("could not decode bytes length at pc=%d", pos)
		return
	}
	pos += bytesUsed
	end := uint64(pos) + length
	if end > uint64(len(dis.program)) || end < uint64(pos) {
		dis.err = fmt.Errorf("pushbytes too long %d %d", end, pos)
		return
	}
	bytes := dis.program[pos:end]
	_, dis.err = fmt.Fprintf(dis.out, "%s 0x%s", spec.Name, hex.EncodeToString(bytes))
	dis.nextpc = int(end)
}
func checkPushBytes(cx *evalContext) int {
	opPushBytes(cx)
	return 1
}

// This is also used to disassemble gtxns
func disTxn(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	dis.nextpc = dis.pc + 2
	txarg := dis.program[dis.pc+1]
	if int(txarg) >= len(TxnFieldNames) {
		dis.err = fmt.Errorf("invalid txn arg index %d at pc=%d", txarg, dis.pc)
		return
	}
	_, dis.err = fmt.Fprintf(dis.out, "%s %s\n", spec.Name, TxnFieldNames[txarg])
}

// This is also used to disassemble gtxnsa
func disTxna(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 2
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	dis.nextpc = dis.pc + 3
	txarg := dis.program[dis.pc+1]
	if int(txarg) >= len(TxnFieldNames) {
		dis.err = fmt.Errorf("invalid txn arg index %d at pc=%d", txarg, dis.pc)
		return
	}
	arrayFieldIdx := dis.program[dis.pc+2]
	_, dis.err = fmt.Fprintf(dis.out, "%s %s %d\n", spec.Name, TxnFieldNames[txarg], arrayFieldIdx)
}

func disGtxn(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 2
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	dis.nextpc = dis.pc + 3
	gi := dis.program[dis.pc+1]
	txarg := dis.program[dis.pc+2]
	if int(txarg) >= len(TxnFieldNames) {
		dis.err = fmt.Errorf("invalid txn arg index %d at pc=%d", txarg, dis.pc)
		return
	}
	_, dis.err = fmt.Fprintf(dis.out, "gtxn %d %s\n", gi, TxnFieldNames[txarg])
}

func disGtxna(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 3
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	dis.nextpc = dis.pc + 4
	gi := dis.program[dis.pc+1]
	txarg := dis.program[dis.pc+2]
	if int(txarg) >= len(TxnFieldNames) {
		dis.err = fmt.Errorf("invalid txn arg index %d at pc=%d", txarg, dis.pc)
		return
	}
	arrayFieldIdx := dis.program[dis.pc+3]
	_, dis.err = fmt.Fprintf(dis.out, "gtxna %d %s %d\n", gi, TxnFieldNames[txarg], arrayFieldIdx)
}

func disGlobal(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	dis.nextpc = dis.pc + 2
	garg := dis.program[dis.pc+1]
	if int(garg) >= len(GlobalFieldNames) {
		dis.err = fmt.Errorf("invalid global arg index %d at pc=%d", garg, dis.pc)
		return
	}
	_, dis.err = fmt.Fprintf(dis.out, "global %s\n", GlobalFieldNames[garg])
}

func disBranch(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 2
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}

	dis.nextpc = dis.pc + 3
	offset := (uint(dis.program[dis.pc+1]) << 8) | uint(dis.program[dis.pc+2])
	target := int(offset) + dis.pc + 3
	label, labelExists := dis.pendingLabels[target]
	if !labelExists {
		dis.labelCount++
		label = fmt.Sprintf("label%d", dis.labelCount)
		dis.putLabel(label, target)
	}
	_, dis.err = fmt.Fprintf(dis.out, "%s %s\n", spec.Name, label)
}

func disAssetHolding(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	dis.nextpc = dis.pc + 2
	arg := dis.program[dis.pc+1]
	if int(arg) >= len(AssetHoldingFieldNames) {
		dis.err = fmt.Errorf("invalid asset holding arg index %d at pc=%d", arg, dis.pc)
		return
	}
	_, dis.err = fmt.Fprintf(dis.out, "asset_holding_get %s\n", AssetHoldingFieldNames[arg])
}

func disAssetParams(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	dis.nextpc = dis.pc + 2
	arg := dis.program[dis.pc+1]
	if int(arg) >= len(AssetParamsFieldNames) {
		dis.err = fmt.Errorf("invalid asset params arg index %d at pc=%d", arg, dis.pc)
		return
	}
	_, dis.err = fmt.Fprintf(dis.out, "asset_params_get %s\n", AssetParamsFieldNames[arg])
}

type disInfo struct {
	pcOffset       []PCOffset
	hasStatefulOps bool
}

// disassembleInstrumented is like Disassemble, but additionally returns where
// each program counter value maps in the disassembly
func disassembleInstrumented(program []byte) (text string, ds disInfo, err error) {
	out := strings.Builder{}
	dis := disassembleState{program: program, out: &out}
	version, vlen := binary.Uvarint(program)
	if vlen <= 0 {
		fmt.Fprintf(dis.out, "// invalid version\n")
		text = out.String()
		return
	}
	if version > LogicVersion {
		fmt.Fprintf(dis.out, "// unsupported version %d\n", version)
		text = out.String()
		return
	}
	fmt.Fprintf(dis.out, "// version %d\n", version)
	dis.pc = vlen
	for dis.pc < len(program) {
		err = dis.outputLabelIfNeeded()
		if err != nil {
			return
		}
		op := opsByOpcode[version][program[dis.pc]]
		if op.Modes == runModeApplication {
			ds.hasStatefulOps = true
		}
		if op.Name == "" {
			ds.pcOffset = append(ds.pcOffset, PCOffset{dis.pc, out.Len()})
			msg := fmt.Sprintf("invalid opcode %02x at pc=%d", program[dis.pc], dis.pc)
			out.WriteString(msg)
			out.WriteRune('\n')
			text = out.String()
			err = errors.New(msg)
			return
		}

		// ds.pcOffset tracks where in the output each opcode maps to assembly
		ds.pcOffset = append(ds.pcOffset, PCOffset{dis.pc, out.Len()})

		// Actually do the disassembly
		op.dis(&dis, &op)
		if dis.err != nil {
			err = dis.err
			return
		}
		dis.pc = dis.nextpc
	}
	err = dis.outputLabelIfNeeded()
	if err != nil {
		return
	}

	text = out.String()
	return
}

// Disassemble produces a text form of program bytes.
// AssembleString(Disassemble()) should result in the same program bytes.
func Disassemble(program []byte) (text string, err error) {
	text, _, err = disassembleInstrumented(program)
	return
}

// HasStatefulOps checks if the program has stateful opcodes
func HasStatefulOps(program []byte) (bool, error) {
	_, ds, err := disassembleInstrumented(program)
	return ds.hasStatefulOps, err
}
