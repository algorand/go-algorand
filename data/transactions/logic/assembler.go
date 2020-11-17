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
	Out     bytes.Buffer
	Version uint64
	Trace   io.Writer
	vubytes [9]byte

	intc        []uint64
	noIntcBlock bool

	bytec        [][]byte
	noBytecBlock bool

	// Keep a stack of the types of what we would push and pop to typecheck a program
	typeStack []StackType

	// current sourceLine during assembly
	sourceLine int

	// map label string to position within Out buffer
	labels map[string]int

	labelReferences []labelReference

	// map opcode offsets to source line
	offsetToLine map[int]int
}

// GetVersion returns the LogicSigVersion we're building to
func (ops *OpStream) GetVersion() uint64 {
	if ops.Version == 0 {
		ops.Version = AssemblerDefaultVersion
	}
	return ops.Version
}

// SetLabelHere inserts a label reference to point to the next instruction
func (ops *OpStream) SetLabelHere(label string) error {
	if ops.labels == nil {
		ops.labels = make(map[string]int)
	}
	if _, ok := ops.labels[label]; ok {
		return ops.errorf("duplicate label %s", label)
	}
	ops.labels[label] = ops.Out.Len()
	return nil
}

// RecordSourceLine adds an entry to pc to line mapping
func (ops *OpStream) RecordSourceLine() {
	if ops.offsetToLine == nil {
		ops.offsetToLine = make(map[int]int)
	}
	ops.offsetToLine[ops.Out.Len()] = ops.sourceLine - 1
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
func (ops *OpStream) Intc(constIndex uint) error {
	switch constIndex {
	case 0:
		ops.Out.WriteByte(0x22) // intc_0
	case 1:
		ops.Out.WriteByte(0x23) // intc_1
	case 2:
		ops.Out.WriteByte(0x24) // intc_2
	case 3:
		ops.Out.WriteByte(0x25) // intc_3
	default:
		if constIndex > 0xff {
			return ops.error("cannot have more than 256 int constants")
		}
		ops.Out.WriteByte(0x21) // intc
		ops.Out.WriteByte(uint8(constIndex))
	}
	if constIndex >= uint(len(ops.intc)) {
		return ops.errorf("intc %d is not defined", constIndex)
	}
	ops.tpush(StackUint64)
	return nil
}

// Uint writes opcodes for loading a uint literal
func (ops *OpStream) Uint(val uint64) error {
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
	return ops.Intc(constIndex)
}

// Bytec writes opcodes for loading a []byte constant onto the stack.
func (ops *OpStream) Bytec(constIndex uint) error {
	switch constIndex {
	case 0:
		ops.Out.WriteByte(0x28) // bytec_0
	case 1:
		ops.Out.WriteByte(0x29) // bytec_1
	case 2:
		ops.Out.WriteByte(0x2a) // bytec_2
	case 3:
		ops.Out.WriteByte(0x2b) // bytec_3
	default:
		if constIndex > 0xff {
			return ops.error("cannot have more than 256 byte constants")
		}
		ops.Out.WriteByte(0x27) // bytec
		ops.Out.WriteByte(uint8(constIndex))
	}
	if constIndex >= uint(len(ops.bytec)) {
		return ops.errorf("bytec %d is not defined", constIndex)
	}
	ops.trace("bytec %d %s", constIndex, hex.EncodeToString(ops.bytec[constIndex]))
	ops.tpush(StackBytes)
	return nil
}

// ByteLiteral writes opcodes and data for loading a []byte literal
// Values are accumulated so that they can be put into a bytecblock
func (ops *OpStream) ByteLiteral(val []byte) error {
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
	return ops.Bytec(constIndex)
}

// Arg writes opcodes for loading from Lsig.Args
func (ops *OpStream) Arg(val uint64) error {
	switch val {
	case 0:
		ops.Out.WriteByte(0x2d) // arg_0
	case 1:
		ops.Out.WriteByte(0x2e) // arg_1
	case 2:
		ops.Out.WriteByte(0x2f) // arg_2
	case 3:
		ops.Out.WriteByte(0x30) // arg_3
	default:
		if val > 0xff {
			return ops.error("cannot have more than 256 args")
		}
		ops.Out.WriteByte(0x2c)
		ops.Out.WriteByte(uint8(val))
	}
	ops.tpush(StackBytes)
	return nil
}

// Txn writes opcodes for loading a field from the current transaction
func (ops *OpStream) Txn(val uint64) error {
	if val >= uint64(len(TxnFieldNames)) {
		return ops.errorf("invalid txn field: %d", val)
	}
	ops.Out.WriteByte(0x31)
	ops.Out.WriteByte(uint8(val))
	ops.tpush(TxnFieldTypes[val])
	return nil
}

// Txna writes opcodes for loading array field from the current transaction
func (ops *OpStream) Txna(fieldNum uint64, arrayFieldIdx uint64) error {
	if fieldNum >= uint64(len(TxnFieldNames)) {
		return ops.errorf("invalid txn field: %d", fieldNum)
	}
	if arrayFieldIdx > 255 {
		return ops.errorf("txna array index beyond 255: %d", arrayFieldIdx)
	}
	ops.Out.WriteByte(0x36)
	ops.Out.WriteByte(uint8(fieldNum))
	ops.Out.WriteByte(uint8(arrayFieldIdx))
	ops.tpush(TxnFieldTypes[fieldNum])
	return nil
}

// Gtxn writes opcodes for loading a field from the current transaction
func (ops *OpStream) Gtxn(gid, val uint64) error {
	if val >= uint64(len(TxnFieldNames)) {
		return ops.errorf("invalid txn field: %d", val)
	}
	if gid > 255 {
		return ops.errorf("gtxn transaction index beyond 255: %d", gid)
	}
	ops.Out.WriteByte(0x33)
	ops.Out.WriteByte(uint8(gid))
	ops.Out.WriteByte(uint8(val))
	ops.tpush(TxnFieldTypes[val])
	return nil
}

// Gtxna writes opcodes for loading an array field from the current transaction
func (ops *OpStream) Gtxna(gid, fieldNum uint64, arrayFieldIdx uint64) error {
	if fieldNum >= uint64(len(TxnFieldNames)) {
		return ops.errorf("invalid txn field: %d", fieldNum)
	}
	if gid > 255 {
		return ops.errorf("gtxna group index beyond 255: %d", gid)
	}
	if arrayFieldIdx > 255 {
		return ops.errorf("gtxna array index beyond 255: %d", arrayFieldIdx)
	}
	ops.Out.WriteByte(0x37)
	ops.Out.WriteByte(uint8(gid))
	ops.Out.WriteByte(uint8(fieldNum))
	ops.Out.WriteByte(uint8(arrayFieldIdx))
	ops.tpush(TxnFieldTypes[fieldNum])
	return nil
}

// Global writes opcodes for loading an evaluator-global field
func (ops *OpStream) Global(val uint64) error {
	if val >= uint64(len(GlobalFieldNames)) {
		return ops.errorf("invalid global field: %d", val)
	}
	ops.Out.WriteByte(0x32)
	ops.Out.WriteByte(uint8(val))
	ops.trace("%s (%s)", GlobalFieldNames[val], GlobalFieldTypes[val].String())
	ops.tpush(GlobalFieldTypes[val])
	return nil
}

// AssetHolding writes opcodes for accessing data from AssetHolding
func (ops *OpStream) AssetHolding(val uint64) error {
	if val >= uint64(len(AssetHoldingFieldNames)) {
		return ops.errorf("invalid asset holding field: %d", val)
	}
	ops.Out.WriteByte(opsByName[ops.Version]["asset_holding_get"].Opcode)
	ops.Out.WriteByte(uint8(val))
	ops.tpush(AssetHoldingFieldTypes[val])
	ops.tpush(StackUint64)
	return nil
}

// AssetParams writes opcodes for accessing data from AssetParams
func (ops *OpStream) AssetParams(val uint64) error {
	if val >= uint64(len(AssetParamsFieldNames)) {
		return ops.errorf("invalid asset params field: %d", val)
	}
	ops.Out.WriteByte(opsByName[ops.Version]["asset_params_get"].Opcode)
	ops.Out.WriteByte(uint8(val))
	ops.tpush(AssetParamsFieldTypes[val])
	ops.tpush(StackUint64)
	return nil
}

func assembleInt(ops *OpStream, spec *OpSpec, args []string) error {
	// check friendly TypeEnum constants
	te, isTypeEnum := txnTypeConstToUint64[args[0]]
	if isTypeEnum {
		return ops.Uint(uint64(te))
	}
	// check raw transaction type strings
	tt, isTypeStr := txnTypeIndexes[args[0]]
	if isTypeStr {
		return ops.Uint(uint64(tt))
	}
	// check OnCompetion constants
	oc, isOCStr := onCompletionConstToUint64[args[0]]
	if isOCStr {
		return ops.Uint(uint64(oc))
	}
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.addLine(err)
	}
	return ops.Uint(val)
}

// Explicit invocation of const lookup and push
func assembleIntC(ops *OpStream, spec *OpSpec, args []string) error {
	constIndex, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.addLine(err)
	}
	return ops.Intc(uint(constIndex))
}
func assembleByteC(ops *OpStream, spec *OpSpec, args []string) error {
	constIndex, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.addLine(err)
	}
	return ops.Bytec(uint(constIndex))
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
	var val []byte
	var err error
	if len(args) == 0 {
		return ops.error("byte operation needs byte literal argument")
	}
	val, _, err = parseBinaryArgs(args)
	if err != nil {
		return ops.addLine(err)
	}
	return ops.ByteLiteral(val)
}

func assembleIntCBlock(ops *OpStream, spec *OpSpec, args []string) error {
	ops.Out.WriteByte(0x20) // intcblock
	var scratch [binary.MaxVarintLen64]byte
	l := binary.PutUvarint(scratch[:], uint64(len(args)))
	ops.Out.Write(scratch[:l])
	ops.intc = make([]uint64, len(args))
	for i, xs := range args {
		cu, err := strconv.ParseUint(xs, 0, 64)
		if err != nil {
			return ops.addLine(err)
		}
		l = binary.PutUvarint(scratch[:], cu)
		ops.Out.Write(scratch[:l])
		ops.intc[i] = cu
	}
	ops.noIntcBlock = true
	return nil
}

func assembleByteCBlock(ops *OpStream, spec *OpSpec, args []string) error {
	ops.Out.WriteByte(0x26) // bytecblock
	bvals := make([][]byte, 0, len(args))
	rest := args
	for len(rest) > 0 {
		val, consumed, err := parseBinaryArgs(rest)
		if err != nil {
			return ops.addLine(err)
		}
		bvals = append(bvals, val)
		rest = rest[consumed:]
	}
	var scratch [binary.MaxVarintLen64]byte
	l := binary.PutUvarint(scratch[:], uint64(len(bvals)))
	ops.Out.Write(scratch[:l])
	for _, bv := range bvals {
		l := binary.PutUvarint(scratch[:], uint64(len(bv)))
		ops.Out.Write(scratch[:l])
		ops.Out.Write(bv)
	}
	ops.bytec = bvals
	ops.noBytecBlock = true
	return nil
}

// addr A1EU...
// parses base32-with-checksum account address strings into a byte literal
func assembleAddr(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.error("addr operation needs one argument")
	}
	addr, err := basics.UnmarshalChecksumAddress(args[0])
	if err != nil {
		return ops.addLine(err)
	}
	return ops.ByteLiteral(addr[:])
}

func assembleArg(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.error("arg operation needs one argument")
	}
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.addLine(err)
	}
	return ops.Arg(val)
}

func assembleBranch(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.error("branch operation needs label argument")
	}
	ops.ReferToLabel(ops.Out.Len(), args[0])
	err := ops.checkArgs(*spec)
	if err != nil {
		return err
	}
	ops.Out.WriteByte(spec.Opcode)
	// zero bytes will get replaced with actual offset in resolveLabels()
	ops.Out.WriteByte(0)
	ops.Out.WriteByte(0)
	return nil
}

func assembleLoad(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.error("load operation needs one argument")
	}
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.addLine(err)
	}
	if val > EvalMaxScratchSize {
		return ops.errorf("load outside 0..255: %d", val)
	}
	ops.Out.WriteByte(0x34)
	ops.Out.WriteByte(byte(val))
	ops.tpush(StackAny)
	return nil
}

func assembleStore(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.error("store operation needs one argument")
	}
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.addLine(err)
	}
	if val > EvalMaxScratchSize {
		return ops.errorf("store outside 0..255: %d", val)
	}
	err = ops.checkArgs(*spec)
	if err != nil {
		return err
	}
	ops.Out.WriteByte(spec.Opcode)
	ops.Out.WriteByte(byte(val))
	return nil
}

func assembleSubstring(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 2 {
		return ops.error("substring expects 2 args")
	}
	start, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.addLine(err)
	}
	if start > EvalMaxScratchSize {
		return ops.error("substring limited to 0..255")
	}
	end, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		return ops.addLine(err)
	}
	if end > EvalMaxScratchSize {
		return ops.error("substring limited to 0..255")
	}

	if end < start {
		return ops.error("substring end is before start")
	}
	opcode := byte(0x51)
	err = ops.checkArgs(*spec)
	if err != nil {
		return err
	}
	ops.Out.WriteByte(opcode)
	ops.Out.WriteByte(byte(start))
	ops.Out.WriteByte(byte(end))
	ops.trace(" pushes([]byte)")
	ops.tpush(StackBytes)
	return nil
}

func disSubstring(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 2
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	start := uint(dis.program[dis.pc+1])
	end := uint(dis.program[dis.pc+2])
	dis.nextpc = dis.pc + 3
	_, dis.err = fmt.Fprintf(dis.out, "substring %d %d\n", start, end)
}

func assembleTxn(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.error("txn expects one argument")
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("txn unknown arg: %v", args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if ok {
		return ops.errorf("found txna field %v in txn op", args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("txn %s available in version %d. Missed #pragma version?", args[0], fs.version)
	}
	val := fs.field
	return ops.Txn(uint64(val))
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
		return ops.errorf("txna unknown arg: %v", args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if !ok {
		return ops.errorf("txna unknown arg: %v", args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("txna %s available in version %d. Missed #pragma version?", args[0], fs.version)
	}
	arrayFieldIdx, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		return ops.addLine(err)
	}
	fieldNum := fs.field
	return ops.Txna(uint64(fieldNum), uint64(arrayFieldIdx))
}

func assembleGtxn(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 2 {
		return ops.error("gtxn expects two arguments")
	}
	gtid, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.addLine(err)
	}
	fs, ok := txnFieldSpecByName[args[1]]
	if !ok {
		return ops.errorf("gtxn unknown arg: %v", args[1])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if ok {
		return ops.errorf("found gtxna field %v in gtxn op", args[1])
	}
	if fs.version > ops.Version {
		return ops.errorf("gtxn %s available in version %d. Missed #pragma version?", args[1], fs.version)
	}
	val := fs.field
	return ops.Gtxn(gtid, uint64(val))
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
		return ops.addLine(err)
	}
	fs, ok := txnFieldSpecByName[args[1]]
	if !ok {
		return ops.errorf("gtxna unknown arg: %v", args[1])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if !ok {
		return ops.errorf("gtxna unknown arg: %v", args[1])
	}
	if fs.version > ops.Version {
		return ops.errorf("gtxna %s available in version %d. Missed #pragma version?", args[1], fs.version)
	}
	arrayFieldIdx, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return ops.addLine(err)
	}
	fieldNum := fs.field
	return ops.Gtxna(gtid, uint64(fieldNum), uint64(arrayFieldIdx))
}

func assembleGlobal(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.error("global expects one argument")
	}
	fs, ok := globalFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("global unknown arg: %v", args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("global %s available in version %d. Missed #pragma version?", args[0], fs.version)
	}
	val := fs.gfield
	return ops.Global(uint64(val))
}

func assembleAssetHolding(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.error("asset_holding_get expects one argument")
	}
	val, ok := assetHoldingFields[args[0]]
	if !ok {
		return ops.errorf("asset_holding_get unknown arg: %v", args[0])
	}
	return ops.AssetHolding(uint64(val))
}

func assembleAssetParams(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.error("asset_params_get expects one argument")
	}
	val, ok := assetParamsFields[args[0]]
	if !ok {
		return ops.errorf("asset_params_get unknown arg: %v", args[0])
	}
	return ops.AssetParams(uint64(val))
}

type assembleFunc func(*OpStream, *OpSpec, []string) error

func asmDefault(ops *OpStream, spec *OpSpec, args []string) error {
	err := ops.checkArgs(*spec)
	if err != nil {
		return err
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
	err = ops.Out.WriteByte(spec.Opcode)
	if err != nil {
		return ops.addLine(err)
	}
	return nil
}

// keywords handle parsing and assembling special asm language constructs like 'addr'
var keywords map[string]assembleFunc

func init() {
	// WARNING: special case op assembly by argOps functions must do their own type stack maintenance via ops.tpop() ops.tpush()/ops.tpusha()
	keywords = make(map[string]assembleFunc)
	keywords["int"] = assembleInt
	keywords["byte"] = assembleByte
	keywords["addr"] = assembleAddr // parse basics.Address, actually just another []byte constant
	// WARNING: special case op assembly by argOps functions must do their own type stack maintenance via ops.tpop() ops.tpush()/ops.tpusha()
}

type lineError struct {
	Line int
	Err  error
}

func addLine(line int, err error) error {
	return &lineError{Line: line, Err: err}
}
func newLineError(line int, msg string) error {
	return addLine(line, errors.New(msg))
}
func fmtLineError(line int, format string, args ...interface{}) error {
	return addLine(line, fmt.Errorf(format, args...))
}

func (lew *lineError) Error() string {
	return fmt.Sprintf("%d: %s", lew.Line, lew.Err.Error())
}

func typecheck(expected, got StackType) bool {
	// Some ops push 'any' and we wait for run time to see what it is.
	// Some of those 'any' are based on fields that we _could_ know now but haven't written a more detailed system of typecheck for (yet).
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
func (ops *OpStream) checkArgs(spec OpSpec) error {
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
			msg := fmt.Sprintf("%s arg %d wanted type %s got %s", spec.Name, i, argType.String(), stype.String())
			if len(ops.labelReferences) > 0 {
				fmt.Fprintf(os.Stderr, "warning: %d: %s; but branches have happened and assembler does not precisely track types in this case\n", ops.sourceLine, msg)
			} else {
				return ops.error(msg)
			}
		}
	}
	if !firstPop {
		ops.trace(")")
	}
	return nil
}

// assemble reads text from an input and accumulates the program
func (ops *OpStream) assemble(fin io.Reader) error {
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
			// all pragmas must be be already processed in advance
			ops.trace("%d: #pragma line\n", ops.sourceLine)
			continue
		}
		fields := fieldsFromLine(line)
		if len(fields) == 0 {
			ops.trace("%d: no fields\n", ops.sourceLine)
			continue
		}
		opstring := fields[0]
		spec, ok := opsByName[ops.Version][opstring]
		var asmFunc assembleFunc
		if ok {
			asmFunc = spec.asm
		} else {
			kwFunc, ok := keywords[opstring]
			if ok {
				asmFunc = kwFunc
			}
		}
		if asmFunc != nil {
			ops.trace("%3d: %s\t", ops.sourceLine, opstring)
			ops.RecordSourceLine()
			err := asmFunc(ops, &spec, fields[1:])
			if err != nil {
				return err
			}
			ops.trace("\n")
			continue
		}
		if opstring[len(opstring)-1] == ':' {
			// create a label
			err := ops.SetLabelHere(opstring[:len(opstring)-1])
			if err != nil {
				return err
			}
			continue
		}
		return ops.errorf("unknown opcode: %v", opstring)
	}

	// backward compatibility: do not allow jumps behind last instruction in TEAL v1
	if ops.Version <= 1 {
		for label, dest := range ops.labels {
			if dest == ops.Out.Len() {
				return ops.errorf("label %v is too far away", label)
			}
		}
	}

	// TODO: warn if expected resulting stack is not len==1 ?
	return ops.resolveLabels()
}

func (ops *OpStream) resolveLabels() (err error) {
	if len(ops.labelReferences) == 0 {
		return nil
	}
	raw := ops.Out.Bytes()
	for _, lr := range ops.labelReferences {
		dest, ok := ops.labels[lr.label]
		if !ok {
			return fmtLineError(lr.sourceLine, "reference to undefined label %v", lr.label)
		}
		// all branch instructions (currently) are opcode byte and 2 offset bytes, and the destination is relative to the next pc as if the branch was a no-op
		naturalPc := lr.position + 3
		if dest < naturalPc {
			return fmtLineError(lr.sourceLine, "label %v is before reference but only forward jumps are allowed", lr.label)
		}
		jump := dest - naturalPc
		if jump > 0x7fff {
			return fmtLineError(lr.sourceLine, "label %v is too far away", lr.label)
		}
		raw[lr.position+1] = uint8(jump >> 8)
		raw[lr.position+2] = uint8(jump & 0x0ff)
	}
	ops.Out.Reset()
	ops.Out.Write(raw)
	return nil
}

// AssemblerDefaultVersion what version of code do we emit by default
// AssemblerDefaultVersion is set to 1 on puprose
// to prevent accidental building of v1 official templates with version 2
// because these templates are not aware of rekeying.
const AssemblerDefaultVersion = 1

// AssemblerMaxVersion is a maximum supported assembler version
const AssemblerMaxVersion = LogicVersion
const assemblerNoVersion = (^uint64(0))

// Bytes returns the finished program bytes
func (ops *OpStream) Bytes() (program []byte, err error) {
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
	if prebytes.Len() == 0 {
		program = ops.Out.Bytes()
		return
	}
	pbl := prebytes.Len()
	outl := ops.Out.Len()
	out := make([]byte, pbl+outl)
	pl, err := prebytes.Read(out)
	if pl != pbl || err != nil {
		err = fmt.Errorf("wat: %d prebytes, %d to buffer? err=%s", pbl, pl, err)
		return
	}
	ol, err := ops.Out.Read(out[pl:])
	if ol != outl || err != nil {
		err = fmt.Errorf("%d program bytes but %d to buffer. err=%s", outl, ol, err)
		return
	}

	// fixup offset to line mapping
	newOffsetToLine := make(map[int]int, len(ops.offsetToLine))
	for o, l := range ops.offsetToLine {
		newOffsetToLine[o+pbl] = l
	}
	ops.offsetToLine = newOffsetToLine

	program = out
	return
}

func (ops *OpStream) addLine(err error) error {
	return addLine(ops.sourceLine, err)
}

func (ops *OpStream) error(msg string) error {
	return ops.addLine(errors.New(msg))
}

func (ops *OpStream) errorf(format string, a ...interface{}) error {
	return ops.addLine(fmt.Errorf(format, a...))
}

// AssembleString takes an entire program in a string and assembles it to bytecode using AssemblerDefaultVersion
func AssembleString(text string) ([]byte, error) {
	return AssembleStringWithVersion(text, assemblerNoVersion)
}

// AssembleStringV1 takes an entire program in a string and assembles it to bytecode using TEAL v1
func AssembleStringV1(text string) ([]byte, error) {
	return AssembleStringWithVersion(text, 1)
}

// AssembleStringV2 takes an entire program in a string and assembles it to bytecode using TEAL v2
func AssembleStringV2(text string) ([]byte, error) {
	return AssembleStringWithVersion(text, 2)
}

// AssembleStringWithVersion takes an entire program in a string and assembles it to bytecode using the assembler version specified
func AssembleStringWithVersion(text string, version uint64) ([]byte, error) {
	program, _, err := AssembleStringWithVersionEx(text, version)
	return program, err
}

// AssembleStringWithVersionEx takes an entire program in a string and assembles it to bytecode
// using the assembler version specified.
// If version is assemblerNoVersion it uses #pragma version or fallbacks to AssemblerDefaultVersion.
// It also returns PC to source line mapping.
func AssembleStringWithVersionEx(text string, version uint64) ([]byte, map[int]int, error) {
	sr := strings.NewReader(text)
	ps := PragmaStream{}
	err := ps.Process(sr)
	if err != nil {
		return nil, nil, err
	}
	// If version not set yet then set either default or #pragma version.
	// We have to use assemblerNoVersion as a marker for non-specified version
	// because version 0 is valid version for TEAL v1
	if version == assemblerNoVersion {
		if ps.Version != 0 {
			version = ps.Version
		} else {
			version = AssemblerDefaultVersion
		}
	} else if ps.Version != 0 && version != ps.Version {
		err = fmt.Errorf("version mismatch: assembling v%d with v%d assembler", ps.Version, version)
		return nil, nil, err
	} else {
		// otherwise the passed version matches the pragma and we are ok
	}

	sr = strings.NewReader(text)
	ops := OpStream{Version: version}
	err = ops.assemble(sr)
	if err != nil {
		return nil, nil, err
	}
	program, err := ops.Bytes()
	return program, ops.offsetToLine, err
}

// PragmaStream represents all parsed pragmas from the program
type PragmaStream struct {
	Version uint64
}

// Process all pragmas in the input stream
func (ps *PragmaStream) Process(fin io.Reader) (err error) {
	scanner := bufio.NewScanner(fin)
	sourceLine := 0
	for scanner.Scan() {
		sourceLine++
		line := scanner.Text()
		if len(line) == 0 || !strings.HasPrefix(line, "#pragma") {
			continue
		}

		fields := strings.Split(line, " ")
		if fields[0] != "#pragma" {
			return fmtLineError(sourceLine, "invalid syntax: %s", fields[0])
		}
		if len(fields) < 2 {
			return newLineError(sourceLine, "empty pragma")
		}
		key := fields[1]
		switch key {
		case "version":
			if len(fields) < 3 {
				return newLineError(sourceLine, "no version value")
			}
			value := fields[2]
			var ver uint64
			if sourceLine != 1 {
				return newLineError(sourceLine, "#pragma version is only allowed on 1st line")
			}
			ver, err = strconv.ParseUint(value, 0, 64)
			if err != nil {
				return addLine(sourceLine, err)
			}
			if ver < 1 || ver > AssemblerMaxVersion {
				return fmtLineError(sourceLine, "unsupported version: %d", ver)
			}
			ps.Version = ver
		default:
			return fmtLineError(sourceLine, "unsupported pragma directive: %s", key)
		}
	}
	return
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

func disDefault(dis *disassembleState, spec *OpSpec) {
	dis.nextpc = dis.pc + 1
	_, dis.err = fmt.Fprintf(dis.out, "%s\n", spec.Name)
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

func disIntc(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	dis.nextpc = dis.pc + 2
	_, dis.err = fmt.Fprintf(dis.out, "intc %d\n", dis.program[dis.pc+1])
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

func disBytec(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	dis.nextpc = dis.pc + 2
	_, dis.err = fmt.Fprintf(dis.out, "bytec %d\n", dis.program[dis.pc+1])
}

func disArg(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	dis.nextpc = dis.pc + 2
	_, dis.err = fmt.Fprintf(dis.out, "arg %d\n", dis.program[dis.pc+1])
}

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
	_, dis.err = fmt.Fprintf(dis.out, "txn %s\n", TxnFieldNames[txarg])
}

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
	_, dis.err = fmt.Fprintf(dis.out, "txna %s %d\n", TxnFieldNames[txarg], arrayFieldIdx)
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

func disLoad(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	n := uint(dis.program[dis.pc+1])
	dis.nextpc = dis.pc + 2
	_, dis.err = fmt.Fprintf(dis.out, "load %d\n", n)
}

func disStore(dis *disassembleState, spec *OpSpec) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		dis.err = fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
		return
	}
	n := uint(dis.program[dis.pc+1])
	dis.nextpc = dis.pc + 2
	_, dis.err = fmt.Fprintf(dis.out, "store %d\n", n)
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
