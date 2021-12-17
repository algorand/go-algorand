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
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/data/basics"
)

// optimizeConstantsEnabledVersion is the first version of TEAL where the
// assembler optimizes constants introduced by pseudo-ops
const optimizeConstantsEnabledVersion = 4

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

type constReference interface {
	// get the referenced value
	getValue() interface{}

	// check if the referenced value equals other. Other must be the same type
	valueEquals(other interface{}) bool

	// get the index into ops.pending where the opcode for this reference is located
	getPosition() int

	// get the length of the op for this reference in ops.pending
	length(ops *OpStream, assembled []byte) (int, error)

	// create the opcode bytes for a new reference of the same value
	makeNewReference(ops *OpStream, singleton bool, newIndex int) []byte
}

type intReference struct {
	value uint64

	// position of the opcode start that declares the int value
	position int
}

func (ref intReference) getValue() interface{} {
	return ref.value
}

func (ref intReference) valueEquals(other interface{}) bool {
	return ref.value == other.(uint64)
}

func (ref intReference) getPosition() int {
	return ref.position
}

func (ref intReference) length(ops *OpStream, assembled []byte) (int, error) {
	opIntc0 := OpsByName[ops.Version]["intc_0"].Opcode
	opIntc1 := OpsByName[ops.Version]["intc_1"].Opcode
	opIntc2 := OpsByName[ops.Version]["intc_2"].Opcode
	opIntc3 := OpsByName[ops.Version]["intc_3"].Opcode
	opIntc := OpsByName[ops.Version]["intc"].Opcode

	switch assembled[ref.position] {
	case opIntc0, opIntc1, opIntc2, opIntc3:
		return 1, nil
	case opIntc:
		return 2, nil
	default:
		return 0, ops.lineErrorf(ops.OffsetToLine[ref.position], "Unexpected op at intReference: %d", assembled[ref.position])
	}
}

func (ref intReference) makeNewReference(ops *OpStream, singleton bool, newIndex int) []byte {
	opIntc0 := OpsByName[ops.Version]["intc_0"].Opcode
	opIntc1 := OpsByName[ops.Version]["intc_1"].Opcode
	opIntc2 := OpsByName[ops.Version]["intc_2"].Opcode
	opIntc3 := OpsByName[ops.Version]["intc_3"].Opcode
	opIntc := OpsByName[ops.Version]["intc"].Opcode
	opPushInt := OpsByName[ops.Version]["pushint"].Opcode

	if singleton {
		var scratch [binary.MaxVarintLen64]byte
		vlen := binary.PutUvarint(scratch[:], ref.value)

		newBytes := make([]byte, 1+vlen)
		newBytes[0] = opPushInt
		copy(newBytes[1:], scratch[:vlen])

		return newBytes
	}

	switch newIndex {
	case 0:
		return []byte{opIntc0}
	case 1:
		return []byte{opIntc1}
	case 2:
		return []byte{opIntc2}
	case 3:
		return []byte{opIntc3}
	default:
		return []byte{opIntc, uint8(newIndex)}
	}
}

type byteReference struct {
	value []byte

	// position of the opcode start that declares the byte value
	position int
}

func (ref byteReference) getValue() interface{} {
	return ref.value
}

func (ref byteReference) valueEquals(other interface{}) bool {
	return bytes.Equal(ref.value, other.([]byte))
}

func (ref byteReference) getPosition() int {
	return ref.position
}

func (ref byteReference) length(ops *OpStream, assembled []byte) (int, error) {
	opBytec0 := OpsByName[ops.Version]["bytec_0"].Opcode
	opBytec1 := OpsByName[ops.Version]["bytec_1"].Opcode
	opBytec2 := OpsByName[ops.Version]["bytec_2"].Opcode
	opBytec3 := OpsByName[ops.Version]["bytec_3"].Opcode
	opBytec := OpsByName[ops.Version]["bytec"].Opcode

	switch assembled[ref.position] {
	case opBytec0, opBytec1, opBytec2, opBytec3:
		return 1, nil
	case opBytec:
		return 2, nil
	default:
		return 0, ops.lineErrorf(ops.OffsetToLine[ref.position], "Unexpected op at byteReference: %d", assembled[ref.position])
	}
}

func (ref byteReference) makeNewReference(ops *OpStream, singleton bool, newIndex int) []byte {
	opBytec0 := OpsByName[ops.Version]["bytec_0"].Opcode
	opBytec1 := OpsByName[ops.Version]["bytec_1"].Opcode
	opBytec2 := OpsByName[ops.Version]["bytec_2"].Opcode
	opBytec3 := OpsByName[ops.Version]["bytec_3"].Opcode
	opBytec := OpsByName[ops.Version]["bytec"].Opcode
	opPushBytes := OpsByName[ops.Version]["pushbytes"].Opcode

	if singleton {
		var scratch [binary.MaxVarintLen64]byte
		vlen := binary.PutUvarint(scratch[:], uint64(len(ref.value)))

		newBytes := make([]byte, 1+vlen+len(ref.value))
		newBytes[0] = opPushBytes
		copy(newBytes[1:], scratch[:vlen])
		copy(newBytes[1+vlen:], ref.value)

		return newBytes
	}

	switch newIndex {
	case 0:
		return []byte{opBytec0}
	case 1:
		return []byte{opBytec1}
	case 2:
		return []byte{opBytec2}
	case 3:
		return []byte{opBytec3}
	default:
		return []byte{opBytec, uint8(newIndex)}
	}
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

	intc         []uint64       // observed ints in code. We'll put them into a intcblock
	intcRefs     []intReference // references to int pseudo-op constants, used for optimization
	hasIntcBlock bool           // prevent prepending intcblock because asm has one

	bytec         [][]byte        // observed bytes in code. We'll put them into a bytecblock
	bytecRefs     []byteReference // references to byte/addr pseudo-op constants, used for optimization
	hasBytecBlock bool            // prevent prepending bytecblock because asm has one

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

	HasStatefulOps bool
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
		ops.errorf("duplicate label %#v", label)
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

type opTypeFunc func(ops *OpStream, immediates []string) (StackTypes, StackTypes)

// returns allows opcodes like `txn` to be specific about their return
// value types, based on the field requested, rather than use Any as
// specified by opSpec.
func (ops *OpStream) returns(argTypes ...StackType) {
	for range argTypes {
		ops.tpop()
	}
	ops.tpusha(argTypes)
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
	ops.intcRefs = append(ops.intcRefs, intReference{
		value:    val,
		position: ops.pending.Len(),
	})
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
		if bytes.Equal(cv, val) {
			found = true
			constIndex = uint(i)
			break
		}
	}
	if !found {
		constIndex = uint(len(ops.bytec))
		ops.bytec = append(ops.bytec, val)
	}
	ops.bytecRefs = append(ops.bytecRefs, byteReference{
		value:    val,
		position: ops.pending.Len(),
	})
	ops.Bytec(constIndex)
}

func assembleInt(ops *OpStream, spec *OpSpec, args []string) error {
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
	if len(args) != 1 {
		return ops.error("bytec operation needs one argument")
	}
	constIndex, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	ops.Bytec(uint(constIndex))
	return nil
}

func asmPushInt(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s needs one argument", spec.Name)
	}
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	ops.pending.WriteByte(spec.Opcode)
	var scratch [binary.MaxVarintLen64]byte
	vlen := binary.PutUvarint(scratch[:], val)
	ops.pending.Write(scratch[:vlen])
	return nil
}
func asmPushBytes(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 0 {
		return ops.errorf("%s operation needs byte literal argument", spec.Name)
	}
	val, consumed, err := parseBinaryArgs(args)
	if err != nil {
		return ops.error(err)
	}
	if len(args) != consumed {
		return ops.errorf("%s operation with extraneous argument", spec.Name)
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
	if len(args) == 0 {
		return ops.errorf("%s operation needs byte literal argument", spec.Name)
	}
	val, consumed, err := parseBinaryArgs(args)
	if err != nil {
		return ops.error(err)
	}
	if len(args) != consumed {
		return ops.errorf("%s operation with extraneous argument", spec.Name)
	}
	ops.ByteLiteral(val)
	return nil
}

// method "add(uint64,uint64)uint64"
func assembleMethod(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 0 {
		return ops.error("method requires a literal argument")
	}
	arg := args[0]
	if len(arg) > 1 && arg[0] == '"' && arg[len(arg)-1] == '"' {
		val, err := parseStringLiteral(arg)
		if err != nil {
			return ops.error(err)
		}
		hash := sha512.Sum512_256(val)
		ops.ByteLiteral(hash[0:4])
		return nil
	}
	return ops.error("Unable to parse method signature")
}

func assembleIntCBlock(ops *OpStream, spec *OpSpec, args []string) error {
	ops.pending.WriteByte(spec.Opcode)
	var scratch [binary.MaxVarintLen64]byte
	l := binary.PutUvarint(scratch[:], uint64(len(args)))
	ops.pending.Write(scratch[:l])
	ops.intcRefs = nil
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
	ops.hasIntcBlock = true
	return nil
}

func assembleByteCBlock(ops *OpStream, spec *OpSpec, args []string) error {
	ops.pending.WriteByte(spec.Opcode)
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
	ops.bytecRefs = nil
	ops.bytec = bvals
	ops.hasBytecBlock = true
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
		return ops.error(err)
	}
	ops.ByteLiteral(addr[:])
	return nil
}

func assembleArg(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.error("arg operation needs one argument")
	}
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	altSpec := *spec
	if val < 4 {
		switch val {
		case 0:
			altSpec = OpsByName[ops.Version]["arg_0"]
		case 1:
			altSpec = OpsByName[ops.Version]["arg_1"]
		case 2:
			altSpec = OpsByName[ops.Version]["arg_2"]
		case 3:
			altSpec = OpsByName[ops.Version]["arg_3"]
		}
		args = []string{}
	}
	return asmDefault(ops, &altSpec, args)
}

func assembleBranch(ops *OpStream, spec *OpSpec, args []string) error {
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
	err := asmDefault(ops, spec, args)
	if err != nil {
		return err
	}
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
		return ops.errorf("txn unknown field: %#v", args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if ok {
		return ops.errorf("found array field %#v in txn op", args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("field %#v available in version %d. Missed #pragma version?", args[0], fs.version)
	}
	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(fs.field))
	ops.returns(fs.ftype)
	return nil
}

// assembleTxn2 delegates to assembleTxn or assembleTxna depending on number of operands
func assembleTxn2(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 1 {
		return assembleTxn(ops, spec, args)
	}
	if len(args) == 2 {
		txna := OpsByName[ops.Version]["txna"]
		return assembleTxna(ops, &txna, args)
	}
	return ops.error("txn expects one or two arguments")
}

func assembleTxna(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 2 {
		return ops.error("txna expects two immediate arguments")
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("txna unknown field: %#v", args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if !ok {
		return ops.errorf("txna unknown field: %#v", args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("txna %#v available in version %d. Missed #pragma version?", args[0], fs.version)
	}
	arrayFieldIdx, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	if arrayFieldIdx > 255 {
		return ops.errorf("txna array index beyond 255: %d", arrayFieldIdx)
	}

	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(fs.field))
	ops.pending.WriteByte(uint8(arrayFieldIdx))
	ops.returns(fs.ftype)
	return nil
}

func assembleTxnas(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.error("txnas expects one immediate argument")
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("txnas unknown field: %#v", args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if !ok {
		return ops.errorf("txnas unknown field: %#v", args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("txnas %#v available in version %d. Missed #pragma version?", args[0], fs.version)
	}

	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(fs.field))
	ops.returns(fs.ftype)
	return nil
}

func assembleGtxn(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 2 {
		return ops.error("gtxn expects two arguments")
	}
	slot, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	if slot > 255 {
		return ops.errorf("%s transaction index beyond 255: %d", spec.Name, slot)
	}

	fs, ok := txnFieldSpecByName[args[1]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[1])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if ok {
		return ops.errorf("found array field %#v in %s op", args[1], spec.Name)
	}
	if fs.version > ops.Version {
		return ops.errorf("field %#v available in version %d. Missed #pragma version?", args[1], fs.version)
	}

	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(slot))
	ops.pending.WriteByte(uint8(fs.field))
	ops.returns(fs.ftype)
	return nil
}

func assembleGtxn2(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 2 {
		return assembleGtxn(ops, spec, args)
	}
	if len(args) == 3 {
		gtxna := OpsByName[ops.Version]["gtxna"]
		return assembleGtxna(ops, &gtxna, args)
	}
	return ops.errorf("%s expects two or three arguments", spec.Name)
}

func assembleGtxna(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 3 {
		return ops.errorf("%s expects three arguments", spec.Name)
	}
	slot, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	if slot > 255 {
		return ops.errorf("%s group index beyond 255: %d", spec.Name, slot)
	}

	fs, ok := txnFieldSpecByName[args[1]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[1])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[1])
	}
	if fs.version > ops.Version {
		return ops.errorf("%s %#v available in version %d. Missed #pragma version?", spec.Name, args[1], fs.version)
	}
	arrayFieldIdx, err := strconv.ParseUint(args[2], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	if arrayFieldIdx > 255 {
		return ops.errorf("%s array index beyond 255: %d", spec.Name, arrayFieldIdx)
	}

	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(slot))
	ops.pending.WriteByte(uint8(fs.field))
	ops.pending.WriteByte(uint8(arrayFieldIdx))
	ops.returns(fs.ftype)
	return nil
}

func assembleGtxnas(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 2 {
		return ops.errorf("%s expects two immediate arguments", spec.Name)
	}

	slot, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	if slot > 255 {
		return ops.errorf("%s group index beyond 255: %d", spec.Name, slot)
	}

	fs, ok := txnFieldSpecByName[args[1]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[1])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[1])
	}
	if fs.version > ops.Version {
		return ops.errorf("%s %#v available in version %d. Missed #pragma version?", spec.Name, args[1], fs.version)
	}

	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(slot))
	ops.pending.WriteByte(uint8(fs.field))
	ops.returns(fs.ftype)
	return nil
}

func assembleGtxns(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 2 {
		gtxnsa := OpsByName[ops.Version]["gtxnsa"]
		return assembleGtxnsa(ops, &gtxnsa, args)
	}
	if len(args) != 1 {
		return ops.errorf("%s expects one or two immediate arguments", spec.Name)
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if ok {
		return ops.errorf("found array field %#v in gtxns op", args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("field %#v available in version %d. Missed #pragma version?", args[0], fs.version)
	}

	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(fs.field))
	ops.returns(fs.ftype)
	return nil
}

func assembleGtxnsa(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 2 {
		return ops.errorf("%s expects two immediate arguments", spec.Name)
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("%s %#v available in version %d. Missed #pragma version?", spec.Name, args[0], fs.version)
	}
	arrayFieldIdx, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	if arrayFieldIdx > 255 {
		return ops.errorf("%s array index beyond 255: %d", spec.Name, arrayFieldIdx)
	}
	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(fs.field))
	ops.pending.WriteByte(uint8(arrayFieldIdx))
	ops.returns(fs.ftype)
	return nil
}

func assembleGtxnsas(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s expects one immediate argument", spec.Name)
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("%s %#v available in version %d. Missed #pragma version?", spec.Name, args[0], fs.version)
	}
	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(fs.field))
	ops.returns(fs.ftype)
	return nil
}

// asmItxn delegates to asmItxnOnly or asmItxna depending on number of operands
func asmItxn(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 1 {
		return asmItxnOnly(ops, spec, args)
	}
	if len(args) == 2 {
		itxna := OpsByName[ops.Version]["itxna"]
		return asmItxna(ops, &itxna, args)
	}
	return ops.errorf("%s expects one or two arguments", spec.Name)
}

func asmItxnOnly(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s expects one argument", spec.Name)
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if ok {
		return ops.errorf("found array field %#v in %s op", args[0], spec.Name)
	}
	if fs.version > ops.Version {
		return ops.errorf("field %#v available in version %d. Missed #pragma version?", args[0], fs.version)
	}
	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(fs.field))
	ops.returns(fs.ftype)
	return nil
}

func asmItxna(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 2 {
		return ops.errorf("%s expects two immediate arguments", spec.Name)
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	if fs.version > ops.Version {
		return ops.errorf("%s %#v available in version %d. Missed #pragma version?", spec.Name, args[0], fs.version)
	}
	arrayFieldIdx, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	if arrayFieldIdx > 255 {
		return ops.errorf("%s array index beyond 255: %d", spec.Name, arrayFieldIdx)
	}

	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(fs.field))
	ops.pending.WriteByte(uint8(arrayFieldIdx))
	ops.returns(fs.ftype)
	return nil
}

func assembleGlobal(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s expects one argument", spec.Name)
	}
	fs, ok := globalFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	if fs.version > ops.Version {
		//nolint:errcheck // we continue to maintain typestack
		ops.errorf("%s %s available in version %d. Missed #pragma version?", spec.Name, args[0], fs.version)
	}

	val := fs.field
	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(val))
	ops.trace("%s (%s)", fs.field.String(), fs.ftype.String())
	ops.returns(fs.ftype)
	return nil
}

func assembleAssetHolding(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s expects one argument", spec.Name)
	}
	fs, ok := assetHoldingFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	if fs.version > ops.Version {
		//nolint:errcheck // we continue to maintain typestack
		ops.errorf("%s %s available in version %d. Missed #pragma version?", spec.Name, args[0], fs.version)
	}

	val := fs.field
	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(val))
	ops.trace("%s (%s)", fs.field.String(), fs.ftype.String())
	ops.returns(fs.ftype, StackUint64)
	return nil
}

func assembleAssetParams(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s expects one argument", spec.Name)
	}
	fs, ok := assetParamsFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	if fs.version > ops.Version {
		//nolint:errcheck // we continue to maintain typestack
		ops.errorf("%s %s available in version %d. Missed #pragma version?", spec.Name, args[0], fs.version)
	}

	val := fs.field
	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(val))
	ops.trace("%s (%s)", fs.field.String(), fs.ftype.String())
	ops.returns(fs.ftype, StackUint64)
	return nil
}

func assembleAppParams(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s expects one argument", spec.Name)
	}
	fs, ok := appParamsFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	if fs.version > ops.Version {
		//nolint:errcheck // we continue to maintain typestack
		ops.errorf("%s %s available in version %d. Missed #pragma version?", spec.Name, args[0], fs.version)
	}

	val := fs.field
	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(val))
	ops.trace("%s (%s)", fs.field.String(), fs.ftype.String())
	ops.returns(fs.ftype, StackUint64)
	return nil
}

func asmTxField(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s expects one argument", spec.Name)
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("txn unknown field: %#v", args[0])
	}
	_, ok = txnaFieldSpecByField[fs.field]
	if ok {
		return ops.errorf("found array field %#v in %s op", args[0], spec.Name)
	}
	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(fs.field))
	return nil
}

func assembleEcdsa(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s expects one argument", spec.Name)
	}

	cs, ok := ecdsaCurveSpecByName[args[0]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	if cs.version > ops.Version {
		//nolint:errcheck // we continue to maintain typestack
		ops.errorf("%s %s available in version %d. Missed #pragma version?", spec.Name, args[0], cs.version)
	}

	val := cs.field
	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(val))
	return nil
}

func assembleBase64Decode(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s expects one argument", spec.Name)
	}

	encoding, ok := base64EncodingSpecByName[args[0]]
	if !ok {
		return ops.errorf("%s unknown encoding: %#v", spec.Name, args[0])
	}
	if encoding.version > ops.Version {
		//nolint:errcheck // we continue to maintain typestack
		ops.errorf("%s %s available in version %d. Missed #pragma version?", spec.Name, args[0], encoding.version)
	}

	val := encoding.field
	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(uint8(val))
	ops.trace("%s (%s)", encoding.field, encoding.ftype)
	ops.returns(encoding.ftype)
	return nil
}

type assembleFunc func(*OpStream, *OpSpec, []string) error

// Basic assembly. Any extra bytes of opcode are encoded as byte immediates.
func asmDefault(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != spec.Details.Size-1 {
		return ops.errorf("%s expects %d immediate arguments", spec.Name, spec.Details.Size-1)
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

func typeSwap(ops *OpStream, args []string) (StackTypes, StackTypes) {
	topTwo := oneAny.plus(oneAny)
	top := len(ops.typeStack) - 1
	if top >= 0 {
		topTwo[1] = ops.typeStack[top]
		if top >= 1 {
			topTwo[0] = ops.typeStack[top-1]
		}
	}
	reversed := StackTypes{topTwo[1], topTwo[0]}
	return topTwo, reversed
}

func typeDig(ops *OpStream, args []string) (StackTypes, StackTypes) {
	if len(args) == 0 {
		return oneAny, oneAny
	}
	n, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return oneAny, oneAny
	}
	depth := int(n) + 1
	anys := make(StackTypes, depth)
	for i := range anys {
		anys[i] = StackAny
	}
	returns := anys.plus(oneAny)
	idx := len(ops.typeStack) - depth
	if idx >= 0 {
		returns[len(returns)-1] = ops.typeStack[idx]
		for i := idx; i < len(ops.typeStack); i++ {
			returns[i-idx] = ops.typeStack[i]
		}
	}
	return anys, returns
}

func typeEquals(ops *OpStream, args []string) (StackTypes, StackTypes) {
	top := len(ops.typeStack) - 1
	if top >= 0 {
		//Require arg0 and arg1 to have same type
		return StackTypes{ops.typeStack[top], ops.typeStack[top]}, oneInt
	}
	return oneAny.plus(oneAny), oneInt
}

func typeDup(ops *OpStream, args []string) (StackTypes, StackTypes) {
	top := len(ops.typeStack) - 1
	if top >= 0 {
		return StackTypes{ops.typeStack[top]}, StackTypes{ops.typeStack[top], ops.typeStack[top]}
	}
	return StackTypes{StackAny}, oneAny.plus(oneAny)
}

func typeDupTwo(ops *OpStream, args []string) (StackTypes, StackTypes) {
	topTwo := oneAny.plus(oneAny)
	top := len(ops.typeStack) - 1
	if top >= 0 {
		topTwo[1] = ops.typeStack[top]
		if top >= 1 {
			topTwo[0] = ops.typeStack[top-1]
		}
	}
	result := topTwo.plus(topTwo)
	return topTwo, result
}

func typeSelect(ops *OpStream, args []string) (StackTypes, StackTypes) {
	selectArgs := twoAny.plus(oneInt)
	top := len(ops.typeStack) - 1
	if top >= 2 {
		if ops.typeStack[top-1] == ops.typeStack[top-2] {
			return selectArgs, StackTypes{ops.typeStack[top-1]}
		}
	}
	return selectArgs, StackTypes{StackAny}
}

func typeSetBit(ops *OpStream, args []string) (StackTypes, StackTypes) {
	setBitArgs := oneAny.plus(twoInts)
	top := len(ops.typeStack) - 1
	if top >= 2 {
		return setBitArgs, StackTypes{ops.typeStack[top-2]}
	}
	return setBitArgs, StackTypes{StackAny}
}

func typeCover(ops *OpStream, args []string) (StackTypes, StackTypes) {
	if len(args) == 0 {
		return oneAny, oneAny
	}
	n, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return oneAny, oneAny
	}
	depth := int(n) + 1
	anys := make(StackTypes, depth)
	for i := range anys {
		anys[i] = StackAny
	}
	returns := make(StackTypes, depth)
	for i := range returns {
		returns[i] = StackAny
	}
	idx := len(ops.typeStack) - depth
	if idx >= 0 {
		sv := ops.typeStack[len(ops.typeStack)-1]
		for i := idx; i < len(ops.typeStack)-1; i++ {
			returns[i-idx+1] = ops.typeStack[i]
		}
		returns[len(returns)-depth] = sv
	}
	return anys, returns
}

func typeUncover(ops *OpStream, args []string) (StackTypes, StackTypes) {
	if len(args) == 0 {
		return oneAny, oneAny
	}
	n, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return oneAny, oneAny
	}
	depth := int(n) + 1
	anys := make(StackTypes, depth)
	for i := range anys {
		anys[i] = StackAny
	}
	returns := make(StackTypes, depth)
	for i := range returns {
		returns[i] = StackAny
	}
	idx := len(ops.typeStack) - depth
	if idx >= 0 {
		sv := ops.typeStack[idx]
		for i := idx + 1; i < len(ops.typeStack); i++ {
			returns[i-idx-1] = ops.typeStack[i]
		}
		returns[len(returns)-1] = sv
	}
	return anys, returns
}

func typeTxField(ops *OpStream, args []string) (StackTypes, StackTypes) {
	if len(args) != 1 {
		return oneAny, nil
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return oneAny, nil
	}
	return StackTypes{fs.ftype}, nil
}

// keywords handle parsing and assembling special asm language constructs like 'addr'
// We use OpSpec here, but somewhat degenerate, since they don't have opcodes or eval functions
var keywords = map[string]OpSpec{
	"int":  {0, "int", nil, assembleInt, nil, nil, oneInt, 1, modeAny, opDetails{1, 2, nil, nil, nil}},
	"byte": {0, "byte", nil, assembleByte, nil, nil, oneBytes, 1, modeAny, opDetails{1, 2, nil, nil, nil}},
	// parse basics.Address, actually just another []byte constant
	"addr": {0, "addr", nil, assembleAddr, nil, nil, oneBytes, 1, modeAny, opDetails{1, 2, nil, nil, nil}},
	// take a signature, hash it, and take first 4 bytes, actually just another []byte constant
	"method": {0, "method", nil, assembleMethod, nil, nil, oneBytes, 1, modeAny, opDetails{1, 2, nil, nil, nil}},
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
func (ops *OpStream) checkStack(args StackTypes, returns StackTypes, instruction []string) {
	argcount := len(args)
	if argcount > len(ops.typeStack) {
		err := fmt.Errorf("%s expects %d stack arguments but stack height is %d", strings.Join(instruction, " "), argcount, len(ops.typeStack))
		if len(ops.labelReferences) > 0 {
			ops.warnf("%w; but branches have happened and assembler does not precisely track the stack in this case", err)
		} else {
			ops.error(err)
		}
	} else {
		firstPop := true
		for i := argcount - 1; i >= 0; i-- {
			argType := args[i]
			stype := ops.tpop()
			if firstPop {
				firstPop = false
				ops.trace("pops(%s", argType.String())
			} else {
				ops.trace(", %s", argType.String())
			}
			if !typecheck(argType, stype) {
				err := fmt.Errorf("%s arg %d wanted type %s got %s", strings.Join(instruction, " "), i, argType.String(), stype.String())
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
	}

	if len(returns) > 0 {
		ops.tpusha(returns)
		ops.trace(" pushes(%s", returns[0].String())
		if len(returns) > 1 {
			for _, rt := range returns[1:] {
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
		line = strings.TrimSpace(line)
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
		// we're about to begin processing opcodes, so fix the Version
		if ops.Version == assemblerNoVersion {
			ops.Version = AssemblerDefaultVersion
		}
		opstring := fields[0]

		if opstring[len(opstring)-1] == ':' {
			ops.createLabel(opstring[:len(opstring)-1])
			fields = fields[1:]
			if len(fields) == 0 {
				// There was a label, not need to ops.trace this
				continue
			}
			opstring = fields[0]
		}

		spec, ok := OpsByName[ops.Version][opstring]
		if !ok {
			spec, ok = keywords[opstring]
			if spec.Version > 1 && spec.Version > ops.Version {
				ok = false
			}
		}
		if ok {
			ops.trace("%3d: %s\t", ops.sourceLine, opstring)
			ops.RecordSourceLine()
			if spec.Modes == runModeApplication {
				ops.HasStatefulOps = true
			}
			args, returns := spec.Args, spec.Returns
			if spec.Details.typeFunc != nil {
				args, returns = spec.Details.typeFunc(ops, fields[1:])
			}
			ops.checkStack(args, returns, fields)
			spec.asm(ops, &spec, fields[1:])
			ops.trace("\n")
			continue
		}
		// unknown opcode, let's report a good error if version problem
		spec, ok = OpsByName[AssemblerMaxVersion][opstring]
		if !ok {
			spec, ok = keywords[opstring]
		}
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
				ops.errorf("label %#v is too far away", label)
			}
		}
	}

	if ops.Version >= optimizeConstantsEnabledVersion {
		ops.optimizeIntcBlock()
		ops.optimizeBytecBlock()
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

		// We initialize Version with assemblerNoVersion as a marker for
		// non-specified version because version 0 is valid
		// version for TEAL v1.
		if ops.Version == assemblerNoVersion {
			ops.Version = ver
		} else if ops.Version != ver {
			return ops.errorf("version mismatch: assembling v%d with v%d assembler", ver, ops.Version)
		} else {
			// ops.Version is already correct, or needed to be upped.
		}
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
				ops.errorf("reference to undefined label %#v", lr.label)
			}
			reported[lr.label] = true
			continue
		}
		// all branch instructions (currently) are opcode byte and 2 offset bytes, and the destination is relative to the next pc as if the branch was a no-op
		naturalPc := lr.position + 3
		if ops.Version < backBranchEnabledVersion && dest < naturalPc {
			ops.errorf("label %#v is a back reference, back jump support was introduced in TEAL v4", lr.label)
			continue
		}
		jump := dest - naturalPc
		if jump > 0x7fff {
			ops.errorf("label %#v is too far away", lr.label)
			continue
		}
		raw[lr.position+1] = uint8(jump >> 8)
		raw[lr.position+2] = uint8(jump & 0x0ff)
	}
	ops.pending = *bytes.NewBuffer(raw)
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

// replaceBytes returns a slice that is the same as s, except the range starting
// at index with length originalLen is replaced by newBytes. The returned slice
// may be the same as s, or it may be a new slice
func replaceBytes(s []byte, index, originalLen int, newBytes []byte) []byte {
	prefix := s[:index]
	suffix := s[index+originalLen:]

	// if we can fit the new bytes into the existing slice, no need to create a
	// new one
	if len(newBytes) <= originalLen {
		copy(s[index:], newBytes)
		copy(s[index+len(newBytes):], suffix)
		return s[:len(s)+len(newBytes)-originalLen]
	}

	replaced := make([]byte, len(prefix)+len(newBytes)+len(suffix))
	copy(replaced, prefix)
	copy(replaced[index:], newBytes)
	copy(replaced[index+len(newBytes):], suffix)

	return replaced
}

// optimizeIntcBlock rewrites the existing intcblock and the ops that reference
// it to reduce code size. This is achieved by ordering the intcblock from most
// frequently referenced constants to least frequently referenced, since the
// first 4 constant can use the intc_X ops to save space. Additionally, any
// ints with a reference of 1 are taken out of the intcblock and instead created
// with the pushint op.
//
// This function only optimizes constants introduces by the int pseudo-op, not
// preexisting intcblocks in the code.
func (ops *OpStream) optimizeIntcBlock() error {
	if ops.hasIntcBlock {
		// don't optimize an existing intcblock, only int pseudo-ops
		return nil
	}

	constBlock := make([]interface{}, len(ops.intc))
	for i, value := range ops.intc {
		constBlock[i] = value
	}

	constRefs := make([]constReference, len(ops.intcRefs))
	for i, ref := range ops.intcRefs {
		constRefs[i] = ref
	}

	// remove all intcRefs here so that optimizeConstants does not alter them
	// when it fixes indexes into ops.pending
	ops.intcRefs = nil

	optimizedIntc, err := ops.optimizeConstants(constRefs, constBlock)

	if err != nil {
		return err
	}

	ops.intc = make([]uint64, len(optimizedIntc))
	for i, value := range optimizedIntc {
		ops.intc[i] = value.(uint64)
	}

	return nil
}

// optimizeBytecBlock rewrites the existing bytecblock and the ops that
// reference it to reduce code size. This is achieved by ordering the bytecblock
// from most frequently referenced constants to least frequently referenced,
// since the first 4 constant can use the bytec_X ops to save space.
// Additionally, any bytes with a reference of 1 are taken out of the bytecblock
// and instead created with the pushbytes op.
//
// This function only optimizes constants introduces by the byte or addr
// pseudo-ops, not preexisting bytecblocks in the code.
func (ops *OpStream) optimizeBytecBlock() error {
	if ops.hasBytecBlock {
		// don't optimize an existing bytecblock, only byte/addr pseudo-ops
		return nil
	}

	constBlock := make([]interface{}, len(ops.bytec))
	for i, value := range ops.bytec {
		constBlock[i] = value
	}

	constRefs := make([]constReference, len(ops.bytecRefs))
	for i, ref := range ops.bytecRefs {
		constRefs[i] = ref
	}

	// remove all bytecRefs here so that optimizeConstants does not alter them
	// when it fixes indexes into ops.pending
	ops.bytecRefs = nil

	optimizedBytec, err := ops.optimizeConstants(constRefs, constBlock)

	if err != nil {
		return err
	}

	ops.bytec = make([][]byte, len(optimizedBytec))
	for i, value := range optimizedBytec {
		ops.bytec[i] = value.([]byte)
	}

	return nil
}

// optimizeConstants optimizes a given constant block and the ops that reference
// it to reduce code size. This is achieved by ordering the constant block from
// most frequently referenced constants to least frequently referenced, since
// the first 4 constant can use a special opcode to save space. Additionally,
// any constants with a reference of 1 are taken out of the constant block and
// instead referenced with an immediate op.
func (ops *OpStream) optimizeConstants(refs []constReference, constBlock []interface{}) (optimizedConstBlock []interface{}, err error) {
	type constFrequency struct {
		value interface{}
		freq  int
	}

	freqs := make([]constFrequency, len(constBlock))

	for i, value := range constBlock {
		freqs[i].value = value
	}

	for _, ref := range refs {
		found := false
		for i := range freqs {
			if ref.valueEquals(freqs[i].value) {
				freqs[i].freq++
				found = true
				break
			}
		}
		if !found {
			err = ops.lineErrorf(ops.OffsetToLine[ref.getPosition()], "Value not found in constant block: %v", ref.getValue())
			return
		}
	}

	for _, f := range freqs {
		if f.freq == 0 {
			err = ops.errorf("Member of constant block is not used: %v", f.value)
			return
		}
	}

	// sort values by greatest to smallest frequency
	// since we're using a stable sort, constants with the same frequency
	// will retain their current ordering (i.e. first referenced, first in constant block)
	sort.SliceStable(freqs, func(i, j int) bool {
		return freqs[i].freq > freqs[j].freq
	})

	// sort refs from last to first
	// this way when we iterate through them and potentially change the size of the assembled
	// program, the later positions will not affect the indexes of the earlier positions
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].getPosition() > refs[j].getPosition()
	})

	raw := ops.pending.Bytes()
	for _, ref := range refs {
		singleton := false
		newIndex := -1
		for i, f := range freqs {
			if ref.valueEquals(f.value) {
				singleton = f.freq == 1
				newIndex = i
				break
			}
		}
		if newIndex == -1 {
			return nil, ops.lineErrorf(ops.OffsetToLine[ref.getPosition()], "Value not found in constant block: %v", ref.getValue())
		}

		newBytes := ref.makeNewReference(ops, singleton, newIndex)
		var currentBytesLen int
		currentBytesLen, err = ref.length(ops, raw)
		if err != nil {
			return
		}

		positionDelta := len(newBytes) - currentBytesLen
		position := ref.getPosition()
		raw = replaceBytes(raw, position, currentBytesLen, newBytes)

		// update all indexes into ops.pending that have been shifted by the above line

		for i := range ops.intcRefs {
			if ops.intcRefs[i].position > position {
				ops.intcRefs[i].position += positionDelta
			}
		}

		for i := range ops.bytecRefs {
			if ops.bytecRefs[i].position > position {
				ops.bytecRefs[i].position += positionDelta
			}
		}

		for label := range ops.labels {
			if ops.labels[label] > position {
				ops.labels[label] += positionDelta
			}
		}

		for i := range ops.labelReferences {
			if ops.labelReferences[i].position > position {
				ops.labelReferences[i].position += positionDelta
			}
		}

		fixedOffsetsToLine := make(map[int]int, len(ops.OffsetToLine))
		for pos, sourceLine := range ops.OffsetToLine {
			if pos > position {
				fixedOffsetsToLine[pos+positionDelta] = sourceLine
			} else {
				fixedOffsetsToLine[pos] = sourceLine
			}
		}
		ops.OffsetToLine = fixedOffsetsToLine
	}

	ops.pending = *bytes.NewBuffer(raw)

	optimizedConstBlock = make([]interface{}, 0)
	for _, f := range freqs {
		if f.freq == 1 {
			break
		}
		optimizedConstBlock = append(optimizedConstBlock, f.value)
	}

	return
}

// prependCBlocks completes the assembly by inserting cblocks if needed.
func (ops *OpStream) prependCBlocks() []byte {
	var scratch [binary.MaxVarintLen64]byte
	prebytes := bytes.Buffer{}
	vlen := binary.PutUvarint(scratch[:], ops.GetVersion())
	prebytes.Write(scratch[:vlen])
	if len(ops.intc) > 0 && !ops.hasIntcBlock {
		prebytes.WriteByte(0x20) // intcblock
		vlen := binary.PutUvarint(scratch[:], uint64(len(ops.intc)))
		prebytes.Write(scratch[:vlen])
		for _, iv := range ops.intc {
			vlen = binary.PutUvarint(scratch[:], iv)
			prebytes.Write(scratch[:vlen])
		}
	}
	if len(ops.bytec) > 0 && !ops.hasBytecBlock {
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
	return ops.lineError(ops.sourceLine, problem)
}

func (ops *OpStream) lineError(line int, problem interface{}) error {
	var le *lineError
	switch p := problem.(type) {
	case string:
		le = &lineError{Line: line, Err: errors.New(p)}
	case error:
		le = &lineError{Line: line, Err: p}
	default:
		le = &lineError{Line: line, Err: fmt.Errorf("%#v", p)}
	}
	ops.Errors = append(ops.Errors, le)
	return le
}

func (ops *OpStream) errorf(format string, a ...interface{}) error {
	return ops.error(fmt.Errorf(format, a...))
}

func (ops *OpStream) lineErrorf(line int, format string, a ...interface{}) error {
	return ops.lineError(line, fmt.Errorf(format, a...))
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

// ReportProblems issues accumulated warnings and outputs errors to an io.Writer.
func (ops *OpStream) ReportProblems(fname string, writer io.Writer) {
	for i, e := range ops.Errors {
		if i > 9 {
			break
		}
		if fname == "" {
			fmt.Fprintf(writer, "%s\n", e)
		} else {
			fmt.Fprintf(writer, "%s: %s\n", fname, e)
		}
	}
	for i, w := range ops.Warnings {
		if i > 9 {
			break
		}
		if fname == "" {
			fmt.Fprintf(writer, "%s\n", w)
		} else {
			fmt.Fprintf(writer, "%s: %s\n", fname, w)
		}
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
	program []byte
	pc      int
	out     io.Writer

	numericTargets bool
	labelCount     int
	pendingLabels  map[int]string

	// If we find a (back) jump to a label we did not generate
	// (because we didn't know about it yet), rerun is set to
	// true, and we make a second attempt to assemble once the
	// first attempt is done. The second attempt retains all the
	// labels found in the first pass.  In effect, the first
	// attempt to assemble becomes a first-pass in a two-pass
	// assembly process that simply collects jump target labels.
	rerun bool

	nextpc int

	intc  []uint64
	bytec [][]byte
}

func (dis *disassembleState) putLabel(label string, target int) {
	if dis.pendingLabels == nil {
		dis.pendingLabels = make(map[int]string)
	}
	dis.pendingLabels[target] = label
	if target <= dis.pc {
		dis.rerun = true
	}
}

func (dis *disassembleState) outputLabelIfNeeded() (err error) {
	if label, hasLabel := dis.pendingLabels[dis.pc]; hasLabel {
		_, err = fmt.Fprintf(dis.out, "%s:\n", label)
	}
	return
}

type disassembleFunc func(dis *disassembleState, spec *OpSpec) (string, error)

// Basic disasemble, and extra bytes of opcode are decoded as bytes integers.
func disDefault(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + spec.Details.Size - 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + spec.Details.Size
	out := spec.Name
	for s := 1; s < spec.Details.Size; s++ {
		b := uint(dis.program[dis.pc+s])
		out += fmt.Sprintf(" %d", b)
	}
	return out, nil
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

func checkIntConstBlock(cx *EvalContext) error {
	pos := cx.pc + 1
	numInts, bytesUsed := binary.Uvarint(cx.program[pos:])
	if bytesUsed <= 0 {
		return fmt.Errorf("could not decode int const block size at pc=%d", pos)
	}
	pos += bytesUsed
	if numInts > uint64(len(cx.program)) {
		return errTooManyIntc
	}
	//intc = make([]uint64, numInts)
	for i := uint64(0); i < numInts; i++ {
		if pos >= len(cx.program) {
			return errShortIntcblock
		}
		_, bytesUsed = binary.Uvarint(cx.program[pos:])
		if bytesUsed <= 0 {
			return fmt.Errorf("could not decode int const[%d] at pc=%d", i, pos)
		}
		pos += bytesUsed
	}
	cx.nextpc = pos
	return nil
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

func checkByteConstBlock(cx *EvalContext) error {
	pos := cx.pc + 1
	numItems, bytesUsed := binary.Uvarint(cx.program[pos:])
	if bytesUsed <= 0 {
		return fmt.Errorf("could not decode []byte const block size at pc=%d", pos)
	}
	pos += bytesUsed
	if numItems > uint64(len(cx.program)) {
		return errTooManyItems
	}
	//bytec = make([][]byte, numItems)
	for i := uint64(0); i < numItems; i++ {
		if pos >= len(cx.program) {
			return errShortBytecblock
		}
		itemLen, bytesUsed := binary.Uvarint(cx.program[pos:])
		if bytesUsed <= 0 {
			return fmt.Errorf("could not decode []byte const[%d] at pc=%d", i, pos)
		}
		pos += bytesUsed
		if pos >= len(cx.program) {
			return errShortBytecblock
		}
		end := uint64(pos) + itemLen
		if end > uint64(len(cx.program)) || end < uint64(pos) {
			return errShortBytecblock
		}
		//bytec[i] = program[pos : pos+int(itemLen)]
		pos += int(itemLen)
	}
	cx.nextpc = pos
	return nil
}

func disIntcblock(dis *disassembleState, spec *OpSpec) (string, error) {
	intc, nextpc, err := parseIntcblock(dis.program, dis.pc)
	if err != nil {
		return "", err
	}
	dis.nextpc = nextpc
	out := spec.Name
	for _, iv := range intc {
		dis.intc = append(dis.intc, iv)
		out += fmt.Sprintf(" %d", iv)
	}
	return out, nil
}

func disIntc(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + spec.Details.Size - 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + spec.Details.Size
	var suffix string
	var b int
	switch spec.Opcode {
	case 0x22:
		suffix = "_0"
		b = 0
	case 0x23:
		suffix = "_1"
		b = 1
	case 0x24:
		suffix = "_2"
		b = 2
	case 0x25:
		suffix = "_3"
		b = 3
	case 0x21:
		b = int(dis.program[dis.pc+1])
		suffix = fmt.Sprintf(" %d", b)
	default:
		return "", fmt.Errorf("disIntc on %v", spec)
	}
	if b < len(dis.intc) {
		return fmt.Sprintf("intc%s // %d", suffix, dis.intc[b]), nil
	}
	return fmt.Sprintf("intc%s", suffix), nil
}

func disBytecblock(dis *disassembleState, spec *OpSpec) (string, error) {
	bytec, nextpc, err := parseBytecBlock(dis.program, dis.pc)
	if err != nil {
		return "", err
	}
	dis.nextpc = nextpc
	out := spec.Name
	for _, bv := range bytec {
		dis.bytec = append(dis.bytec, bv)
		out += fmt.Sprintf(" 0x%s", hex.EncodeToString(bv))
	}
	return out, nil
}

func allPrintableASCII(bytes []byte) bool {
	for _, b := range bytes {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
func guessByteFormat(bytes []byte) string {
	var short basics.Address

	if len(bytes) == len(short) {
		copy(short[:], bytes[:])
		return fmt.Sprintf("addr %s", short.String())
	}
	if allPrintableASCII(bytes) {
		return fmt.Sprintf("%#v", string(bytes))
	}
	return "0x" + hex.EncodeToString(bytes)
}

func disBytec(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + spec.Details.Size - 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + spec.Details.Size
	var suffix string
	var b int
	switch spec.Opcode {
	case 0x28:
		suffix = "_0"
		b = 0
	case 0x29:
		suffix = "_1"
		b = 1
	case 0x2a:
		suffix = "_2"
		b = 2
	case 0x2b:
		suffix = "_3"
		b = 3
	case 0x27:
		b = int(dis.program[dis.pc+1])
		suffix = fmt.Sprintf(" %d", b)
	}
	if b < len(dis.bytec) {
		return fmt.Sprintf("bytec%s // %s", suffix, guessByteFormat(dis.bytec[b])), nil
	}
	return fmt.Sprintf("bytec%s", suffix), nil
}

func disPushInt(dis *disassembleState, spec *OpSpec) (string, error) {
	pos := dis.pc + 1
	val, bytesUsed := binary.Uvarint(dis.program[pos:])
	if bytesUsed <= 0 {
		return "", fmt.Errorf("could not decode int at pc=%d", pos)
	}
	dis.nextpc = pos + bytesUsed
	return fmt.Sprintf("%s %d", spec.Name, val), nil
}
func checkPushInt(cx *EvalContext) error {
	opPushInt(cx)
	return cx.err
}

func disPushBytes(dis *disassembleState, spec *OpSpec) (string, error) {
	pos := dis.pc + 1
	length, bytesUsed := binary.Uvarint(dis.program[pos:])
	if bytesUsed <= 0 {
		return "", fmt.Errorf("could not decode bytes length at pc=%d", pos)
	}
	pos += bytesUsed
	end := uint64(pos) + length
	if end > uint64(len(dis.program)) || end < uint64(pos) {
		return "", fmt.Errorf("pushbytes too long %d %d", end, pos)
	}
	bytes := dis.program[pos:end]
	dis.nextpc = int(end)
	return fmt.Sprintf("%s 0x%s // %s", spec.Name, hex.EncodeToString(bytes), guessByteFormat(bytes)), nil
}
func checkPushBytes(cx *EvalContext) error {
	opPushBytes(cx)
	return cx.err
}

// This is also used to disassemble gtxns, gtxnsas, txnas, itxn
func disTxn(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + 2
	txarg := dis.program[dis.pc+1]
	if int(txarg) >= len(TxnFieldNames) {
		return "", fmt.Errorf("invalid txn arg index %d at pc=%d", txarg, dis.pc)
	}
	return fmt.Sprintf("%s %s", spec.Name, TxnFieldNames[txarg]), nil
}

// This is also used to disassemble gtxnsa
func disTxna(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + 2
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + 3
	txarg := dis.program[dis.pc+1]
	if int(txarg) >= len(TxnFieldNames) {
		return "", fmt.Errorf("invalid txn arg index %d at pc=%d", txarg, dis.pc)
	}
	arrayFieldIdx := dis.program[dis.pc+2]
	return fmt.Sprintf("%s %s %d", spec.Name, TxnFieldNames[txarg], arrayFieldIdx), nil
}

// This is also used to disassemble gtxnas
func disGtxn(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + 2
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + 3
	gi := dis.program[dis.pc+1]
	txarg := dis.program[dis.pc+2]
	if int(txarg) >= len(TxnFieldNames) {
		return "", fmt.Errorf("invalid txn arg index %d at pc=%d", txarg, dis.pc)
	}
	return fmt.Sprintf("%s %d %s", spec.Name, gi, TxnFieldNames[txarg]), nil
}

func disGtxna(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + 3
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + 4
	gi := dis.program[dis.pc+1]
	txarg := dis.program[dis.pc+2]
	if int(txarg) >= len(TxnFieldNames) {
		return "", fmt.Errorf("invalid txn arg index %d at pc=%d", txarg, dis.pc)
	}
	arrayFieldIdx := dis.program[dis.pc+3]
	return fmt.Sprintf("gtxna %d %s %d", gi, TxnFieldNames[txarg], arrayFieldIdx), nil
}

func disGlobal(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + 2
	garg := dis.program[dis.pc+1]
	if int(garg) >= len(GlobalFieldNames) {
		return "", fmt.Errorf("invalid global arg index %d at pc=%d", garg, dis.pc)
	}
	return fmt.Sprintf("%s %s", spec.Name, GlobalFieldNames[garg]), nil
}

func disBranch(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + 2
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}

	dis.nextpc = dis.pc + 3
	offset := (uint(dis.program[dis.pc+1]) << 8) | uint(dis.program[dis.pc+2])
	target := int(offset) + dis.pc + 3
	if target > 0xffff {
		target -= 0x10000
	}
	var label string
	if dis.numericTargets {
		label = fmt.Sprintf("%d", target)
	} else {
		if known, ok := dis.pendingLabels[target]; ok {
			label = known
		} else {
			dis.labelCount++
			label = fmt.Sprintf("label%d", dis.labelCount)
			dis.putLabel(label, target)
		}
	}
	return fmt.Sprintf("%s %s", spec.Name, label), nil
}

func disAssetHolding(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + 2
	arg := dis.program[dis.pc+1]
	if int(arg) >= len(AssetHoldingFieldNames) {
		return "", fmt.Errorf("invalid asset holding arg index %d at pc=%d", arg, dis.pc)
	}
	return fmt.Sprintf("%s %s", spec.Name, AssetHoldingFieldNames[arg]), nil
}

func disAssetParams(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + 2
	arg := dis.program[dis.pc+1]
	if int(arg) >= len(AssetParamsFieldNames) {
		return "", fmt.Errorf("invalid asset params arg index %d at pc=%d", arg, dis.pc)
	}
	return fmt.Sprintf("%s %s", spec.Name, AssetParamsFieldNames[arg]), nil
}

func disAppParams(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + 2
	arg := dis.program[dis.pc+1]
	if int(arg) >= len(AppParamsFieldNames) {
		return "", fmt.Errorf("invalid app params arg index %d at pc=%d", arg, dis.pc)
	}
	return fmt.Sprintf("%s %s", spec.Name, AppParamsFieldNames[arg]), nil
}

func disTxField(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + 2
	arg := dis.program[dis.pc+1]
	if int(arg) >= len(TxnFieldNames) {
		return "", fmt.Errorf("invalid %s arg index %d at pc=%d", spec.Name, arg, dis.pc)
	}
	return fmt.Sprintf("%s %s", spec.Name, TxnFieldNames[arg]), nil
}

func disEcdsa(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + 2
	arg := dis.program[dis.pc+1]
	if int(arg) >= len(EcdsaCurveNames) {
		return "", fmt.Errorf("invalid curve arg index %d at pc=%d", arg, dis.pc)
	}
	return fmt.Sprintf("%s %s", spec.Name, EcdsaCurveNames[arg]), nil
}

func disBase64Decode(dis *disassembleState, spec *OpSpec) (string, error) {
	lastIdx := dis.pc + 1
	if len(dis.program) <= lastIdx {
		missing := lastIdx - len(dis.program) + 1
		return "", fmt.Errorf("unexpected %s opcode end: missing %d bytes", spec.Name, missing)
	}
	dis.nextpc = dis.pc + 2
	b64dArg := dis.program[dis.pc+1]
	if int(b64dArg) >= len(base64EncodingNames) {
		return "", fmt.Errorf("invalid base64_decode arg index %d at pc=%d", b64dArg, dis.pc)
	}
	return fmt.Sprintf("%s %s", spec.Name, base64EncodingNames[b64dArg]), nil
}

type disInfo struct {
	pcOffset       []PCOffset
	hasStatefulOps bool
}

// disassembleInstrumented is like Disassemble, but additionally
// returns where each program counter value maps in the
// disassembly. If the labels names are known, they may be passed in.
// When doing so, labels for all jump targets must be provided.
func disassembleInstrumented(program []byte, labels map[int]string) (text string, ds disInfo, err error) {
	out := strings.Builder{}
	dis := disassembleState{program: program, out: &out, pendingLabels: labels}
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
	fmt.Fprintf(dis.out, "#pragma version %d\n", version)
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
		var line string
		line, err = op.dis(&dis, &op)
		if err != nil {
			return
		}
		out.WriteString(line)
		out.WriteRune('\n')
		dis.pc = dis.nextpc
	}
	err = dis.outputLabelIfNeeded()
	if err != nil {
		return
	}

	text = out.String()

	if dis.rerun {
		if labels != nil {
			err = errors.New("rerun even though we had labels")
			return
		}
		return disassembleInstrumented(program, dis.pendingLabels)
	}
	return
}

// Disassemble produces a text form of program bytes.
// AssembleString(Disassemble()) should result in the same program bytes.
func Disassemble(program []byte) (text string, err error) {
	text, _, err = disassembleInstrumented(program, nil)
	return
}

// HasStatefulOps checks if the program has stateful opcodes
func HasStatefulOps(program []byte) (bool, error) {
	_, ds, err := disassembleInstrumented(program, nil)
	return ds.hasStatefulOps, err
}
