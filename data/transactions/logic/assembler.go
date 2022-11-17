// Copyright (C) 2019-2022 Algorand, Inc.
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
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/algorand/avm-abi/abi"
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

	// position of the label reference
	position int

	label string

	// ending positions of the opcode containing the label reference.
	offsetPosition int
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
	Trace    *strings.Builder
	Warnings []error     // informational warnings, shouldn't stop assembly
	Errors   []lineError // errors that should prevent final assembly
	Program  []byte      // Final program bytes. Will stay nil if any errors

	// Running bytes as they are assembled. jumps must be resolved
	// and cblocks added before these bytes become a legal program.
	pending bytes.Buffer

	intc         []uint64       // observed ints in code. We'll put them into a intcblock
	intcRefs     []intReference // references to int pseudo-op constants, used for optimization
	cntIntcBlock int            // prevent prepending intcblock because asm has one
	hasPseudoInt bool           // were any `int` pseudo ops used?

	bytec         [][]byte        // observed bytes in code. We'll put them into a bytecblock
	bytecRefs     []byteReference // references to byte/addr pseudo-op constants, used for optimization
	cntBytecBlock int             // prevent prepending bytecblock because asm has one
	hasPseudoByte bool            // were any `byte` (or equivalent) pseudo ops used?

	// tracks information we know to be true at the point being assembled
	known        ProgramKnowledge
	typeTracking bool

	// current sourceLine during assembly
	sourceLine int

	// map label string to position within pending buffer
	labels map[string]int

	// track references in order to patch in jump offsets
	labelReferences []labelReference

	// map opcode offsets to source line
	OffsetToLine map[int]int

	HasStatefulOps bool

	// Need new copy for each opstream
	versionedPseudoOps map[string]map[int]OpSpec
}

// newOpStream constructs OpStream instances ready to invoke assemble. A new
// OpStream must be used for each call to assemble().
func newOpStream(version uint64) OpStream {
	o := OpStream{
		labels:       make(map[string]int),
		OffsetToLine: make(map[int]int),
		typeTracking: true,
		Version:      version,
		known:        ProgramKnowledge{fp: -1},
	}

	for i := range o.known.scratchSpace {
		o.known.scratchSpace[i] = StackUint64
	}

	return o
}

// ProgramKnowledge tracks statically known information as we assemble
type ProgramKnowledge struct {
	// list of the types known to be on the value stack, based on specs of
	// opcodes seen while assembling. In normal code, the tip of the stack must
	// match the next opcode's Arg.Types, and is then replaced with its
	// Return.Types. If `deadcode` is true, `stack` should be empty.
	stack StackTypes

	// bottom is the type given out when `stack` is empty. It is StackNone at
	// program start, so, for example, a `+` opcode at the start of a program
	// fails. But when a label or callsub is encountered, `stack` is truncated
	// and `bottom` becomes StackAny, because we don't track program state
	// coming in from elsewhere. A `+` after a label succeeds, because the stack
	// "vitually" contains an infinite list of StackAny.
	bottom StackType

	// deadcode indicates that the program is in deadcode, so no type checking
	// errors should be reported.
	deadcode bool

	// fp is the frame pointer, if known/usable, or -1 if not.  When
	// encountering a `proto`, `stack` is grown to fit `args`, and this `fp` is
	// set to the top of those args.  This may not be the "real" fp when the
	// program is actually evaluated, but it is good enough for frame_{dig/bury}
	// to work from there.
	fp int

	scratchSpace [256]StackType
}

func (pgm *ProgramKnowledge) top() (StackType, bool) {
	if len(pgm.stack) == 0 {
		return pgm.bottom, pgm.bottom != StackNone
	}
	last := len(pgm.stack) - 1
	return pgm.stack[last], true
}

func (pgm *ProgramKnowledge) pop() StackType {
	if len(pgm.stack) == 0 {
		return pgm.bottom
	}
	last := len(pgm.stack) - 1
	t := pgm.stack[last]
	pgm.stack = pgm.stack[:last]
	return t
}

func (pgm *ProgramKnowledge) push(types ...StackType) {
	pgm.stack = append(pgm.stack, types...)
}

func (pgm *ProgramKnowledge) deaden() {
	pgm.stack = pgm.stack[:0]
	pgm.deadcode = true
}

// label resets knowledge to reflect that control may enter from elsewhere.
func (pgm *ProgramKnowledge) label() {
	if pgm.deadcode {
		pgm.reset()
	}
}

// reset clears existing knowledge and permissively allows any stack value.  It's intended to be invoked after encountering a label or pragma type tracking change.
func (pgm *ProgramKnowledge) reset() {
	pgm.stack = nil
	pgm.bottom = StackAny
	pgm.fp = -1
	pgm.deadcode = false
	for i := range pgm.scratchSpace {
		pgm.scratchSpace[i] = StackAny
	}
}

// createLabel inserts a label to point to the next instruction, reporting an
// error for a duplicate.
func (ops *OpStream) createLabel(label string) {
	if _, ok := ops.labels[label]; ok {
		ops.errorf("duplicate label %#v", label)
	}
	ops.labels[label] = ops.pending.Len()
	ops.known.label()
}

// recordSourceLine adds an entry to pc to line mapping
func (ops *OpStream) recordSourceLine() {
	ops.OffsetToLine[ops.pending.Len()] = ops.sourceLine - 1
}

// referToLabel records an opcode label reference to resolve later
func (ops *OpStream) referToLabel(pc int, label string, offsetPosition int) {
	ops.labelReferences = append(ops.labelReferences, labelReference{ops.sourceLine, pc, label, offsetPosition})
}

type refineFunc func(pgm *ProgramKnowledge, immediates []string) (StackTypes, StackTypes, error)

// returns allows opcodes like `txn` to be specific about their return value
// types, based on the field requested, rather than use Any as specified by
// opSpec. It replaces StackAny in the top `count` elements of the typestack.
func (ops *OpStream) returns(spec *OpSpec, replacement StackType) {
	if ops.known.deadcode {
		return
	}
	end := len(ops.known.stack)
	tip := ops.known.stack[end-len(spec.Return.Types):]
	for i := range tip {
		if tip[i] == StackAny {
			tip[i] = replacement
			return
		}
	}
	// returns was called on an OpSpec with no StackAny in its Returns
	panic(fmt.Sprintf("%+v", spec))
}

// Intc writes opcodes for loading a uint64 constant onto the stack.
func (ops *OpStream) Intc(constIndex uint) {
	switch constIndex {
	case 0:
		ops.pending.WriteByte(OpsByName[ops.Version]["intc_0"].Opcode)
	case 1:
		ops.pending.WriteByte(OpsByName[ops.Version]["intc_1"].Opcode)
	case 2:
		ops.pending.WriteByte(OpsByName[ops.Version]["intc_2"].Opcode)
	case 3:
		ops.pending.WriteByte(OpsByName[ops.Version]["intc_3"].Opcode)
	default:
		if constIndex > 0xff {
			ops.error("cannot have more than 256 int constants")
		}
		ops.pending.WriteByte(OpsByName[ops.Version]["intc"].Opcode)
		ops.pending.WriteByte(uint8(constIndex))
	}
	if constIndex >= uint(len(ops.intc)) {
		ops.errorf("intc %d is not defined", constIndex)
	} else {
		ops.trace("intc %d: %d", constIndex, ops.intc[constIndex])
	}
}

// IntLiteral writes opcodes for loading a uint literal
func (ops *OpStream) IntLiteral(val uint64) {
	ops.hasPseudoInt = true

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
		if ops.cntIntcBlock > 0 {
			ops.errorf("int %d used without %d in intcblock", val, val)
		}
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
		ops.pending.WriteByte(OpsByName[ops.Version]["bytec_0"].Opcode)
	case 1:
		ops.pending.WriteByte(OpsByName[ops.Version]["bytec_1"].Opcode)
	case 2:
		ops.pending.WriteByte(OpsByName[ops.Version]["bytec_2"].Opcode)
	case 3:
		ops.pending.WriteByte(OpsByName[ops.Version]["bytec_3"].Opcode)
	default:
		if constIndex > 0xff {
			ops.error("cannot have more than 256 byte constants")
		}
		ops.pending.WriteByte(OpsByName[ops.Version]["bytec"].Opcode)
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
	ops.hasPseudoByte = true

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
		if ops.cntBytecBlock > 0 {
			ops.errorf("byte/addr/method used without value in bytecblock")
		}
		constIndex = uint(len(ops.bytec))
		ops.bytec = append(ops.bytec, val)
	}
	ops.bytecRefs = append(ops.bytecRefs, byteReference{
		value:    val,
		position: ops.pending.Len(),
	})
	ops.Bytec(constIndex)
}

func asmInt(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s needs one immediate argument, was given %d", spec.Name, len(args))
	}

	// After backBranchEnabledVersion, control flow is confusing, so if there's
	// a manual cblock, use push instead of trying to use what's given.
	if ops.cntIntcBlock > 0 && ops.Version >= backBranchEnabledVersion {
		// We don't understand control-flow, so use pushint
		ops.warnf("int %s used with explicit intcblock. must pushint", args[0])
		pushint := OpsByName[ops.Version]["pushint"]
		return asmPushInt(ops, &pushint, args)
	}

	// There are no backjumps, but there are multiple cblocks. Maybe one is
	// conditional skipped. Too confusing.
	if ops.cntIntcBlock > 1 {
		pushint, ok := OpsByName[ops.Version]["pushint"]
		if ok {
			return asmPushInt(ops, &pushint, args)
		}
		return ops.errorf("int %s used with manual intcblocks. Use intc.", args[0])
	}

	// In both of the above clauses, we _could_ track whether a particular
	// intcblock dominates the current instruction. If so, we could use it.

	// check txn type constants
	i, ok := txnTypeMap[args[0]]
	if ok {
		ops.IntLiteral(i)
		return nil
	}
	// check OnCompletion constants
	oc, isOCStr := onCompletionMap[args[0]]
	if isOCStr {
		ops.IntLiteral(oc)
		return nil
	}
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return ops.error(err)
	}
	ops.IntLiteral(val)
	return nil
}

// Explicit invocation of const lookup and push
func asmIntC(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s needs one immediate argument, was given %d", spec.Name, len(args))
	}
	constIndex, err := byteImm(args[0], "constant")
	if err != nil {
		return ops.error(err)
	}
	ops.Intc(uint(constIndex))
	return nil
}
func asmByteC(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s needs one immediate argument, was given %d", spec.Name, len(args))
	}
	constIndex, err := byteImm(args[0], "constant")
	if err != nil {
		return ops.error(err)
	}
	ops.Bytec(uint(constIndex))
	return nil
}

func asmPushInt(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s needs one immediate argument, was given %d", spec.Name, len(args))
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

func asmPushInts(ops *OpStream, spec *OpSpec, args []string) error {
	ops.pending.WriteByte(spec.Opcode)
	_, err := asmIntImmArgs(ops, args)
	return err
}

func asmPushBytes(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 0 {
		return ops.errorf("%s needs byte literal argument", spec.Name)
	}
	val, consumed, err := parseBinaryArgs(args)
	if err != nil {
		return ops.error(err)
	}
	if len(args) != consumed {
		return ops.errorf("%s with extraneous argument", spec.Name)
	}
	ops.pending.WriteByte(spec.Opcode)
	var scratch [binary.MaxVarintLen64]byte
	vlen := binary.PutUvarint(scratch[:], uint64(len(val)))
	ops.pending.Write(scratch[:vlen])
	ops.pending.Write(val)
	return nil
}

func asmPushBytess(ops *OpStream, spec *OpSpec, args []string) error {
	ops.pending.WriteByte(spec.Opcode)
	_, err := asmByteImmArgs(ops, args)
	return err
}

func base32DecodeAnyPadding(x string) (val []byte, err error) {
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
		val, err = base32DecodeAnyPadding(arg[open+1 : close])
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
		val, err = base32DecodeAnyPadding(args[1])
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
func asmByte(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 0 {
		return ops.errorf("%s needs byte literal argument", spec.Name)
	}

	// After backBranchEnabledVersion, control flow is confusing, so if there's
	// a manual cblock, use push instead of trying to use what's given.
	if ops.cntBytecBlock > 0 && ops.Version >= backBranchEnabledVersion {
		// We don't understand control-flow, so use pushbytes
		ops.warnf("byte %s used with explicit bytecblock. must pushbytes", args[0])
		pushbytes := OpsByName[ops.Version]["pushbytes"]
		return asmPushBytes(ops, &pushbytes, args)
	}

	// There are no backjumps, but there are multiple cblocks. Maybe one is
	// conditional skipped. Too confusing.
	if ops.cntBytecBlock > 1 {
		pushbytes, ok := OpsByName[ops.Version]["pushbytes"]
		if ok {
			return asmPushBytes(ops, &pushbytes, args)
		}
		return ops.errorf("byte %s used with manual bytecblocks. Use bytec.", args[0])
	}

	// In both of the above clauses, we _could_ track whether a particular
	// bytecblock dominates the current instruction. If so, we could use it.

	val, consumed, err := parseBinaryArgs(args)
	if err != nil {
		return ops.error(err)
	}
	if len(args) != consumed {
		return ops.errorf("%s with extraneous argument", spec.Name)
	}
	ops.ByteLiteral(val)
	return nil
}

// method "add(uint64,uint64)uint64"
func asmMethod(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 0 {
		return ops.error("method requires a literal argument")
	}
	arg := args[0]
	if len(arg) > 1 && arg[0] == '"' && arg[len(arg)-1] == '"' {
		methodSig, err := parseStringLiteral(arg)
		if err != nil {
			return ops.error(err)
		}
		methodSigStr := string(methodSig)
		err = abi.VerifyMethodSignature(methodSigStr)
		if err != nil {
			// Warn if an invalid signature is used. Don't return an error, since the ABI is not
			// governed by the core protocol, so there may be changes to it that we don't know about
			ops.warnf("Invalid ARC-4 ABI method signature for method op: %s", err.Error())
		}
		hash := sha512.Sum512_256(methodSig)
		ops.ByteLiteral(hash[0:4])
		return nil
	}
	return ops.error("Unable to parse method signature")
}

func asmIntImmArgs(ops *OpStream, args []string) ([]uint64, error) {
	ivals := make([]uint64, len(args))
	var scratch [binary.MaxVarintLen64]byte
	l := binary.PutUvarint(scratch[:], uint64(len(args)))
	ops.pending.Write(scratch[:l])
	for i, xs := range args {
		cu, err := strconv.ParseUint(xs, 0, 64)
		if err != nil {
			ops.error(err)
		}
		l = binary.PutUvarint(scratch[:], cu)
		ops.pending.Write(scratch[:l])
		ivals[i] = cu
	}

	return ivals, nil
}

func asmIntCBlock(ops *OpStream, spec *OpSpec, args []string) error {
	ops.pending.WriteByte(spec.Opcode)
	ivals, err := asmIntImmArgs(ops, args)
	if err != nil {
		return err
	}
	if !ops.known.deadcode {
		// If we previously processed an `int`, we thought we could insert our
		// own intcblock, but now we see a manual one.
		if ops.hasPseudoInt {
			ops.error("intcblock following int")
		}
		ops.intcRefs = nil
		ops.intc = ivals
		ops.cntIntcBlock++
	}

	return nil
}

func asmByteImmArgs(ops *OpStream, args []string) ([][]byte, error) {
	bvals := make([][]byte, 0, len(args))
	rest := args
	for len(rest) > 0 {
		val, consumed, err := parseBinaryArgs(rest)
		if err != nil {
			// Would be nice to keep going, as in
			// intcblock, but parseBinaryArgs would have
			// to return a useful consumed value even in
			// the face of errors.  Hard.
			return nil, ops.error(err)
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

	return bvals, nil
}

func asmByteCBlock(ops *OpStream, spec *OpSpec, args []string) error {
	ops.pending.WriteByte(spec.Opcode)
	bvals, err := asmByteImmArgs(ops, args)
	if err != nil {
		return err
	}

	if !ops.known.deadcode {
		// If we previously processed a pseudo `byte`, we thought we could
		// insert our own bytecblock, but now we see a manual one.
		if ops.hasPseudoByte {
			ops.error("bytecblock following byte/addr/method")
		}
		ops.bytecRefs = nil
		ops.bytec = bvals
		ops.cntBytecBlock++
	}
	return nil
}

// addr A1EU...
// parses base32-with-checksum account address strings into a byte literal
func asmAddr(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s needs one immediate argument, was given %d", spec.Name, len(args))
	}
	addr, err := basics.UnmarshalChecksumAddress(args[0])
	if err != nil {
		return ops.error(err)
	}
	ops.ByteLiteral(addr[:])
	return nil
}

func asmArg(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s needs one immediate argument, was given %d", spec.Name, len(args))
	}
	val, err := byteImm(args[0], "argument")
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

func asmBranch(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s needs a single label argument", spec.Name)
	}

	ops.referToLabel(ops.pending.Len()+1, args[0], ops.pending.Len()+spec.Size)
	ops.pending.WriteByte(spec.Opcode)
	// zero bytes will get replaced with actual offset in resolveLabels()
	ops.pending.WriteByte(0)
	ops.pending.WriteByte(0)
	return nil
}

func asmSwitch(ops *OpStream, spec *OpSpec, args []string) error {
	numOffsets := len(args)
	if numOffsets > math.MaxUint8 {
		return ops.errorf("%s cannot take more than 255 labels", spec.Name)
	}
	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(byte(numOffsets))
	opEndPos := ops.pending.Len() + 2*numOffsets
	for _, arg := range args {
		ops.referToLabel(ops.pending.Len(), arg, opEndPos)
		// zero bytes will get replaced with actual offset in resolveLabels()
		ops.pending.WriteByte(0)
		ops.pending.WriteByte(0)
	}
	return nil
}

func asmSubstring(ops *OpStream, spec *OpSpec, args []string) error {
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

func byteImm(value string, label string) (byte, error) {
	res, err := strconv.ParseUint(value, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("unable to parse %s %#v as integer", label, value)
	}
	if res > 255 {
		return 0, fmt.Errorf("%s beyond 255: %d", label, res)
	}
	return byte(res), err
}

func int8Imm(value string, label string) (byte, error) {
	res, err := strconv.ParseInt(value, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("unable to parse %s %#v as int8", label, value)
	}
	return byte(res), err
}

func asmItxn(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 1 {
		return asmDefault(ops, spec, args)
	}
	if len(args) == 2 {
		itxna := OpsByName[ops.Version]["itxna"]
		return asmDefault(ops, &itxna, args)
	}
	return ops.errorf("%s expects 1 or 2 immediate arguments", spec.Name)
}

// asmGitxn substitutes gitna's spec if the are 3 args
func asmGitxn(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) == 2 {
		return asmDefault(ops, spec, args)
	}
	if len(args) == 3 {
		itxna := OpsByName[ops.Version]["gitxna"]
		return asmDefault(ops, &itxna, args)
	}
	return ops.errorf("%s expects 2 or 3 immediate arguments", spec.Name)
}

func asmItxnField(ops *OpStream, spec *OpSpec, args []string) error {
	if len(args) != 1 {
		return ops.errorf("%s expects one argument", spec.Name)
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return ops.errorf("%s unknown field: %#v", spec.Name, args[0])
	}
	if fs.itxVersion == 0 {
		return ops.errorf("%s %#v is not allowed.", spec.Name, args[0])
	}
	if fs.itxVersion > ops.Version {
		return ops.errorf("%s %s field was introduced in v%d. Missed #pragma version?", spec.Name, args[0], fs.itxVersion)
	}
	ops.pending.WriteByte(spec.Opcode)
	ops.pending.WriteByte(fs.Field())
	return nil
}

type asmFunc func(*OpStream, *OpSpec, []string) error

// Basic assembly. Any extra bytes of opcode are encoded as byte immediates.
func asmDefault(ops *OpStream, spec *OpSpec, args []string) error {
	expected := len(spec.OpDetails.Immediates)
	if len(args) != expected {
		if expected == 1 {
			return ops.errorf("%s expects 1 immediate argument", spec.Name)
		}
		return ops.errorf("%s expects %d immediate arguments", spec.Name, expected)
	}
	ops.pending.WriteByte(spec.Opcode)
	for i, imm := range spec.OpDetails.Immediates {
		var correctImmediates []string
		var numImmediatesWithField []int
		pseudos, isPseudoName := ops.versionedPseudoOps[spec.Name]
		switch imm.kind {
		case immByte:
			if imm.Group != nil {
				fs, ok := imm.Group.SpecByName(args[i])
				if !ok {
					_, err := byteImm(args[i], "")
					if err == nil {
						// User supplied a uint, so we see if any of the other immediates take uints
						for j, otherImm := range spec.OpDetails.Immediates {
							if otherImm.kind == immByte && otherImm.Group == nil {
								correctImmediates = append(correctImmediates, strconv.Itoa(j+1))
							}
						}
						if len(correctImmediates) > 0 {
							errMsg := spec.Name
							if isPseudoName {
								errMsg += " with " + joinIntsOnOr("immediate", len(args))
							}
							return ops.errorf("%s can only use %#v as immediate %s", errMsg, args[i], strings.Join(correctImmediates, " or "))
						}
					}
					if isPseudoName {
						for numImms, ps := range pseudos {
							for _, psImm := range ps.OpDetails.Immediates {
								if psImm.kind == immByte && psImm.Group != nil {
									if _, ok := psImm.Group.SpecByName(args[i]); ok {
										numImmediatesWithField = append(numImmediatesWithField, numImms)
									}
								}
							}
						}
						if len(numImmediatesWithField) > 0 {
							return ops.errorf("%#v field of %s can only be used with %s", args[i], spec.Name, joinIntsOnOr("immediate", numImmediatesWithField...))
						}
					}
					return ops.errorf("%s unknown field: %#v", spec.Name, args[i])
				}
				// refine the typestack now, so it is maintained even if there's a version error
				if fs.Type().Typed() {
					ops.returns(spec, fs.Type())
				}
				if fs.Version() > ops.Version {
					return ops.errorf("%s %s field was introduced in v%d. Missed #pragma version?",
						spec.Name, args[i], fs.Version())
				}
				ops.pending.WriteByte(fs.Field())
			} else {
				// simple immediate that must be a number from 0-255
				val, err := byteImm(args[i], imm.Name)
				if err != nil {
					if strings.Contains(err.Error(), "unable to parse") {
						// Perhaps the field works in a different order
						for j, otherImm := range spec.OpDetails.Immediates {
							if otherImm.kind == immByte && otherImm.Group != nil {
								if _, match := otherImm.Group.SpecByName(args[i]); match {
									correctImmediates = append(correctImmediates, strconv.Itoa(j+1))
								}
							}
						}
						if len(correctImmediates) > 0 {
							errMsg := spec.Name
							if isPseudoName {
								errMsg += " with " + joinIntsOnOr("immediate", len(args))
							}
							return ops.errorf("%s can only use %#v as immediate %s", errMsg, args[i], strings.Join(correctImmediates, " or "))
						}
					}
					return ops.errorf("%s %w", spec.Name, err)
				}
				ops.pending.WriteByte(val)
			}
		case immInt8:
			val, err := int8Imm(args[i], imm.Name)
			if err != nil {
				return ops.errorf("%s %w", spec.Name, err)
			}
			ops.pending.WriteByte(val)
		default:
			return ops.errorf("unable to assemble immKind %d", imm.kind)
		}
	}
	return nil
}

// getImm interprets the arg at index argIndex as an immediate
func getImm(args []string, argIndex int) (int, bool) {
	if len(args) <= argIndex {
		return 0, false
	}
	// We want to parse anything from -128 up to 255. So allow 9 bits.
	// Normal assembly checking will catch signed as byte, vice versa
	n, err := strconv.ParseInt(args[argIndex], 0, 9)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

func anyTypes(n int) StackTypes {
	as := make(StackTypes, n)
	for i := range as {
		as[i] = StackAny
	}
	return as
}

func typeSwap(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	swapped := StackTypes{StackAny, StackAny}
	top := len(pgm.stack) - 1
	if top >= 0 {
		swapped[0] = pgm.stack[top]
		if top >= 1 {
			swapped[1] = pgm.stack[top-1]
		}
	}
	return nil, swapped, nil
}

func typeDig(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	n, ok := getImm(args, 0)
	if !ok {
		return nil, nil, nil
	}
	depth := n + 1
	returns := anyTypes(depth + 1)
	idx := len(pgm.stack) - depth
	if idx >= 0 {
		// We return exactly what on the stack...
		copy(returns[:], pgm.stack[idx:])
		// plus a repeat of what was at idx
		returns[len(returns)-1] = pgm.stack[idx]
	}
	return anyTypes(depth), returns, nil
}

func typeBury(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	n, ok := getImm(args, 0)
	if !ok {
		return nil, nil, nil
	}
	if n == 0 {
		return nil, nil, errors.New("bury 0 always fails")
	}

	top := len(pgm.stack) - 1
	typ, ok := pgm.top()
	if !ok {
		return nil, nil, nil // Will error because bury demands a stack arg
	}

	idx := top - n
	if idx < 0 {
		if pgm.bottom == StackNone {
			// By demanding n+1 elements, we'll trigger an error
			return anyTypes(n + 1), nil, nil
		}
		// We're going to bury below the tracked portion of the stack, so there's
		// nothing to update.
		return nil, nil, nil
	}

	returns := make(StackTypes, n)
	copy(returns, pgm.stack[idx:]) // Won't have room to copy the top type
	returns[0] = typ               // Replace the bottom with the top type
	return pgm.stack[idx:], returns, nil
}

func typeFrameDig(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	n, ok := getImm(args, 0)
	if !ok {
		return nil, nil, nil
	}
	// If we have no frame pointer, we can't do better than "any"
	if pgm.fp == -1 {
		return nil, nil, nil
	}

	// If we do have a framepointer, we can try to get the type
	idx := pgm.fp + n
	if idx < 0 {
		return nil, nil, fmt.Errorf("frame_dig %d in sub with %d args", n, pgm.fp)
	}
	if idx >= len(pgm.stack) {
		return nil, nil, fmt.Errorf("frame_dig above stack")
	}
	return nil, StackTypes{pgm.stack[idx]}, nil
}

func typeFrameBury(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	n, ok := getImm(args, 0)
	if !ok {
		return nil, nil, nil
	}

	top := len(pgm.stack) - 1
	typ, ok := pgm.top()
	if !ok {
		return nil, nil, nil // Will error because fbury demands a stack arg
	}

	// If we have no frame pointer, we have to wipe out any belief that the
	// stack contains anything but the supplied type.
	if pgm.fp == -1 {
		// Perhaps it would be cleaner to build up the args, return slices to
		// cause this, rather than manipulate the pgm.stack directly.
		for i := range pgm.stack {
			if pgm.stack[i] != typ {
				pgm.stack[i] = StackAny
			}
		}
		return nil, nil, nil
	}

	// If we do have a framepointer, we can try to update the typestack
	idx := pgm.fp + n
	if idx < 0 {
		return nil, nil, fmt.Errorf("frame_bury %d in sub with %d args", n, pgm.fp)
	}
	if idx >= top {
		return nil, nil, fmt.Errorf("frame_bury above stack")
	}
	depth := top - idx

	returns := make(StackTypes, depth)
	copy(returns, pgm.stack[idx:]) // Won't have room to copy the top type
	returns[0] = typ               // Replace the bottom with the top type
	return pgm.stack[idx:], returns, nil
}

func typeEquals(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	top := len(pgm.stack) - 1
	if top >= 0 {
		//Require arg0 and arg1 to have same type
		return StackTypes{pgm.stack[top], pgm.stack[top]}, nil, nil
	}
	return nil, nil, nil
}

func typeDup(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	top := len(pgm.stack) - 1
	if top >= 0 {
		return nil, StackTypes{pgm.stack[top], pgm.stack[top]}, nil
	}
	return nil, nil, nil
}

func typeDupTwo(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	topTwo := StackTypes{StackAny, StackAny}
	top := len(pgm.stack) - 1
	if top >= 0 {
		topTwo[1] = pgm.stack[top]
		if top >= 1 {
			topTwo[0] = pgm.stack[top-1]
		}
	}
	return nil, append(topTwo, topTwo...), nil
}

func typeSelect(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	top := len(pgm.stack) - 1
	if top >= 2 {
		if pgm.stack[top-1] == pgm.stack[top-2] {
			return nil, StackTypes{pgm.stack[top-1]}, nil
		}
	}
	return nil, nil, nil
}

func typeSetBit(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	top := len(pgm.stack) - 1
	if top >= 2 {
		return nil, StackTypes{pgm.stack[top-2]}, nil
	}
	return nil, nil, nil
}

func typeCover(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	n, ok := getImm(args, 0)
	if !ok {
		return nil, nil, nil
	}
	depth := int(n) + 1
	returns := anyTypes(depth)

	idx := len(pgm.stack) - depth
	// This rotates all the types if idx is >= 0. But there's a potential
	// improvement: when pgm.bottom is StackAny, and the cover is going "under"
	// the known stack, the returns slice could still be partially populated
	// based on pgm.stack.
	if idx >= 0 {
		returns[0] = pgm.stack[len(pgm.stack)-1]
		for i := idx; i < len(pgm.stack)-1; i++ {
			returns[i-idx+1] = pgm.stack[i]
		}
	}
	return anyTypes(depth), returns, nil
}

func typeUncover(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	n, ok := getImm(args, 0)
	if !ok {
		return nil, nil, nil
	}
	depth := n + 1
	returns := anyTypes(depth)
	idx := len(pgm.stack) - depth
	// See precision comment in typeCover
	if idx >= 0 {
		returns[len(returns)-1] = pgm.stack[idx]
		for i := idx + 1; i < len(pgm.stack); i++ {
			returns[i-idx-1] = pgm.stack[i]
		}
	}
	return anyTypes(depth), returns, nil
}

func typeTxField(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	if len(args) != 1 {
		return nil, nil, nil
	}
	fs, ok := txnFieldSpecByName[args[0]]
	if !ok {
		return nil, nil, nil
	}
	return StackTypes{fs.ftype}, nil, nil
}

func typeStore(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	scratchIndex, ok := getImm(args, 0)
	if !ok {
		return nil, nil, nil
	}
	top := len(pgm.stack) - 1
	if top >= 0 {
		pgm.scratchSpace[scratchIndex] = pgm.stack[top]
	}
	return nil, nil, nil
}

func typeStores(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	top := len(pgm.stack) - 1
	if top < 0 {
		return nil, nil, nil
	}
	for i := range pgm.scratchSpace {
		// We can't know what slot stacktop is being stored in, but we can at least keep the slots that are the same type as stacktop
		if pgm.scratchSpace[i] != pgm.stack[top] {
			pgm.scratchSpace[i] = StackAny
		}
	}
	return nil, nil, nil
}

func typeLoad(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	scratchIndex, ok := getImm(args, 0)
	if !ok {
		return nil, nil, nil
	}
	return nil, StackTypes{pgm.scratchSpace[scratchIndex]}, nil
}

func typeProto(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	a, aok := getImm(args, 0)
	_, rok := getImm(args, 1)
	if !aok || !rok {
		return nil, nil, nil
	}

	if len(pgm.stack) != 0 || pgm.bottom != StackAny {
		return nil, nil, fmt.Errorf("proto must be unreachable from previous PC")
	}
	pgm.stack = anyTypes(a)
	pgm.fp = a
	return nil, nil, nil
}

func typeLoads(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	scratchType := pgm.scratchSpace[0]
	for _, item := range pgm.scratchSpace {
		// If all the scratch slots are one type, then we can say we are loading that type
		if item != scratchType {
			return nil, nil, nil
		}
	}
	return nil, StackTypes{scratchType}, nil
}

func typePopN(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	n, ok := getImm(args, 0)
	if !ok {
		return nil, nil, nil
	}
	return anyTypes(n), nil, nil
}

func typeDupN(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	n, ok := getImm(args, 0)
	if !ok {
		return nil, nil, nil
	}
	top := len(pgm.stack) - 1
	if top < 0 {
		return nil, nil, nil
	}

	// `dupn 3` ends up with 4 copies of ToS on top
	copies := make(StackTypes, n+1)
	for i := range copies {
		copies[i] = pgm.stack[top]
	}

	return nil, copies, nil
}

func typePushBytess(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	types := make(StackTypes, len(args))
	for i := range types {
		types[i] = StackBytes
	}

	return nil, types, nil
}

func typePushInts(pgm *ProgramKnowledge, args []string) (StackTypes, StackTypes, error) {
	types := make(StackTypes, len(args))
	for i := range types {
		types[i] = StackUint64
	}

	return nil, types, nil
}

func joinIntsOnOr(singularTerminator string, list ...int) string {
	if len(list) == 1 {
		switch list[0] {
		case 0:
			return "no " + singularTerminator + "s"
		case 1:
			return "1 " + singularTerminator
		default:
			return fmt.Sprintf("%d %ss", list[0], singularTerminator)
		}
	}
	sort.Ints(list)
	errMsg := ""
	for i, val := range list {
		if i+1 < len(list) {
			errMsg += fmt.Sprintf("%d or ", val)
		} else {
			errMsg += fmt.Sprintf("%d ", val)
		}
	}
	return errMsg + singularTerminator + "s"
}

func pseudoImmediatesError(ops *OpStream, name string, specs map[int]OpSpec) {
	immediateCounts := make([]int, len(specs))
	i := 0
	for numImms := range specs {
		immediateCounts[i] = numImms
		i++
	}
	ops.error(name + " expects " + joinIntsOnOr("immediate argument", immediateCounts...))
}

// getSpec finds the OpSpec we need during assembly based on its name, our current version, and the immediates passed in
// Note getSpec handles both normal OpSpecs and those supplied by versionedPseudoOps
// The returned string is the spec's name, annotated if it was a pseudoOp with no immediates to help disambiguate typetracking errors
func getSpec(ops *OpStream, name string, args []string) (OpSpec, string, bool) {
	pseudoSpecs, ok := ops.versionedPseudoOps[name]
	if ok {
		pseudo, ok := pseudoSpecs[len(args)]
		if !ok {
			// Could be that pseudoOp wants to handle immediates itself so check -1 key
			pseudo, ok = pseudoSpecs[anyImmediates]
			if !ok {
				// Number of immediates supplied did not match any of the pseudoOps of the given name, so we try to construct a mock spec that can be used to track types
				pseudoImmediatesError(ops, name, pseudoSpecs)
				proto, version, ok := mergeProtos(pseudoSpecs)
				if !ok {
					return OpSpec{}, "", false
				}
				pseudo = OpSpec{Name: name, Proto: proto, Version: version, OpDetails: OpDetails{asm: func(*OpStream, *OpSpec, []string) error { return nil }}}
			}
		}
		pseudo.Name = name
		if pseudo.Version > ops.Version {
			ops.errorf("%s opcode with %s was introduced in v%d", pseudo.Name, joinIntsOnOr("immediate", len(args)), pseudo.Version)
		}
		if len(args) == 0 {
			return pseudo, pseudo.Name + " without immediates", true
		}
		return pseudo, pseudo.Name, true
	}
	spec, ok := OpsByName[ops.Version][name]
	if !ok {
		spec, ok = OpsByName[AssemblerMaxVersion][name]
		if ok {
			ops.errorf("%s opcode was introduced in v%d", name, spec.Version)
		} else {
			ops.errorf("unknown opcode: %s", name)
		}
	}
	return spec, spec.Name, ok
}

// pseudoOps allows us to provide convenient ops that mirror existing ops without taking up another opcode. Using "txn" in version 2 and on, for example, determines whether to actually assemble txn or to use txna instead based on the number of immediates.
// Immediates key of -1 means asmfunc handles number of immediates
// These will then get transferred over into a per-opstream versioned table during assembly
const anyImmediates = -1

var pseudoOps = map[string]map[int]OpSpec{
	"int":  {anyImmediates: OpSpec{Name: "int", Proto: proto(":i"), OpDetails: assembler(asmInt)}},
	"byte": {anyImmediates: OpSpec{Name: "byte", Proto: proto(":b"), OpDetails: assembler(asmByte)}},
	// parse basics.Address, actually just another []byte constant
	"addr": {anyImmediates: OpSpec{Name: "addr", Proto: proto(":b"), OpDetails: assembler(asmAddr)}},
	// take a signature, hash it, and take first 4 bytes, actually just another []byte constant
	"method":  {anyImmediates: OpSpec{Name: "method", Proto: proto(":b"), OpDetails: assembler(asmMethod)}},
	"txn":     {1: OpSpec{Name: "txn"}, 2: OpSpec{Name: "txna"}},
	"gtxn":    {2: OpSpec{Name: "gtxn"}, 3: OpSpec{Name: "gtxna"}},
	"gtxns":   {1: OpSpec{Name: "gtxns"}, 2: OpSpec{Name: "gtxnsa"}},
	"extract": {0: OpSpec{Name: "extract3"}, 2: OpSpec{Name: "extract"}},
	"replace": {0: OpSpec{Name: "replace3"}, 1: OpSpec{Name: "replace2"}},
}

func addPseudoDocTags() {
	for name, specs := range pseudoOps {
		for i, spec := range specs {
			if spec.Name == name || i == anyImmediates {
				continue
			}
			msg := fmt.Sprintf("`%s` can be called using `%s` with %s.", spec.Name, name, joinIntsOnOr("immediate", i))
			desc, ok := opDocByName[spec.Name]
			if ok {
				opDocByName[spec.Name] = desc + "<br />" + msg
			} else {
				opDocByName[spec.Name] = msg
			}
		}
	}
}

func init() {
	addPseudoDocTags()
}

// Differentiates between specs in pseudoOps that can be assembled on their own and those that need to grab a different spec
func isFullSpec(spec OpSpec) bool {
	return spec.asm != nil
}

// mergeProtos allows us to support typetracking of pseudo-ops which are given an improper number of immediates
//by creating a new proto that is a combination of all the pseudo-op's possibilities
func mergeProtos(specs map[int]OpSpec) (Proto, uint64, bool) {
	var args StackTypes
	var returns StackTypes
	var minVersion uint64
	i := 0
	for _, spec := range specs {
		if i == 0 {
			args = spec.Arg.Types
			returns = spec.Return.Types
			minVersion = spec.Version
		} else {
			if spec.Version < minVersion {
				minVersion = spec.Version
			}
			if len(args) != len(spec.Arg.Types) || len(returns) != len(spec.Return.Types) {
				return Proto{}, 0, false
			}
			for j := range args {
				if args[j] != spec.Arg.Types[j] {
					args[j] = StackAny
				}
			}
			for j := range returns {
				if returns[j] != spec.Return.Types[j] {
					returns[j] = StackAny
				}
			}
		}
		i++
	}
	return Proto{typedList{args, ""}, typedList{returns, ""}}, minVersion, true
}

func prepareVersionedPseudoTable(version uint64) map[string]map[int]OpSpec {
	m := make(map[string]map[int]OpSpec)
	for name, specs := range pseudoOps {
		m[name] = make(map[int]OpSpec)
		for numImmediates, spec := range specs {
			if isFullSpec(spec) {
				m[name][numImmediates] = spec
				continue
			}
			newSpec, ok := OpsByName[version][spec.Name]
			if ok {
				m[name][numImmediates] = newSpec
			} else {
				m[name][numImmediates] = OpsByName[AssemblerMaxVersion][spec.Name]
			}
		}
	}
	return m
}

type lineError struct {
	Line int
	Err  error
}

func (le lineError) Error() string {
	return fmt.Sprintf("%d: %s", le.Line, le.Err.Error())
}

func (le lineError) Unwrap() error {
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

// newline not included since handled in scanner
var tokenSeparators = [256]bool{'\t': true, ' ': true, ';': true}

func tokensFromLine(line string) []string {
	var tokens []string

	i := 0
	for i < len(line) && tokenSeparators[line[i]] {
		if line[i] == ';' {
			tokens = append(tokens, ";")
		}
		i++
	}

	start := i
	inString := false // tracked to allow spaces and comments inside
	inBase64 := false // tracked to allow '//' inside
	for i < len(line) {
		if !tokenSeparators[line[i]] { // if not space
			switch line[i] {
			case '"': // is a string literal?
				if !inString {
					if i == 0 || i > 0 && tokenSeparators[line[i-1]] {
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
						tokens = append(tokens, line[start:i])
					}
					return tokens
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

		// we've hit a space, end last token unless inString

		if !inString {
			token := line[start:i]
			tokens = append(tokens, token)
			if line[i] == ';' {
				tokens = append(tokens, ";")
			}
			if inBase64 {
				inBase64 = false
			} else if token == "base64" || token == "b64" {
				inBase64 = true
			}
		}
		i++

		// gobble up consecutive whitespace (but notice semis)
		if !inString {
			for i < len(line) && tokenSeparators[line[i]] {
				if line[i] == ';' {
					tokens = append(tokens, ";")
				}
				i++
			}
			start = i
		}
	}

	// add rest of the string if any
	if start < len(line) {
		tokens = append(tokens, line[start:i])
	}

	return tokens
}

func (ops *OpStream) trace(format string, args ...interface{}) {
	if ops.Trace == nil {
		return
	}
	fmt.Fprintf(ops.Trace, format, args...)
}

func (ops *OpStream) typeErrorf(format string, args ...interface{}) {
	if ops.typeTracking {
		ops.errorf(format, args...)
	}
}

// trackStack checks that the typeStack has `args` on it, then pushes `returns` to it.
func (ops *OpStream) trackStack(args StackTypes, returns StackTypes, instruction []string) {
	// If in deadcode, allow anything. Maybe it's some sort of onchain data.
	if ops.known.deadcode {
		return
	}
	argcount := len(args)
	if argcount > len(ops.known.stack) && ops.known.bottom == StackNone {
		ops.typeErrorf("%s expects %d stack arguments but stack height is %d",
			strings.Join(instruction, " "), argcount, len(ops.known.stack))
	} else {
		firstPop := true
		for i := argcount - 1; i >= 0; i-- {
			argType := args[i]
			stype := ops.known.pop()
			if firstPop {
				firstPop = false
				ops.trace("pops(%s", argType)
			} else {
				ops.trace(", %s", argType)
			}
			if !typecheck(argType, stype) {
				ops.typeErrorf("%s arg %d wanted type %s got %s",
					strings.Join(instruction, " "), i, argType, stype)
			}
		}
		if !firstPop {
			ops.trace(")")
		}
	}

	if len(returns) > 0 {
		ops.known.push(returns...)
		ops.trace(" pushes(%s", returns[0])
		if len(returns) > 1 {
			for _, rt := range returns[1:] {
				ops.trace(", %s", rt)
			}
		}
		ops.trace(")")
	}
}

// splitTokens breaks tokens into two slices at the first semicolon.
func splitTokens(tokens []string) (current, rest []string) {
	for i, token := range tokens {
		if token == ";" {
			return tokens[:i], tokens[i+1:]
		}
	}
	return tokens, nil
}

// assemble reads text from an input and accumulates the program
func (ops *OpStream) assemble(text string) error {
	fin := strings.NewReader(text)
	if ops.Version > LogicVersion && ops.Version != assemblerNoVersion {
		return ops.errorf("Can not assemble version %d", ops.Version)
	}
	scanner := bufio.NewScanner(fin)
	for scanner.Scan() {
		ops.sourceLine++
		line := scanner.Text()
		tokens := tokensFromLine(line)
		if len(tokens) > 0 {
			if first := tokens[0]; first[0] == '#' {
				directive := first[1:]
				switch directive {
				case "pragma":
					ops.pragma(tokens) //nolint:errcheck // report bad pragma line error, but continue assembling
					ops.trace("%3d: #pragma line\n", ops.sourceLine)
				default:
					ops.errorf("Unknown directive: %s", directive)
				}
				continue
			}
		}
		for current, next := splitTokens(tokens); len(current) > 0 || len(next) > 0; current, next = splitTokens(next) {
			if len(current) == 0 {
				continue
			}
			// we're about to begin processing opcodes, so settle the Version
			if ops.Version == assemblerNoVersion {
				ops.Version = AssemblerDefaultVersion
			}
			if ops.versionedPseudoOps == nil {
				ops.versionedPseudoOps = prepareVersionedPseudoTable(ops.Version)
			}
			opstring := current[0]
			if opstring[len(opstring)-1] == ':' {
				ops.createLabel(opstring[:len(opstring)-1])
				current = current[1:]
				if len(current) == 0 {
					ops.trace("%3d: label only\n", ops.sourceLine)
					continue
				}
				opstring = current[0]
			}
			spec, expandedName, ok := getSpec(ops, opstring, current[1:])
			if ok {
				ops.trace("%3d: %s\t", ops.sourceLine, opstring)
				ops.recordSourceLine()
				if spec.Modes == modeApp {
					ops.HasStatefulOps = true
				}
				args, returns := spec.Arg.Types, spec.Return.Types
				if spec.refine != nil {
					nargs, nreturns, err := spec.refine(&ops.known, current[1:])
					if err != nil {
						ops.typeErrorf("%w", err)
					}
					if nargs != nil {
						args = nargs
					}
					if nreturns != nil {
						returns = nreturns
					}
				}
				ops.trackStack(args, returns, append([]string{expandedName}, current[1:]...))
				spec.asm(ops, &spec, current[1:]) //nolint:errcheck // ignore error and continue, to collect more errors

				if spec.deadens() { // An unconditional branch deadens the following code
					ops.known.deaden()
				}
				if spec.Name == "callsub" {
					// since retsub comes back to the callsub, it is an entry point like a label
					ops.known.label()
				}
			}
			ops.trace("\n")
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			err = errors.New("line too long")
		}
		ops.error(err)
	}

	// backward compatibility: do not allow jumps past last instruction in v1
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

func (ops *OpStream) pragma(tokens []string) error {
	if tokens[0] != "#pragma" {
		return ops.errorf("invalid syntax: %s", tokens[0])
	}
	if len(tokens) < 2 {
		return ops.error("empty pragma")
	}
	key := tokens[1]
	switch key {
	case "version":
		if len(tokens) < 3 {
			return ops.error("no version value")
		}
		value := tokens[2]
		var ver uint64
		if ops.pending.Len() > 0 {
			return ops.error("#pragma version is only allowed before instructions")
		}
		ver, err := strconv.ParseUint(value, 0, 64)
		if err != nil {
			return ops.errorf("bad #pragma version: %#v", value)
		}
		if ver > AssemblerMaxVersion {
			return ops.errorf("unsupported version: %d", ver)
		}

		// We initialize Version with assemblerNoVersion as a marker for
		// non-specified version because version 0 is valid
		// version for v1.
		if ops.Version == assemblerNoVersion {
			ops.Version = ver
		} else if ops.Version != ver {
			return ops.errorf("version mismatch: assembling v%d with v%d assembler", ver, ops.Version)
		} else {
			// ops.Version is already correct, or needed to be upped.
		}
		return nil
	case "typetrack":
		if len(tokens) < 3 {
			return ops.error("no typetrack value")
		}
		value := tokens[2]
		on, err := strconv.ParseBool(value)
		if err != nil {
			return ops.errorf("bad #pragma typetrack: %#v", value)
		}
		prev := ops.typeTracking
		if !prev && on {
			ops.known.reset()
		}
		ops.typeTracking = on

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
		ops.sourceLine = lr.sourceLine // so errors get reported where the label was used
		dest, ok := ops.labels[lr.label]
		if !ok {
			if !reported[lr.label] {
				ops.errorf("reference to undefined label %#v", lr.label)
			}
			reported[lr.label] = true
			continue
		}

		// All branch targets are encoded as 2 offset bytes. The destination is relative to the end of the
		// instruction they appear in, which is available in lr.offsetPostion
		if ops.Version < backBranchEnabledVersion && dest < lr.offsetPosition {
			ops.errorf("label %#v is a back reference, back jump support was introduced in v4", lr.label)
			continue
		}
		jump := dest - lr.offsetPosition
		if jump > 0x7fff {
			ops.errorf("label %#v is too far away", lr.label)
			continue
		}
		raw[lr.position] = uint8(jump >> 8)
		raw[lr.position+1] = uint8(jump & 0x0ff)
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
	if ops.cntIntcBlock > 0 {
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
	if ops.cntBytecBlock > 0 {
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

		// This is a huge optimization for long repetitive programs. Takes
		// BenchmarkUintMath from 160sec to 19s.
		if positionDelta == 0 {
			continue
		}

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
				ops.labelReferences[i].offsetPosition += positionDelta
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
	vlen := binary.PutUvarint(scratch[:], ops.Version)
	prebytes.Write(scratch[:vlen])
	if len(ops.intc) > 0 && ops.cntIntcBlock == 0 {
		prebytes.WriteByte(OpsByName[ops.Version]["intcblock"].Opcode)
		vlen := binary.PutUvarint(scratch[:], uint64(len(ops.intc)))
		prebytes.Write(scratch[:vlen])
		for _, iv := range ops.intc {
			vlen = binary.PutUvarint(scratch[:], iv)
			prebytes.Write(scratch[:vlen])
		}
	}
	if len(ops.bytec) > 0 && ops.cntBytecBlock == 0 {
		prebytes.WriteByte(OpsByName[ops.Version]["bytecblock"].Opcode)
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
	var err lineError
	switch p := problem.(type) {
	case string:
		err = lineError{Line: line, Err: errors.New(p)}
	case error:
		err = lineError{Line: line, Err: p}
	default:
		err = lineError{Line: line, Err: fmt.Errorf("%#v", p)}
	}
	ops.Errors = append(ops.Errors, err)
	return err
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
	ops := newOpStream(version)
	err := ops.assemble(text)
	return &ops, err
}

type disassembleState struct {
	program []byte
	pc      int
	out     io.Writer

	numericTargets bool
	labelCount     int
	pendingLabels  map[int]string

	// If we find a (back) jump to a label we did not generate (because we
	// didn't know it was needed yet), rerun is set to true, and we make a
	// second attempt to disassemble once the first attempt is done. The second
	// attempt retains all the labels found in the first pass.  In effect, the
	// first attempt simply collects jump target labels for the second pass.
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

// disassemble a single opcode at program[pc] according to spec
func disassemble(dis *disassembleState, spec *OpSpec) (string, error) {
	out := spec.Name
	pc := dis.pc + 1
	for _, imm := range spec.OpDetails.Immediates {
		out += " "
		switch imm.kind {
		case immByte, immInt8:
			if pc >= len(dis.program) {
				return "", fmt.Errorf("program end while reading immediate %s for %s",
					imm.Name, spec.Name)
			}
			b := dis.program[pc]
			if imm.Group != nil {
				if int(b) >= len(imm.Group.Names) {
					return "", fmt.Errorf("invalid immediate %s for %s: %d", imm.Name, spec.Name, b)
				}
				name := imm.Group.Names[b]
				if name == "" {
					return "", fmt.Errorf("invalid immediate %s for %s: %d", imm.Name, spec.Name, b)
				}
				out += name
			} else {
				if imm.kind == immByte {
					out += fmt.Sprintf("%d", b)
				} else if imm.kind == immInt8 {
					out += fmt.Sprintf("%d", int8(b))
				}
			}
			if spec.Name == "intc" && int(b) < len(dis.intc) {
				out += fmt.Sprintf(" // %d", dis.intc[b])
			}
			if spec.Name == "bytec" && int(b) < len(dis.bytec) {
				out += fmt.Sprintf(" // %s", guessByteFormat(dis.bytec[b]))
			}

			pc++
		case immLabel:
			offset := decodeBranchOffset(dis.program, pc)
			target := offset + pc + 2
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
			out += label
			pc += 2
		case immInt:
			val, bytesUsed := binary.Uvarint(dis.program[pc:])
			if bytesUsed <= 0 {
				return "", fmt.Errorf("could not decode immediate %s for %s", imm.Name, spec.Name)
			}
			out += fmt.Sprintf("%d", val)
			pc += bytesUsed
		case immBytes:
			length, bytesUsed := binary.Uvarint(dis.program[pc:])
			if bytesUsed <= 0 {
				return "", fmt.Errorf("could not decode immediate %s for %s", imm.Name, spec.Name)
			}
			pc += bytesUsed
			end := uint64(pc) + length
			if end > uint64(len(dis.program)) || end < uint64(pc) {
				return "", fmt.Errorf("could not decode immediate %s for %s", imm.Name, spec.Name)
			}
			constant := dis.program[pc:end]
			out += fmt.Sprintf("0x%s // %s", hex.EncodeToString(constant), guessByteFormat(constant))
			pc = int(end)
		case immInts:
			intc, nextpc, err := parseIntImmArgs(dis.program, pc)
			if err != nil {
				return "", err
			}

			dis.intc = intc
			for i, iv := range intc {
				if i != 0 {
					out += " "
				}
				out += fmt.Sprintf("%d", iv)
			}
			pc = nextpc
		case immBytess:
			bytec, nextpc, err := parseByteImmArgs(dis.program, pc)
			if err != nil {
				return "", err
			}
			dis.bytec = bytec
			for i, bv := range bytec {
				if i != 0 {
					out += " "
				}
				out += fmt.Sprintf("0x%s", hex.EncodeToString(bv))
			}
			pc = nextpc
		case immLabels:
			targets, nextpc, err := parseSwitch(dis.program, pc)
			if err != nil {
				return "", err
			}

			var labels []string
			for _, target := range targets {
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
				labels = append(labels, label)
			}
			out += strings.Join(labels, " ")
			pc = nextpc
		default:
			return "", fmt.Errorf("unknown immKind %d", imm.kind)
		}
	}

	if strings.HasPrefix(spec.Name, "intc_") {
		b := spec.Name[len(spec.Name)-1] - byte('0')
		if int(b) < len(dis.intc) {
			out += fmt.Sprintf(" // %d", dis.intc[b])
		}
	}
	if strings.HasPrefix(spec.Name, "bytec_") {
		b := spec.Name[len(spec.Name)-1] - byte('0')
		if int(b) < len(dis.bytec) {
			out += fmt.Sprintf(" // %s", guessByteFormat(dis.bytec[b]))
		}
	}
	dis.nextpc = pc
	return out, nil
}

var errShortIntImmArgs = errors.New("const int list ran past end of program")
var errTooManyIntc = errors.New("const int list with too many items")

func parseIntImmArgs(program []byte, pos int) (intc []uint64, nextpc int, err error) {
	numInts, bytesUsed := binary.Uvarint(program[pos:])
	if bytesUsed <= 0 {
		err = fmt.Errorf("could not decode length of int list at pc=%d", pos)
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
			err = errShortIntImmArgs
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

func checkIntImmArgs(cx *EvalContext) error {
	var err error
	_, cx.nextpc, err = parseIntImmArgs(cx.program, cx.pc+1)
	return err
}

var errShortByteImmArgs = errors.New("const bytes list ran past end of program")
var errTooManyItems = errors.New("const bytes list with too many items")

func parseByteImmArgs(program []byte, pos int) (bytec [][]byte, nextpc int, err error) {
	numItems, bytesUsed := binary.Uvarint(program[pos:])
	if bytesUsed <= 0 {
		err = fmt.Errorf("could not decode length of bytes list at pc=%d", pos)
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
			err = errShortByteImmArgs
			return
		}
		itemLen, bytesUsed := binary.Uvarint(program[pos:])
		if bytesUsed <= 0 {
			err = fmt.Errorf("could not decode []byte const[%d] at pc=%d", i, pos)
			return
		}
		pos += bytesUsed
		if pos >= len(program) {
			err = errShortByteImmArgs
			return
		}
		end := uint64(pos) + itemLen
		if end > uint64(len(program)) || end < uint64(pos) {
			err = errShortByteImmArgs
			return
		}
		bytec[i] = program[pos : pos+int(itemLen)]
		pos += int(itemLen)
	}
	nextpc = pos
	return
}

func checkByteImmArgs(cx *EvalContext) error {
	var err error
	_, cx.nextpc, err = parseByteImmArgs(cx.program, cx.pc+1)
	return err
}

func parseSwitch(program []byte, pos int) (targets []int, nextpc int, err error) {
	numOffsets := int(program[pos])
	pos++
	end := pos + 2*numOffsets // end of op: offset is applied to this position
	for i := 0; i < numOffsets; i++ {
		offset := decodeBranchOffset(program, pos)
		target := end + offset
		targets = append(targets, target)
		pos += 2
	}
	nextpc = pos
	return
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
	var addr basics.Address

	if len(bytes) == len(addr) {
		copy(addr[:], bytes[:])
		return fmt.Sprintf("addr %s", addr)
	}
	if allPrintableASCII(bytes) {
		return fmt.Sprintf("%#v", string(bytes))
	}
	return "0x" + hex.EncodeToString(bytes)
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
		if op.Modes == modeApp {
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
		line, err = disassemble(&dis, &op)
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
