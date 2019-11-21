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
	"github.com/algorand/go-algorand/protocol"
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
	intc    []uint64
	bytec   [][]byte

	// Keep a stack of the types of what we would push and pop to typecheck a program
	typeStack []StackType

	// current sourceLine during assembly
	sourceLine int

	// map label string to position within Out buffer
	labels map[string]int

	labelReferences []labelReference
}

// SetLabelHere inserts a label reference to point to the next instruction
func (ops *OpStream) SetLabelHere(label string) error {
	if ops.labels == nil {
		ops.labels = make(map[string]int)
	}
	if _, ok := ops.labels[label]; ok {
		return fmt.Errorf("duplicate label %s", label)
	}
	ops.labels[label] = ops.Out.Len()
	return nil
}

// ReferToLabel records an opcode label refence to resolve later
func (ops *OpStream) ReferToLabel(sourceLine, pc int, label string) {
	ops.labelReferences = append(ops.labelReferences, labelReference{sourceLine, pc, label})
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
			return errors.New("cannot have more than 256 int constants")
		}
		ops.Out.WriteByte(0x21) // intc
		ops.Out.WriteByte(uint8(constIndex))
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
			return errors.New("cannot have more than 256 byte constants")
		}
		ops.Out.WriteByte(0x27) // bytec
		ops.Out.WriteByte(uint8(constIndex))
	}
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
			return errors.New("cannot have more than 256 args")
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
		return errors.New("invalid txn field")
	}
	ops.Out.WriteByte(0x31)
	ops.Out.WriteByte(uint8(val))
	ops.tpush(TxnFieldTypes[val])
	return nil
}

// Gtxn writes opcodes for loading a field from the current transaction
func (ops *OpStream) Gtxn(gid, val uint64) error {
	if val >= uint64(len(TxnFieldNames)) {
		return errors.New("invalid txn field")
	}
	if gid > 255 {
		return errors.New("gtxn cannot look up beyond group index 255")
	}
	ops.Out.WriteByte(0x33)
	ops.Out.WriteByte(uint8(gid))
	ops.Out.WriteByte(uint8(val))
	ops.tpush(TxnFieldTypes[val])
	return nil
}

// Global writes opcodes for loading an evaluator-global field
func (ops *OpStream) Global(val uint64) error {
	if val >= uint64(len(GlobalFieldNames)) {
		return errors.New("invalid txn field")
	}
	ops.Out.WriteByte(0x32)
	ops.Out.WriteByte(uint8(val))
	ops.tpush(GlobalFieldTypes[val])
	return nil
}

func assembleInt(ops *OpStream, args []string) error {
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
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return err
	}
	return ops.Uint(val)
}

// Explicit invocation of const lookup and push
func assembleIntC(ops *OpStream, args []string) error {
	constIndex, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return err
	}
	return ops.Intc(uint(constIndex))
}
func assembleByteC(ops *OpStream, args []string) error {
	constIndex, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return err
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
	} else {
		err = fmt.Errorf("byte arg did not parse: %v", arg)
		return
	}
	return
}

// byte {base64,b64,base32,b32}(...)
// byte {base64,b64,base32,b32} ...
// byte 0x....
func assembleByte(ops *OpStream, args []string) error {
	var val []byte
	var err error
	if len(args) == 0 {
		return errors.New("byte operation needs byte literal argument")
	}
	val, _, err = parseBinaryArgs(args)
	if err != nil {
		return err
	}
	return ops.ByteLiteral(val)
}

func assembleIntCBlock(ops *OpStream, args []string) error {
	ops.Out.WriteByte(0x20) // intcblock
	var scratch [binary.MaxVarintLen64]byte
	l := binary.PutUvarint(scratch[:], uint64(len(args)))
	ops.Out.Write(scratch[:l])
	for _, xs := range args {
		cu, err := strconv.ParseUint(xs, 0, 64)
		if err != nil {
			return err
		}
		l = binary.PutUvarint(scratch[:], cu)
		ops.Out.Write(scratch[:l])
	}
	return nil
}

func assembleByteCBlock(ops *OpStream, args []string) error {
	ops.Out.WriteByte(0x26) // bytecblock
	bvals := make([][]byte, 0, len(args))
	rest := args
	for len(rest) > 0 {
		val, consumed, err := parseBinaryArgs(rest)
		if err != nil {
			return err
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
	return nil
}

// addr A1EU...
// parses base32-with-checksum account address strings into a byte literal
func assembleAddr(ops *OpStream, args []string) error {
	if len(args) != 1 {
		return errors.New("addr operation needs one argument")
	}
	addr, err := basics.UnmarshalChecksumAddress(args[0])
	if err != nil {
		return err
	}
	return ops.ByteLiteral(addr[:])
}

func assembleArg(ops *OpStream, args []string) error {
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return err
	}
	return ops.Arg(val)
}

func assembleBnz(ops *OpStream, args []string) error {
	if len(args) != 1 {
		return errors.New("bnz operation needs label argument")
	}
	ops.ReferToLabel(ops.sourceLine, ops.Out.Len(), args[0])
	opcode := byte(0x40)
	spec := opsByOpcode[opcode]
	err := ops.checkArgs(spec)
	if err != nil {
		return err
	}
	ops.Out.WriteByte(opcode)
	// zero bytes will get replaced with actual offset in resolveLabels()
	ops.Out.WriteByte(0)
	ops.Out.WriteByte(0)
	return nil
}

func assembleLoad(ops *OpStream, args []string) error {
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return err
	}
	if val > EvalMaxScratchSize {
		return errors.New("load limited to 0..255")
	}
	ops.Out.WriteByte(0x34)
	ops.Out.WriteByte(byte(val))
	ops.tpush(StackAny)
	return nil
}

func assembleStore(ops *OpStream, args []string) error {
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return err
	}
	if val > EvalMaxScratchSize {
		return errors.New("store limited to 0..255")
	}
	opcode := byte(0x35)
	spec := opsByOpcode[opcode]
	err = ops.checkArgs(spec)
	if err != nil {
		return err
	}
	ops.Out.WriteByte(opcode)
	ops.Out.WriteByte(byte(val))
	return nil
}

//go:generate stringer -type=TxnField

// TxnField is an enum type for `txn` and `gtxn`
type TxnField int

const (
	// Sender Transaction.Sender
	Sender TxnField = iota
	// Fee Transaction.Fee
	Fee
	// FirstValid Transaction.FirstValid
	FirstValid
	// FirstValidTime panic
	FirstValidTime
	// LastValid Transaction.LastValid
	LastValid
	// Note Transaction.Note
	Note
	// Lease Transaction.Lease
	Lease
	// Receiver Transaction.Receiver
	Receiver
	// Amount Transaction.Amount
	Amount
	// CloseRemainderTo Transaction.CloseRemainderTo
	CloseRemainderTo
	// VotePK Transaction.VotePK
	VotePK
	// SelectionPK Transaction.SelectionPK
	SelectionPK
	// VoteFirst Transaction.VoteFirst
	VoteFirst
	// VoteLast Transaction.VoteLast
	VoteLast
	// VoteKeyDilution Transaction.VoteKeyDilution
	VoteKeyDilution
	// Type Transaction.Type
	Type
	// TypeEnum int(Transaction.Type)
	TypeEnum
	// XferAsset Transaction.XferAsset
	XferAsset
	// AssetAmount Transaction.AssetAmount
	AssetAmount
	// AssetSender Transaction.AssetSender
	AssetSender
	// AssetReceiver Transaction.AssetReceiver
	AssetReceiver
	// AssetCloseTo Transaction.AssetCloseTo
	AssetCloseTo
	// GroupIndex i for txngroup[i] == Txn
	GroupIndex
	// TxID Transaction.ID()
	TxID

	invalidTxnField // fence for some setup that loops from Sender..invalidTxnField
)

// TxnFieldNames are arguments to the 'txn' and 'txnById' opcodes
var TxnFieldNames []string
var txnFields map[string]uint

type txnFieldType struct {
	field TxnField
	ftype StackType
}

var txnFieldTypePairs = []txnFieldType{
	{Sender, StackBytes},
	{Fee, StackUint64},
	{FirstValid, StackUint64},
	{FirstValidTime, StackUint64},
	{LastValid, StackUint64},
	{Note, StackBytes},
	{Lease, StackBytes},
	{Receiver, StackBytes},
	{Amount, StackUint64},
	{CloseRemainderTo, StackBytes},
	{VotePK, StackBytes},
	{SelectionPK, StackBytes},
	{VoteFirst, StackUint64},
	{VoteLast, StackUint64},
	{VoteKeyDilution, StackUint64},
	{Type, StackBytes},
	{TypeEnum, StackUint64},
	{XferAsset, StackUint64},
	{AssetAmount, StackUint64},
	{AssetSender, StackBytes},
	{AssetReceiver, StackBytes},
	{AssetCloseTo, StackBytes},
	{GroupIndex, StackUint64},
	{TxID, StackBytes},
}

// TxnFieldTypes is StackBytes or StackUint64 parallel to TxnFieldNames
var TxnFieldTypes []StackType

// TxnTypeNames is the values of Txn.Type in enum order
var TxnTypeNames = []string{
	string(protocol.UnknownTx),
	string(protocol.PaymentTx),
	string(protocol.KeyRegistrationTx),
	string(protocol.AssetConfigTx),
	string(protocol.AssetTransferTx),
	string(protocol.AssetFreezeTx),
}

// map TxnTypeName to its enum index, for `txn TypeEnum`
var txnTypeIndexes map[string]int

// map symbolic name to uint64 for assembleInt
var txnTypeConstToUint64 map[string]uint64

func assembleTxn(ops *OpStream, args []string) error {
	if len(args) != 1 {
		return errors.New("txn expects one argument")
	}
	val, ok := txnFields[args[0]]
	if !ok {
		return fmt.Errorf("txn unknown arg %s", args[0])
	}
	return ops.Txn(uint64(val))
}

func assembleGtxn(ops *OpStream, args []string) error {
	if len(args) != 2 {
		return errors.New("gtxn expects two arguments")
	}
	gtid, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return err
	}
	val, ok := txnFields[args[1]]
	if !ok {
		return fmt.Errorf("gtxn unknown arg %s", args[0])
	}
	return ops.Gtxn(gtid, uint64(val))
}

//go:generate stringer -type=GlobalField

// GlobalField is an enum for `global` opcode
type GlobalField int

const (
	// MinTxnFee ConsensusParams.MinTxnFee
	MinTxnFee GlobalField = iota
	// MinBalance ConsensusParams.MinBalance
	MinBalance
	// MaxTxnLife ConsensusParams.MaxTxnLife
	MaxTxnLife
	// ZeroAddress [32]byte{0...}
	ZeroAddress
	// GroupSize len(txn group)
	GroupSize
	invalidGlobalField
)

// GlobalFieldNames are arguments to the 'global' opcode
var GlobalFieldNames []string

type globalFieldType struct {
	gfield GlobalField
	ftype  StackType
}

var globalFieldTypeList = []globalFieldType{
	{MinTxnFee, StackUint64},
	{MinBalance, StackUint64},
	{MaxTxnLife, StackUint64},
	{ZeroAddress, StackBytes},
	{GroupSize, StackUint64},
}

// GlobalFieldTypes is StackUint64 StackBytes in parallel with GlobalFieldNames
var GlobalFieldTypes []StackType

var globalFields map[string]uint

func assembleGlobal(ops *OpStream, args []string) error {
	if len(args) != 1 {
		return errors.New("global expects one argument")
	}
	val, ok := globalFields[args[0]]
	if !ok {
		return fmt.Errorf("global unknown arg %v", args[0])
	}
	return ops.Global(uint64(val))
}

// AccountFieldNames are arguments to the 'account' opcode
var AccountFieldNames = []string{
	"Balance",
}
var accountFields map[string]uint

// opcodesByName maps name to base opcode. Sometimes this is all we need.
var opcodesByName map[string]byte

// argOps take an immediate value and need to parse that argument from assembler code
var argOps map[string]func(*OpStream, []string) error

func init() {
	opcodesByName = make(map[string]byte)
	for _, oi := range OpSpecs {
		opcodesByName[oi.Name] = oi.Opcode
	}

	// WARNING: special case op assembly by argOps functions must do their own type stack maintenance via ops.tpop() ops.tpush()/ops.tpusha()
	argOps = make(map[string]func(*OpStream, []string) error)
	argOps["int"] = assembleInt
	argOps["intc"] = assembleIntC
	argOps["intcblock"] = assembleIntCBlock
	argOps["byte"] = assembleByte
	argOps["bytec"] = assembleByteC
	argOps["bytecblock"] = assembleByteCBlock
	argOps["addr"] = assembleAddr // parse basics.Address, actually just another []byte constant
	argOps["arg"] = assembleArg
	argOps["txn"] = assembleTxn
	argOps["gtxn"] = assembleGtxn
	argOps["global"] = assembleGlobal
	argOps["bnz"] = assembleBnz
	argOps["load"] = assembleLoad
	argOps["store"] = assembleStore
	// WARNING: special case op assembly by argOps functions must do their own type stack maintenance via ops.tpop() ops.tpush()/ops.tpusha()

	TxnFieldNames = make([]string, int(invalidTxnField))
	for fi := Sender; fi < invalidTxnField; fi++ {
		TxnFieldNames[fi] = fi.String()
	}
	txnFields = make(map[string]uint)
	for i, tfn := range TxnFieldNames {
		txnFields[tfn] = uint(i)
	}

	TxnFieldTypes = make([]StackType, int(invalidTxnField))
	for i, ft := range txnFieldTypePairs {
		if int(ft.field) != i {
			panic("txnFieldTypePairs disjoint with TxnField enum")
		}
		TxnFieldTypes[i] = ft.ftype
	}

	GlobalFieldNames = make([]string, int(invalidGlobalField))
	for i := MinTxnFee; i < invalidGlobalField; i++ {
		GlobalFieldNames[int(i)] = i.String()
	}
	GlobalFieldTypes = make([]StackType, len(GlobalFieldNames))
	for _, ft := range globalFieldTypeList {
		GlobalFieldTypes[int(ft.gfield)] = ft.ftype
	}
	globalFields = make(map[string]uint)
	for i, gfn := range GlobalFieldNames {
		globalFields[gfn] = uint(i)
	}

	accountFields = make(map[string]uint)
	for i, gfn := range AccountFieldNames {
		accountFields[gfn] = uint(i)
	}

	txnTypeIndexes = make(map[string]int, len(TxnTypeNames))
	for i, tt := range TxnTypeNames {
		txnTypeIndexes[tt] = i
	}

	txnTypeConstToUint64 = make(map[string]uint64, len(TxnTypeNames))
	for tt, v := range txnTypeIndexes {
		symbol := TypeNameDescription(tt)
		txnTypeConstToUint64[symbol] = uint64(v)
	}
}

type lineErrorWrapper struct {
	Line int
	Err  error
}

func (lew *lineErrorWrapper) Error() string {
	return fmt.Sprintf(":%d %s", lew.Line, lew.Err.Error())
}

func lineErr(line int, err error) error {
	return &lineErrorWrapper{Line: line, Err: err}
}

func typecheck(expected, got StackType) bool {
	// Some ops push 'any' and we wait for run time to see what it is.
	// Some of those 'any' are based on fields that we _could_ know now but haven't written a more detailed system of typecheck for (yet).
	if (expected == StackAny) || (got == StackAny) {
		return true
	}
	return expected == got
}

func filterFieldsForLineComment(fields []string) []string {
	for i, s := range fields {
		if strings.HasPrefix(s, "//") {
			return fields[:i]
		}
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
	for i, argType := range spec.Args {
		stype := ops.tpop()
		if firstPop {
			firstPop = false
			ops.trace("pops(%s", stype.String())
		} else {
			ops.trace(", %s", stype.String())
		}
		if !typecheck(argType, stype) {
			msg := fmt.Sprintf("%s arg %d wanted type %s got %s", spec.Name, i, argType.String(), stype.String())
			if len(ops.labelReferences) > 0 {
				fmt.Fprintf(os.Stderr, "warning: %d: %s; but branches have happened and assembler does not precisely track types in this case\n", ops.sourceLine, msg)
			} else {
				return lineErr(ops.sourceLine, errors.New(msg))
			}
		}
	}
	if !firstPop {
		ops.trace(") ")
	}
	return nil
}

// Assemble reads text from an input and accumulates the program
func (ops *OpStream) Assemble(fin io.Reader) error {
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
		fields := strings.Fields(line)
		fields = filterFieldsForLineComment(fields)
		if len(fields) == 0 {
			ops.trace("%d: no fields\n", ops.sourceLine)
			continue
		}
		opstring := fields[0]
		argf, ok := argOps[opstring]
		if ok {
			ops.trace("%3d: %s\t", ops.sourceLine, opstring)
			err := argf(ops, fields[1:])
			if err != nil {
				return lineErr(ops.sourceLine, err)
			}
			ops.trace("\n")
			continue
		}
		opcode, ok := opcodesByName[opstring]
		if ok {
			ops.trace("%3d: %s\t", ops.sourceLine, opstring)
			spec := opsByOpcode[opcode]
			err := ops.checkArgs(spec)
			if err != nil {
				return err
			}
			if spec.Returns != nil {
				ops.tpusha(spec.Returns)
				ops.trace("pushes%#v", spec.Returns)
			}
			err = ops.Out.WriteByte(opcode)
			if err != nil {
				return lineErr(ops.sourceLine, err)
			}
			ops.trace("\n")
			continue
		}
		if opstring[len(opstring)-1] == ':' {
			// create a label
			err := ops.SetLabelHere(opstring[:len(opstring)-1])
			if err != nil {
				return lineErr(ops.sourceLine, err)
			}
			continue
		}
		err := fmt.Errorf("unknown opcode %v", opstring)
		return lineErr(ops.sourceLine, err)
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
			return fmt.Errorf(":%d reference to undefined label %v", lr.sourceLine, lr.label)
		}
		// all branch instructions (currently) are opcode byte and 2 offset bytes, and the destination is relative to the next pc as if the branch was a no-op
		naturalPc := lr.position + 3
		if dest < naturalPc {
			return fmt.Errorf(":%d label %v is before reference but only forward jumps are allowed", lr.sourceLine, lr.label)
		}
		jump := dest - naturalPc
		if jump > 0x7fff {
			return fmt.Errorf(":%d label %v is too far away", lr.sourceLine, lr.label)
		}
		raw[lr.position+1] = uint8(jump >> 8)
		raw[lr.position+2] = uint8(jump & 0x0ff)
	}
	ops.Out.Reset()
	ops.Out.Write(raw)
	return nil
}

// AssemblerDefaultVersion what version of code do we emit by default
const AssemblerDefaultVersion = 1

// Bytes returns the finished program bytes
func (ops *OpStream) Bytes() (program []byte, err error) {
	var scratch [binary.MaxVarintLen64]byte
	prebytes := bytes.Buffer{}
	// TODO: configurable what version to compile for in case we're near a version boundary?
	version := ops.Version
	if version == 0 {
		//version = config.Consensus[protocol.ConsensusCurrentVersion].LogicSigVersion
		version = AssemblerDefaultVersion
	}
	vlen := binary.PutUvarint(scratch[:], version)
	prebytes.Write(scratch[:vlen])
	if len(ops.intc) > 0 {
		prebytes.WriteByte(0x20) // intcblock
		vlen := binary.PutUvarint(scratch[:], uint64(len(ops.intc)))
		prebytes.Write(scratch[:vlen])
		for _, iv := range ops.intc {
			vlen = binary.PutUvarint(scratch[:], iv)
			prebytes.Write(scratch[:vlen])
		}
	}
	if len(ops.bytec) > 0 {
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
	program = out
	return
}

// AssembleString takes an entire program in a string and assembles it to bytecode
func AssembleString(text string) ([]byte, error) {
	sr := strings.NewReader(text)
	ops := OpStream{}
	err := ops.Assemble(sr)
	if err != nil {
		return nil, err
	}
	return ops.Bytes()
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

type disassembleFunc func(dis *disassembleState)

type disassembler struct {
	name    string
	handler disassembleFunc
}

var disassemblers = []disassembler{
	{"intcblock", disIntcblock},
	{"intc", disIntc},
	{"bytecblock", disBytecblock},
	{"bytec", disBytec},
	{"arg", disArg},
	{"txn", disTxn},
	{"gtxn", disGtxn},
	{"global", disGlobal},
	{"bnz", disBnz},
	{"load", disLoad},
	{"store", disStore},
}

var disByName map[string]disassembler

func init() {
	disByName = make(map[string]disassembler)
	for _, dis := range disassemblers {
		disByName[dis.name] = dis
	}
}

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
			err = fmt.Errorf("bytecblock ran past end of program")
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
			cx.err = fmt.Errorf("bytecblock ran past end of program")
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

func disIntcblock(dis *disassembleState) {
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

func disIntc(dis *disassembleState) {
	dis.nextpc = dis.pc + 2
	_, dis.err = fmt.Fprintf(dis.out, "intc %d\n", dis.program[dis.pc+1])
}

func disBytecblock(dis *disassembleState) {
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

func disBytec(dis *disassembleState) {
	dis.nextpc = dis.pc + 2
	_, dis.err = fmt.Fprintf(dis.out, "bytec %d\n", dis.program[dis.pc+1])
}

func disArg(dis *disassembleState) {
	dis.nextpc = dis.pc + 2
	_, dis.err = fmt.Fprintf(dis.out, "arg %d\n", dis.program[dis.pc+1])
}

func disTxn(dis *disassembleState) {
	dis.nextpc = dis.pc + 2
	txarg := dis.program[dis.pc+1]
	if int(txarg) >= len(TxnFieldNames) {
		dis.err = fmt.Errorf("invalid txn arg index %d at pc=%d", txarg, dis.pc)
		return
	}
	_, dis.err = fmt.Fprintf(dis.out, "txn %s\n", TxnFieldNames[txarg])
}

func disGtxn(dis *disassembleState) {
	dis.nextpc = dis.pc + 3
	gi := dis.program[dis.pc+1]
	txarg := dis.program[dis.pc+2]
	if int(txarg) >= len(TxnFieldNames) {
		dis.err = fmt.Errorf("invalid txn arg index %d at pc=%d", txarg, dis.pc)
		return
	}
	_, dis.err = fmt.Fprintf(dis.out, "gtxn %d %s\n", gi, TxnFieldNames[txarg])
}

func disGlobal(dis *disassembleState) {
	dis.nextpc = dis.pc + 2
	garg := dis.program[dis.pc+1]
	if int(garg) >= len(GlobalFieldNames) {
		dis.err = fmt.Errorf("invalid global arg index %d at pc=%d", garg, dis.pc)
		return
	}
	_, dis.err = fmt.Fprintf(dis.out, "global %s\n", GlobalFieldNames[garg])
}

func disBnz(dis *disassembleState) {
	dis.nextpc = dis.pc + 3
	offset := (uint(dis.program[dis.pc+1]) << 8) | uint(dis.program[dis.pc+2])
	target := int(offset) + dis.pc + 3
	dis.labelCount++
	label := fmt.Sprintf("label%d", dis.labelCount)
	dis.putLabel(label, target)
	_, dis.err = fmt.Fprintf(dis.out, "bnz %s\n", label)
}

func disLoad(dis *disassembleState) {
	n := uint(dis.program[dis.pc+1])
	dis.nextpc = dis.pc + 2
	_, dis.err = fmt.Fprintf(dis.out, "load %d\n", n)
}

func disStore(dis *disassembleState) {
	n := uint(dis.program[dis.pc+1])
	dis.nextpc = dis.pc + 2
	_, dis.err = fmt.Fprintf(dis.out, "store %d\n", n)
}

// Disassemble produces a text form of program bytes.
// AssembleString(Disassemble()) should result in the same program bytes.
func Disassemble(program []byte) (text string, err error) {
	out := strings.Builder{}
	dis := disassembleState{program: program, out: &out}
	version, vlen := binary.Uvarint(program)
	if vlen <= 0 {
		fmt.Fprintf(dis.out, "// invalid version\n")
		return out.String(), nil
	}
	fmt.Fprintf(dis.out, "// version %d\n", version)
	dis.pc = vlen
	for dis.pc < len(program) {
		label, hasLabel := dis.pendingLabels[dis.pc]
		if hasLabel {
			_, dis.err = fmt.Fprintf(dis.out, "%s:\n", label)
			if dis.err != nil {
				return "", dis.err
			}
		}
		op := opsByOpcode[program[dis.pc]]
		if op.Name == "" {
			msg := fmt.Sprintf("invalid opcode %02x at pc=%d", program[dis.pc], dis.pc)
			out.WriteString(msg)
			out.WriteRune('\n')
			text = out.String()
			err = errors.New(msg)
			return
		}
		nd, hasDis := disByName[op.Name]
		if hasDis {
			nd.handler(&dis)
			if dis.err != nil {
				return "", dis.err
			}
			dis.pc = dis.nextpc
			continue
		}
		out.WriteString(op.Name)
		out.WriteRune('\n')
		dis.pc++
	}
	return out.String(), nil
}
