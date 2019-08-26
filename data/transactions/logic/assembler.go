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
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/data/basics"
)

// Writer is what we want here. Satisfied by bufio.Buffer
type Writer interface {
	Write([]byte) (int, error)
	WriteByte(c byte) error
}

// OpStream is destination for program and scratch space
type OpStream struct {
	Out     bytes.Buffer
	vubytes [9]byte
	intc    []uint64
	bytec   [][]byte

	// Keep a stack of the types of what we would push and pop to typecheck a program
	typeStack []byte
}

func (ops *OpStream) tpush(argType byte) {
	ops.typeStack = append(ops.typeStack, argType)
}

func (ops *OpStream) tpop() (argType byte) {
	if len(ops.typeStack) == 0 {
		argType = opNone
		return
	}
	last := len(ops.typeStack) - 1
	argType = ops.typeStack[last]
	ops.typeStack = ops.typeStack[:last]
	return
}

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
	ops.tpush(opUint)
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
	ops.tpush(opBytes)
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
	ops.tpush(opBytes)
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

// simpleOps are just an opcode, no immediate, working on the stack
var simpleOps map[string]byte

// argOps take an immediate value and need to parse that argument from assembler code
var argOps map[string]func(*OpStream, []string) error

func assembleInt(ops *OpStream, args []string) error {
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

func parseBinaryArgs(args []string) (val []byte, consumed int, err error) {
	arg := args[0]
	if strings.HasPrefix(arg, "base32(") || strings.HasPrefix(arg, "b32(") {
		open := strings.IndexRune(arg, '(')
		close := strings.IndexRune(arg, ')')
		if close == -1 {
			err = errors.New("byte base32 arg lacks close paren")
			return
		}
		val, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(arg[open+1 : close])
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
		val, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(args[1])
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
	var scratch [11]byte
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
	var scratch [11]byte
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

// TxnFieldNames are arguments to the 'txn' and 'txnById' opcodes
var TxnFieldNames = []string{
	"Sender", "Fee", "FirstValid", "LastValid", "Note",
	"Receiver", "Amount", "CloseRemainderTo", "VotePK", "SelectionPK",
	"VoteFirst", "VoteLast", "VoteKeyDilution",
}

// TxnFieldTypes is opBytes or opUint parallel to TxnFieldNames
var TxnFieldTypes = []byte{
	opBytes, opUint, opUint, opUint, opBytes,
	opBytes, opUint, opBytes, opBytes, opBytes,
	opUint, opUint, opUint,
}

var txnFields map[string]uint

func assembleTxn(ops *OpStream, args []string) error {
	if len(args) != 1 {
		return errors.New("txn expects one argument")
	}
	val, ok := txnFields[args[0]]
	if !ok {
		return fmt.Errorf("txn unknown arg %v", args[0])
	}
	return ops.Txn(uint64(val))
}

// GlobalFieldNames are arguments to the 'global' opcode
var GlobalFieldNames = []string{
	"Round",
	"MinTxnFee",
	"MinBalance",
	"MaxTxnLife",
	"TimeStamp",
}

// GlobalFieldTypes is opUint opBytes in parallel with GlobalFieldNames
var GlobalFieldTypes = []byte{
	opUint,
	opUint,
	opUint,
	opUint,
	opUint,
}

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

func init() {
	simpleOps = make(map[string]byte)
	for _, oi := range opSpecs {
		if oi.mask == 0xff {
			simpleOps[oi.name] = oi.opcode
		}
	}

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
	argOps["global"] = assembleGlobal
	// TODO: implement account balance lookup
	//argOps["account"] = assembleAccount
	// TODO: implement lookup on other transactions (in txn group?)
	//argOps["txnById"] = assembleTxID

	txnFields = make(map[string]uint)
	for i, tfn := range TxnFieldNames {
		txnFields[tfn] = uint(i)
	}

	globalFields = make(map[string]uint)
	for i, gfn := range GlobalFieldNames {
		globalFields[gfn] = uint(i)
	}

	accountFields = make(map[string]uint)
	for i, gfn := range AccountFieldNames {
		accountFields[gfn] = uint(i)
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

func typecheck(expected, got byte) bool {
	// Some ops push 'any' and we wait for run time to see what it is.
	// Some of those 'any' are based on fields that we _could_ know now but haven't written a more detailed system of typecheck for (yet).
	if (expected == opAny) || (got == opAny) {
		return true
	}
	return expected == got
}

// Assemble reads text from an input and writes bytecode out.
// Single pass assembler, no forward references.
func (ops *OpStream) Assemble(fin io.Reader) error {
	scanner := bufio.NewScanner(fin)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, "//") {
			continue
		}
		fields := strings.Fields(line)
		opstring := fields[0]
		argf, ok := argOps[opstring]
		if ok {
			err := argf(ops, fields[1:])
			if err != nil {
				return lineErr(lineNumber, err)
			}
			continue
		}
		opcode, ok := simpleOps[opstring]
		if ok {
			spec := opsByOpcode[opcode]
			for i, argType := range spec.args {
				stype := ops.tpop()
				if !typecheck(argType, stype) {
					return fmt.Errorf(":%d %s arg %d wanted type %s got %s", lineNumber, spec.name, i, argTypeName(argType), argTypeName(stype))
				}
			}
			if spec.returns != opNone {
				ops.tpush(spec.returns)
			}
			err := ops.Out.WriteByte(opcode)
			if err != nil {
				return lineErr(lineNumber, err)
			}
			continue
		}
		return fmt.Errorf(":%d unknown opcode %v", lineNumber, opstring)
	}
	// TODO: warn if expected resulting stack is not len==1 ?
	return nil
}

func (ops *OpStream) Bytes() (program []byte, err error) {
	var scratch [11]byte
	prebytes := bytes.Buffer{}
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
