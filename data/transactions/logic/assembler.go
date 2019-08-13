package logic

import (
	"bufio"
	"bytes"
	"encoding/base32"
	"encoding/base64"
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
	out     Writer
	vubytes [9]byte
}

func (ops *OpStream) hiddenUint(opcode byte, val uint64) error {
	vlen := uint(0)
	tv := val
	for tv > 0 {
		vlen++
		tv = tv >> 8
	}
	if vlen > 8 {
		panic("uint val too big?")
	}
	if vlen == 8 {
		// 8 is encoded as 7 in the opcode.
		// if we're loading 7 bytes, we load 8 bytes, not much waste.
		// if we're loading 0 bytes, we get a handy 0 value.
		ops.vubytes[0] = opcode | 0x07
	} else {
		ops.vubytes[0] = opcode | byte(vlen&0x07)
	}
	for i := uint(0); i < vlen; i++ {
		ops.vubytes[i+1] = byte((val >> (8 * (vlen - i - 1))) & 0x0ff)
	}
	_, err := ops.out.Write(ops.vubytes[0 : 1+vlen])
	return err
}

// Uint writes opcodes for loading a uint literal
func (ops *OpStream) Uint(val uint64) error {
	return ops.hiddenUint(0x20, val)
}

// ByteLiteral writes opcodes and data for loading a []byte literal
func (ops *OpStream) ByteLiteral(val []byte) error {
	if len(val) == 0 {
		return ops.out.WriteByte(0x28)
	}
	err := ops.hiddenUint(0x28, uint64(len(val)))
	if err != nil {
		return err
	}
	_, err = ops.out.Write(val)
	return err
}

// Arg writes opcodes for loading from Lsig.Args
func (ops *OpStream) Arg(val uint64) error {
	return ops.hiddenUint(0x30, val)
}

// Txn writes opcodes for loading a field from the current transaction
func (ops *OpStream) Txn(val uint64) error {
	return ops.hiddenUint(0x38, val)
}

// Global writes opcodes for loading an evaluator-global field
func (ops *OpStream) Global(val uint64) error {
	return ops.hiddenUint(0x40, val)
}

// Account writes opcodes for loading a field from some account
func (ops *OpStream) Account(val uint64) error {
	return ops.hiddenUint(0x48, val)
}

// TxID writes opcodes for loading a field from some other transaction
func (ops *OpStream) TxID(val uint64) error {
	return ops.hiddenUint(0x50, val)
}

var simpleOps map[string]byte

var argOps map[string]func(*OpStream, []string) error

func assembleInt(ops *OpStream, args []string) error {
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return err
	}
	return ops.Uint(val)
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
	arg := args[0]
	if strings.HasPrefix(arg, "base32(") || strings.HasPrefix(arg, "b32(") {
		open := strings.IndexRune(arg, '(')
		close := strings.IndexRune(arg, ')')
		if close == -1 {
			return errors.New("byte base32 arg lacks close paren")
		}
		val, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(arg[open+1 : close])
		if err != nil {
			return err
		}
	} else if strings.HasPrefix(arg, "base64(") || strings.HasPrefix(arg, "b64(") {
		open := strings.IndexRune(arg, '(')
		close := strings.IndexRune(arg, ')')
		if close == -1 {
			return errors.New("byte base64 arg lacks close paren")
		}
		val, err = base64.StdEncoding.DecodeString(arg[open+1 : close])
		if err != nil {
			return err
		}
	} else if strings.HasPrefix(arg, "0x") {
		val, err = hex.DecodeString(arg[2:])
		if err != nil {
			return err
		}
	} else if arg == "base32" || arg == "b32" {
		if len(args) < 2 {
			return fmt.Errorf("need literal after 'byte %s'", arg)
		}
		val, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(args[1])
		if err != nil {
			return err
		}
	} else if arg == "base64" || arg == "b64" {
		if len(args) < 2 {
			return fmt.Errorf("need literal after 'byte %s'", arg)
		}
		val, err = base64.StdEncoding.DecodeString(args[1])
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("byte arg did not parse: %v", arg)
	}
	return ops.ByteLiteral(val)
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

func assembleAccount(ops *OpStream, args []string) error {
	if len(args) != 1 {
		return errors.New("account expects one argument")
	}
	val, ok := accountFields[args[0]]
	if !ok {
		return fmt.Errorf("account unknown arg %v", args[0])
	}
	return ops.Account(uint64(val))
}

func assembleTxID(ops *OpStream, args []string) error {
	if len(args) != 1 {
		return errors.New("txnById expects one argument")
	}
	val, ok := txnFields[args[0]]
	if !ok {
		return fmt.Errorf("txnById unknown arg %v", args[0])
	}
	return ops.TxID(uint64(val))
}

func init() {
	simpleOps = make(map[string]byte)
	for _, oi := range opSpecs {
		if oi.mask == 0xff {
			simpleOps[oi.name] = oi.opcode
		}
	}

	argOps = make(map[string]func(*OpStream, []string) error)
	argOps["int"] = assembleInt
	argOps["byte"] = assembleByte
	argOps["addr"] = assembleAddr
	argOps["arg"] = assembleArg
	argOps["txn"] = assembleTxn
	argOps["global"] = assembleGlobal
	argOps["account"] = assembleAccount
	argOps["txnById"] = assembleTxID

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
		opcode, ok := simpleOps[opstring]
		if ok {
			err := ops.out.WriteByte(opcode)
			if err != nil {
				return lineErr(lineNumber, err)
			}
			continue
		}
		argf, ok := argOps[opstring]
		if ok {
			err := argf(ops, fields[1:])
			if err != nil {
				return lineErr(lineNumber, err)
			}
			continue
		}
		return fmt.Errorf(":%d unknown opcode %v", lineNumber, opstring)
	}
	return nil
}

// AssembleString takes an entire program in a string and assembles it to bytecode
func AssembleString(text string) ([]byte, error) {
	sr := strings.NewReader(text)
	pbytes := bytes.Buffer{}
	ops := OpStream{out: &pbytes}
	err := ops.Assemble(sr)
	if err != nil {
		return nil, err
	}
	return pbytes.Bytes(), nil
}
