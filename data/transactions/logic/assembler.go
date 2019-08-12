package logic

import (
	"bufio"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type Writer interface {
	Write([]byte) (int, error)
	WriteByte(c byte) error
}

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
	if vlen > 0x07 {
		panic("uint val too big?")
	}
	ops.vubytes[0] = opcode | byte(vlen&0x07)
	for i := uint(0); i < vlen; i++ {
		ops.vubytes[i+1] = byte((val >> (8 * (vlen - i - 1))) & 0x0ff)
	}
	_, err := ops.out.Write(ops.vubytes[0 : 1+vlen])
	return err
}

func (ops *OpStream) Uint(val uint64) error {
	return ops.hiddenUint(0x20, val)
}

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

func (ops *OpStream) Arg(val uint64) error {
	return ops.hiddenUint(0x30, val)
}

func (ops *OpStream) Txn(val uint64) error {
	return ops.hiddenUint(0x38, val)
}

func (ops *OpStream) Global(val uint64) error {
	return ops.hiddenUint(0x40, val)
}

func (ops *OpStream) Account(val uint64) error {
	return ops.hiddenUint(0x48, val)
}

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
		val, err = base32.StdEncoding.DecodeString(arg[open+1 : close])
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
		val, err = base32.StdEncoding.DecodeString(args[1])
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

func assembleArg(ops *OpStream, args []string) error {
	val, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		return err
	}
	return ops.Arg(val)
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
	argOps["arg"] = assembleArg
}

type LineErrorWrapper struct {
	Line int
	Err  error
}

func (lew *LineErrorWrapper) Error() string {
	return fmt.Sprintf(":%d %s", lew.Line, lew.Err.Error())
}

func lineErr(line int, err error) error {
	return &LineErrorWrapper{Line: line, Err: err}
}

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
