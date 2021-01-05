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

package converter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
)

// MaxOperandsCount is the maximum number of constants which an intcblock or a bytecblock instruction could have.
const MaxOperandsCount = 255

// MaxByteArrayLen is the maximum length which is allowed for a byte array in a bytecblock instruction.
const MaxByteArrayLen = 4 * 1024

type OpcodeLenType int

const (
	OneByte OpcodeLenType = iota
	TwoByte
	ThreeByte
	FourByte
	VarLenIntC
	VarLenByteC
)

// OpcodeLenGroups categorizes opcodes based on their instruction length. opcodes that are not in this list are
// considered to have one byte length instructions.
var OpcodeLenGroups = [][]Opcode{
	TwoByte:   {0x21, 0x27, 0x2c, 0x31, 0x32, 0x34, 0x35, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71},
	ThreeByte: {0x33, 0x36, 0x40, 0x41, 0x42, 0x51},
	FourByte:  {0x37},
	// VarLenIntC are instructions that have the same variable length format as 'incblock'
	VarLenIntC: {0x20},
	// VarLenByteC are instructions that have the same variable length format as 'bytecblock'
	VarLenByteC: {0x26},
}

var GetOpcodeLenType func(Opcode) OpcodeLenType

func init() {
	GetOpcodeLenType = func() func(Opcode) OpcodeLenType {
		lenTypes := categorize(OpcodeLenGroups, 256)
		return func(opcode Opcode) OpcodeLenType {
			return OpcodeLenType(lenTypes[opcode])
		}
	}()
}

type Reader interface {
	io.Reader
	io.ByteReader
}

// ReadInstructions reads and parses instructions from a byte-code and returns them as a slice of Instruction structs.
// It also returns the number of read bytes and the version tag of the byte-code. when an error occurs it returns a non-nil
// error but it does not return zero values for other return variables. The caller would be able to use these values
// for better error handling.
func ReadInstructions(r Reader) (code []*Instruction, bytesRead int, v Version, err error) {
	v, err = ReadVersion(r)
	if err != nil {
		return code, 1, v, err
	}
	var opcodeByte byte
	var position int
	for {
		opcodeByte, err = r.ReadByte()
		if err == io.EOF {
			return code, position, v, nil
		} else if err != nil {
			return code, position, v, err
		}
		opcode := Opcode(opcodeByte)
		var operands []byte
		switch GetOpcodeLenType(opcode) {
		case OneByte, TwoByte, ThreeByte, FourByte:
			operands = make([]byte, GetOpcodeLenType(opcode))
			_, err = io.ReadFull(r, operands)
		case VarLenIntC:
			operands, err = readOperandsIntC(r)
		case VarLenByteC:
			operands, err = readOperandsByteC(r)
		default:
			log.Panicf("length of this opcode:%d is not known", opcode)
		}
		if err != nil {
			return code, position, v, fmt.Errorf("while parsing opcode %x: %v", opcode, err)
		}
		inst := NewInstruction(opcode, operands, position)
		position += inst.Length()
		code = append(code, inst)
	}
}

func readOperandsByteC(r Reader) ([]byte, error) {
	count, got, err := readVarUint(r, MaxOperandsCount)
	if err != nil {
		return nil, err
	}
	operands := append([]byte{}, got...)
	for i := 0; i < int(count); i++ {
		length, got, err := readVarUint(r, MaxByteArrayLen)
		if err != nil {
			return nil, err
		}
		operands = append(operands, got...)
		buf := make([]byte, length)
		_, err = io.ReadFull(r, buf)
		if err != nil {
			return nil, err
		}
		operands = append(operands, buf...)
	}
	return operands, nil
}

func readOperandsIntC(r Reader) ([]byte, error) {
	count, got, err := readVarUint(r, MaxOperandsCount)
	if err != nil {
		return nil, err
	}
	operands := append([]byte{}, got...)
	for i := 0; i < int(count); i++ {
		_, got, err = readVarUint(r, math.MaxUint64)
		if err != nil {
			return nil, err
		}
		operands = append(operands, got...)
	}
	return operands, nil
}

func readVarUint(r io.ByteReader, maxValue uint64) (uint64, []byte, error) {
	value, err := binary.ReadUvarint(r)
	if value > maxValue || err != nil {
		return 0, nil, errors.New("invalid varUint")
	}
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, value)
	return value, buf[:n], nil
}
