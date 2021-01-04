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

package converter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
)

const MaxOperandsCount = 255
const MaxByteArrayLen = 4 * 1024

type Reader interface {
	io.Reader
	io.ByteReader
}

type Version int

func (v *Version) Bytes() []byte {
	return []byte{byte(*v)}
}

func readVersion(r Reader) (Version, error) {
	v, err := r.ReadByte()
	return Version(v), err
}

func ReadInstructions(r Reader) (code []*Instruction, codeLength int, v Version, err error) {
	v, err = readVersion(r)
	if err != nil {
		return
	}

	var opcodeByte byte
	var position int
	for {
		opcodeByte, err = r.ReadByte()
		if err == io.EOF {
			return code, position, v, nil
		} else if err != nil {
			return
		}
		opcode := Opcode(opcodeByte)
		var operands []byte
		switch GetOpcodeLenType(opcode) {
		case oneByte, twoByte, threeByte, fourByte:
			operands = make([]byte, GetOpcodeLenType(opcode))
			_, err = io.ReadFull(r, operands)
		case varLenIntC:
			operands, err = readOperandsIntC(r)
		case varLenByteC:
			operands, err = readOperandsByteC(r)
		default:
			log.Panicf("length of this opcode:%d is not known", opcode)
		}
		if err != nil {
			err = fmt.Errorf("while parsing opcode %x: %v", opcode, err)
			return
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
		var length uint64
		length, got, err = readVarUint(r, MaxByteArrayLen)
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
