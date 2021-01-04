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
	"bytes"
	"fmt"
)

type Converter interface {
	Convert() ([]*Instruction, error)
	SetTranslator(interface{})
	Length() int
	LengthDelta() int
}

type ConverterMaker interface {
}

type Program struct {
	version    Version
	code       []*Instruction
	codeLength int
}

func NewProgram(byteCode []byte) (*Program, error) {
	code, codeLen, version, err := ReadInstructions(bytes.NewBuffer(byteCode))
	if err != nil {
		return nil, err
	}
	return &Program{
		version:    version,
		code:       code,
		codeLength: codeLen,
	}, nil
}

func (p *Program) ConvertTo(v Version) (byteCode []byte, err error) {
	converters := make([]Converter, len(p.code))
	for i, instruction := range p.code {
		converters[i], err = makeConverter(instruction, p.version, v)
		if err != nil {
			return nil, err
		}
	}
	addrMap := generateAddrMap(converters, p.codeLength)
	// write the new version tag
	byteCode = append(byteCode, v.Bytes()...)
	for _, converter := range converters {
		converter.SetTranslator(addrMap)
		instList, e := converter.Convert()
		if e != nil {
			return nil, e
		}
		for _, inst := range instList {
			byteCode = append(byteCode, inst.ByteCode()...)
		}
	}
	return
}

func (p *Program) String() string {
	return fmt.Sprintf("%v", p.code)
}

func generateAddrMap(code []Converter, codeLength int) (addrMap []int) {
	addrMap = make([]int, codeLength)
	var oldAddr, newAddr int
	for _, inst := range code {
		for i := 0; i < inst.Length(); i++ {
			addrMap[oldAddr] = newAddr
			oldAddr++
			newAddr++
		}
		newAddr += inst.LengthDelta()
	}
	return
}

type Instruction struct {
	opcode   Opcode
	operands []byte
	position int
}

func NewInstruction(o Opcode, operands []byte, position int) *Instruction {
	return &Instruction{
		opcode:   o,
		operands: operands,
		position: position,
	}
}

func (inst *Instruction) Length() int {
	return len(inst.operands) + len(inst.opcode.Bytes())
}

func (inst *Instruction) ByteCode() []byte {
	return append(inst.opcode.Bytes(), inst.operands...)
}

func (inst *Instruction) SetTranslator(interface{}) {}

func (inst *Instruction) String() string {
	return fmt.Sprintf("%d:[%x,%x]", inst.position, inst.opcode, inst.operands)
}
