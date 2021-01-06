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
	"bytes"
	"fmt"
)

// Converter represents an instruction which can convert itself to a sequence of instructions of another version.
type Converter interface {
	// Convert converts the Converter to a sequence of instruction in another version. if the conversion is not
	// possible it returns an error
	Convert() ([]*Instruction, error)
	// SetTranslator provides Converter with additional information it might need for conversion
	SetTranslator(interface{})
	// Length is the length of the byte-code of a Converter before conversion
	Length() int
	// LengthDelta represents the change in the byte-code's length of a Converter after conversion
	LengthDelta() int
}

// Maker is responsible for transforming an Instruction to a Converter.
type Maker interface {
	// MakeConverter transforms 'inst' from a script of version 'from' to a Converter which can be converted to a
	// script of version 'to'.
	MakeConverter(inst *Instruction, from Version, to Version) (Converter, error)
}

type Opcode byte

func (o Opcode) Bytes() []byte {
	return []byte{byte(o)}
}

type Version int

func (v Version) Bytes() []byte {
	return []byte{byte(v)}
}

func ReadVersion(r Reader) (Version, error) {
	v, err := r.ReadByte()
	return Version(v), err
}

// categorize makes a category mapping for members of opcode groups specified by 'groups' parameter. Category of
// members that are not in 'groups' list will be considered 0.
func categorize(groups [][]Opcode, resultSize int) (categoryMap []int) {
	categoryMap = make([]int, resultSize)
	for i, group := range groups {
		for _, member := range group {
			categoryMap[member] = i
		}
	}
	return categoryMap
}

type Program struct {
	version        Version
	code           []*Instruction
	codeLength     int
	converterMaker Maker
}

// NewProgram parses the 'byteCode' and creates a Program from it. By default it will initialize Program's converter
// maker with a DefaultConverterMaker. if the user needs to use another converter.Maker he can change this by using
// SetConverterMaker method.
func NewProgram(byteCode []byte) (*Program, error) {
	code, codeLen, version, err := ReadInstructions(bytes.NewBuffer(byteCode))
	if err != nil {
		return nil, err
	}
	return &Program{
		version:        version,
		code:           code,
		codeLength:     codeLen,
		converterMaker: new(DefaultConverterMaker),
	}, nil
}

func (p *Program) Version() Version {
	return p.version
}

func (p *Program) SetConverterMaker(converterMaker Maker) {
	p.converterMaker = converterMaker
}

// ConvertTo returns the converted byte-code of the Program to a byte-code of version 'v'.
func (p *Program) ConvertTo(v Version) (byteCode []byte, err error) {
	converters := make([]Converter, len(p.code))
	for i, instruction := range p.code {
		converters[i], err = p.converterMaker.MakeConverter(instruction, p.version, v)
		if err != nil {
			return nil, err
		}
	}
	addrMap := generateAddrMap(converters, p.codeLength)
	// write the new version tag
	byteCode = append(byteCode, v.Bytes()...)
	for _, converter := range converters {
		converter.SetTranslator(addrMap)
		instList, err := converter.Convert()
		if err != nil {
			return nil, err
		}
		for _, inst := range instList {
			byteCode = append(byteCode, inst.ByteCode()...)
		}
	}
	return byteCode, nil
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

// Instruction is an immutable struct that represents a binary instruction.
type Instruction struct {
	opcode   Opcode
	operands []byte
	position int
}

// NewInstruction creates a new Instruction. 'position' is the address of the instruction in the bytecode.
//
// NewInstruction does not copy the 'operands' byte slice and the caller should not keep any references to it.
func NewInstruction(o Opcode, operands []byte, position int) *Instruction {
	return &Instruction{
		opcode:   o,
		operands: operands,
		position: position,
	}
}

func (inst *Instruction) Operands() []byte {
	cp := make([]byte, len(inst.operands))
	copy(cp, inst.operands)
	return cp
}

func (inst *Instruction) Position() int {
	return inst.position
}

func (inst *Instruction) Opcode() Opcode {
	return inst.opcode
}

// Length is the number of bytes the byte-code of this instruction has.
func (inst *Instruction) Length() int {
	return len(inst.operands) + len(inst.opcode.Bytes())
}

func (inst *Instruction) ByteCode() []byte {
	return append(inst.opcode.Bytes(), inst.operands...)
}

func (inst *Instruction) String() string {
	return fmt.Sprintf("%d:[%x,%x]", inst.position, inst.opcode, inst.operands)
}
