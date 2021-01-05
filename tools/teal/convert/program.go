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

package convert

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

type Maker interface {
	MakeConverter(inst *Instruction, from Version, to Version) (Converter, error)
}

type Opcode byte

func (o *Opcode) Bytes() []byte {
	return []byte{byte(*o)}
}

type Version int

func (v *Version) Bytes() []byte {
	return []byte{byte(*v)}
}

func ReadVersion(r Reader) (Version, error) {
	v, err := r.ReadByte()
	return Version(v), err
}

// categorize makes a categoryMap for members of 'groups'. category of members that are not in groups list will
// be considered 0
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

// ConvertTo returns the converted code of the Program to a byte-code of version 'v'.
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

func (inst *Instruction) String() string {
	return fmt.Sprintf("%d:[%x,%x]", inst.position, inst.opcode, inst.operands)
}
