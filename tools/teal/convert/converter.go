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
	"errors"
	"fmt"
	"log"
)

const MaxBranchOffset = 0x7FFF

type OpcodeConversionType int

const (
	WithoutChange OpcodeConversionType = iota
	// MemoryAccess instructions will be converted to [0x26 0x01 0x01 {i} 0x28 opcode]
	MemoryAccess
	// MemoryWrite instructions will be converted to [0x35 0xFF 0x26 0x01 0x01 {i} 0x28 0x34 0xFF opcode]
	MemoryWrite
	Branch
)

// OpcodeConversionGroups categorizes opcodes based on how they can be converted to older version opcodes. opcodes
// that are not in this list will be considered to be in WithoutChange group. these opcodes can be used in an older version
// teal script without any change
var OpcodeConversionGroups = [][]Opcode{
	MemoryAccess: {0x62, 0x63, 0x64, 0x65, 0x68, 0x69},
	MemoryWrite:  {0x66, 0x67},
	Branch:       {0x40, 0x41, 0x42},
}

var GetOpcodeConversionType func(Opcode) OpcodeConversionType

func init() {
	GetOpcodeConversionType = func() func(Opcode) OpcodeConversionType {
		convTypes := categorize(OpcodeConversionGroups, 256)
		return func(opcode Opcode) OpcodeConversionType {
			return OpcodeConversionType(convTypes[opcode])
		}
	}()
}

func (d *DefaultConverterMaker) CanConvert(from Version, to Version) bool {
	return from == 3 && to == 2
}

type DefaultConverterMaker struct {
}

func (d *DefaultConverterMaker) MakeConverter(inst *Instruction, from Version, to Version) (Converter, error) {
	if !d.CanConvert(from, to) {
		return nil, fmt.Errorf("can not convert from version %d to version %d", from, to)
	}
	switch GetOpcodeConversionType(inst.opcode) {
	case WithoutChange:
		return newFixedInst(inst), nil
	case MemoryAccess:
		return newMemAccessInst(inst), nil
	case MemoryWrite:
		return newMemWriteInst(inst), nil
	case Branch:
		return newBranchInst(inst), nil
	default:
		log.Panic("unknown opcode conversion type")
		return nil, nil
	}
}

type fixedInst struct {
	Instruction
}

func newFixedInst(inst *Instruction) *fixedInst {
	return &fixedInst{Instruction: *inst}
}

func (f fixedInst) Convert() ([]*Instruction, error) {
	return []*Instruction{NewInstruction(f.opcode, f.operands, f.position)}, nil
}

func (f fixedInst) LengthDelta() int {
	return 0
}

func (*fixedInst) SetTranslator(interface{}) {}

type memAccessInst struct {
	Instruction
}

func newMemAccessInst(inst *Instruction) *memAccessInst {
	if len(inst.operands) != 1 {
		log.Panic("invalid operands")
	}
	return &memAccessInst{Instruction: *inst}
}

func (ma *memAccessInst) LengthDelta() int {
	// new len is 6 old len was 2 so delta is 4
	return 4
}

func (ma *memAccessInst) Convert() ([]*Instruction, error) {
	// 0x26 0x01 len(i) {i} 0x28 op
	return []*Instruction{
		NewInstruction(0x26, []byte{0x01, 0x01, ma.operands[0]}, ma.position),
		NewInstruction(0x28, nil, ma.position+4),
		NewInstruction(ma.opcode, nil, ma.position+5),
	}, nil
}

func (*memAccessInst) SetTranslator(interface{}) {}

type memWriteInst struct {
	Instruction
}

func newMemWriteInst(inst *Instruction) *memWriteInst {
	if len(inst.operands) != 1 {
		log.Panic("invalid operands")
	}
	return &memWriteInst{Instruction: *inst}
}

func (mw memWriteInst) Convert() ([]*Instruction, error) {
	// 0x35 0xFF 0x26 0x01 len(i) {i} 0x28 0x34 0xFF op
	return []*Instruction{
		NewInstruction(0x35, []byte{0xFF}, mw.position),
		NewInstruction(0x26, []byte{0x01, 0x01, mw.operands[0]}, mw.position+2),
		NewInstruction(0x28, nil, mw.position+6),
		NewInstruction(0x34, []byte{0xFF}, mw.position+7),
		NewInstruction(mw.opcode, nil, mw.position+9),
	}, nil
}

func (mw memWriteInst) LengthDelta() int {
	// new len is 10 old len was 2 so delta is 8
	return 8
}

func (*memWriteInst) SetTranslator(interface{}) {}

type branchInst struct {
	Instruction
	offset     int
	translator []int
}

func newBranchInst(inst *Instruction) *branchInst {
	if len(inst.operands) != 2 {
		log.Panic("invalid operands for branch instruction")
	}
	return &branchInst{
		Instruction: *inst,
		offset:      int(inst.operands[0])<<8 | int(inst.operands[1]),
	}
}

func (bi *branchInst) Convert() ([]*Instruction, error) {
	if bi.translator == nil {
		log.Panic("no translator is available for offset conversion")
	}
	branchAddr := bi.position + bi.Length() + bi.offset
	if branchAddr >= len(bi.translator) || branchAddr < 0 {
		return nil, errors.New("trying to branch out of the program")
	}
	newOffset := bi.translator[branchAddr] - (bi.translator[bi.position] + bi.Length() + bi.LengthDelta())
	if newOffset > MaxBranchOffset || newOffset < 0 {
		return nil, errors.New("overflow in branch's offset")
	}
	return []*Instruction{
		NewInstruction(bi.opcode, []byte{byte(newOffset >> 8), byte(newOffset)}, bi.position),
	}, nil
}

func (bi *branchInst) String() string {
	return fmt.Sprintf("%s %d", bi.Instruction.String(), bi.offset)
}

func (bi *branchInst) SetTranslator(addrTranslator interface{}) {
	bi.translator = addrTranslator.([]int)
}

func (bi *branchInst) LengthDelta() int {
	return 0
}
