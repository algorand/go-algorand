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
	"errors"
	"fmt"
	"log"
)

const MaxBranchOffset = 0x7FFF

func CanConvert(from Version, to Version) bool {
	return from == 3 && to == 2
}

func makeConverter(inst *Instruction, from Version, to Version) (Converter, error) {
	if !CanConvert(from, to) {
		return nil, fmt.Errorf("can not convert from version %d to version %d", from, to)
	}
	switch GetOpcodeConversionType(inst.opcode) {
	case WithoutChange:
		return NewFixedInst(inst), nil
	case MemoryAccess:
		return NewMemAccessInst(inst), nil
	case MemoryWrite:
		return NewMemWriteInst(inst), nil
	case Branch:
		return NewBranchInst(inst), nil
	default:
		log.Panic("unknown opcode conversion type")
		return nil, nil
	}
}

type FixedInst struct {
	Instruction
}

func NewFixedInst(inst *Instruction) *FixedInst {
	return &FixedInst{Instruction: *inst}
}

func (f FixedInst) Convert() ([]*Instruction, error) {
	return []*Instruction{NewInstruction(f.opcode, f.operands, f.position)}, nil
}

func (f FixedInst) LengthDelta() int {
	return 0
}

type MemAccessInst struct {
	Instruction
}

func NewMemAccessInst(inst *Instruction) *MemAccessInst {
	if len(inst.operands) != 1 {
		log.Panic("invalid operands")
	}
	return &MemAccessInst{Instruction: *inst}
}

func (ma *MemAccessInst) LengthDelta() int {
	// new len is 6 old len was 2 so delta is 4
	return 4
}

func (ma *MemAccessInst) Convert() ([]*Instruction, error) {
	// 0x26 0x01 len(i) {i} 0x28 op
	return []*Instruction{
		NewInstruction(0x26, []byte{0x01, 0x01, ma.operands[0]}, ma.position),
		NewInstruction(0x28, nil, ma.position+4),
		NewInstruction(ma.opcode, nil, ma.position+5),
	}, nil
}

type MemWriteInst struct {
	Instruction
}

func NewMemWriteInst(inst *Instruction) *MemWriteInst {
	if len(inst.operands) != 1 {
		log.Panic("invalid operands")
	}
	return &MemWriteInst{Instruction: *inst}
}

func (mw MemWriteInst) Convert() ([]*Instruction, error) {
	// 0x35 0xFF 0x26 0x01 len(i) {i} 0x28 0x34 0xFF op
	return []*Instruction{
		NewInstruction(0x35, []byte{0xFF}, mw.position),
		NewInstruction(0x26, []byte{0x01, 0x01, mw.operands[0]}, mw.position+2),
		NewInstruction(0x28, nil, mw.position+6),
		NewInstruction(0x34, []byte{0xFF}, mw.position+7),
		NewInstruction(mw.opcode, nil, mw.position+9),
	}, nil
}

func (mw MemWriteInst) LengthDelta() int {
	// new len is 10 old len was 2 so delta is 8
	return 8
}

type BranchInst struct {
	Instruction
	offset     int
	translator []int
}

func NewBranchInst(inst *Instruction) *BranchInst {
	if len(inst.operands) != 2 {
		log.Panic("invalid operands for branch instruction")
	}
	return &BranchInst{
		Instruction: *inst,
		offset:      int(inst.operands[0])<<8 | int(inst.operands[1]),
	}
}

func (bi *BranchInst) Convert() ([]*Instruction, error) {
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

func (bi *BranchInst) String() string {
	return fmt.Sprintf("%s %d", bi.Instruction.String(), bi.offset)
}

func (bi *BranchInst) SetTranslator(addrTranslator interface{}) {
	bi.translator = addrTranslator.([]int)
}

func (bi *BranchInst) LengthDelta() int {
	return 0
}
