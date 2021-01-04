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

type Opcode byte
type OpcodeLenType int
type OpcodeConversionType int

const (
	oneByte OpcodeLenType = iota
	twoByte
	threeByte
	fourByte
	varLenIntC
	varLenByteC
)

// OpcodeLenGroups categorizes opcodes based on their instruction length. opcodes that are not in this list will
// be considered 1 byte length
var OpcodeLenGroups = [][]Opcode{
	twoByte:     {0x21, 0x27, 0x2c, 0x31, 0x32, 0x34, 0x35, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71},
	threeByte:   {0x33, 0x36, 0x40, 0x41, 0x42, 0x51},
	fourByte:    {0x37},
	varLenIntC:  {0x20},
	varLenByteC: {0x26},
}

const (
	WithoutChange OpcodeConversionType = iota
	MemoryAccess
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

var GetOpcodeLenType func(Opcode) OpcodeLenType
var GetOpcodeConversionType func(Opcode) OpcodeConversionType

func init() {
	GetOpcodeLenType = func() func(Opcode) OpcodeLenType {
		lenTypes := categorize(OpcodeLenGroups, 256)
		return func(opcode Opcode) OpcodeLenType {
			return OpcodeLenType(lenTypes[opcode])
		}
	}()

	GetOpcodeConversionType = func() func(Opcode) OpcodeConversionType {
		convTypes := categorize(OpcodeConversionGroups, 256)
		return func(opcode Opcode) OpcodeConversionType {
			return OpcodeConversionType(convTypes[opcode])
		}

	}()
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

func (o *Opcode) Bytes() []byte {
	return []byte{byte(*o)}
}
