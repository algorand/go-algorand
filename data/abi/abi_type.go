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

package abi

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

/*
   ABI-Types: uint<N>: An N-bit unsigned integer (8 <= N <= 512 and N % 8 = 0).
            | byte (alias for uint8)
            | ufixed <N> x <M> (8 <= N <= 512, N % 8 = 0, and 0 < M <= 160)
            | bool
            | address (alias for byte[32])
            | <type> [<N>]
            | <type> []
            | string
            | (T1, ..., Tn)
*/

// BaseType is an type-alias for uint32. A BaseType value indicates the type of an ABI value.
type BaseType uint32

const (
	// Uint is the index (0) for `Uint` type in ABI encoding.
	Uint BaseType = iota
	// Byte is the index (1) for `Byte` type in ABI encoding.
	Byte
	// Ufixed is the index (2) for `UFixed` type in ABI encoding.
	Ufixed
	// Bool is the index (3) for `Bool` type in ABI encoding.
	Bool
	// ArrayStatic is the index (4) for static length array (<type>[length]) type in ABI encoding.
	ArrayStatic
	// Address is the index (5) for `Address` type in ABI encoding (an type alias of Byte[32]).
	Address
	// ArrayDynamic is the index (6) for dynamic length array (<type>[]) type in ABI encoding.
	ArrayDynamic
	// String is the index (7) for `String` type in ABI encoding (an type alias of Byte[]).
	String
	// Tuple is the index (8) for tuple `(<type 0>, ..., <type k>)` in ABI encoding.
	Tuple
)

// Type is the struct that stores information about an ABI value's type.
type Type struct {
	enumIndex  BaseType
	childTypes []Type

	// only can be applied to `uint` size <N> or `ufixed` size <N>
	size uint16
	// only can be applied to `ufixed` precision <M>
	precision uint16

	// length for static array / tuple
	/*
		by ABI spec, len over binary array returns number of bytes
		the type is uint16, which allows for only lenth in [0, 2^16 - 1]
		representation of static length can only be constrained in uint16 type
	*/
	// NOTE may want to change back to uint32/uint64
	staticLength uint16
}

// String serialize an ABI Type to a string in ABI encoding.
func (t Type) String() string {
	switch t.enumIndex {
	case Uint:
		return "uint" + strconv.Itoa(int(t.size))
	case Byte:
		return "byte"
	case Ufixed:
		return "ufixed" + strconv.Itoa(int(t.size)) + "x" + strconv.Itoa(int(t.precision))
	case Bool:
		return "bool"
	case ArrayStatic:
		return t.childTypes[0].String() + "[" + strconv.Itoa(int(t.staticLength)) + "]"
	case Address:
		return "address"
	case ArrayDynamic:
		return t.childTypes[0].String() + "[]"
	case String:
		return "string"
	case Tuple:
		typeStrings := make([]string, len(t.childTypes))
		for i := 0; i < len(t.childTypes); i++ {
			typeStrings[i] = t.childTypes[i].String()
		}
		return "(" + strings.Join(typeStrings, ",") + ")"
	default:
		panic("Bruh you should not be here")
	}
}

// TypeFromString de-serialize ABI type from a string following ABI encoding.
func TypeFromString(str string) (Type, error) {
	switch {
	case strings.HasSuffix(str, "[]"):
		arrayArgType, err := TypeFromString(str[:len(str)-2])
		if err != nil {
			return arrayArgType, err
		}
		return MakeDynamicArrayType(arrayArgType), nil
	case strings.HasSuffix(str, "]"):
		stringMatches := regexp.MustCompile(`^([a-z\d\[\](),]+)\[([1-9][\d]*)]$`).FindStringSubmatch(str)
		// match the string itself, array element type, then array length
		if len(stringMatches) != 3 {
			return Type{}, fmt.Errorf("static array ill formated: %s", str)
		}
		// guaranteed that the length of array is existing
		arrayLengthStr := stringMatches[2]
		arrayLength, err := strconv.ParseUint(arrayLengthStr, 10, 16)
		if err != nil {
			return Type{}, err
		}
		// parse the array element type
		arrayType, err := TypeFromString(stringMatches[1])
		if err != nil {
			return Type{}, err
		}
		return MakeStaticArrayType(arrayType, uint16(arrayLength)), nil
	case strings.HasPrefix(str, "uint"):
		typeSize, err := strconv.ParseUint(str[4:], 10, 16)
		if err != nil {
			return Type{}, fmt.Errorf("ill formed uint type: %s", str)
		}
		return MakeUintType(uint16(typeSize))
	case str == "byte":
		return MakeByteType(), nil
	case strings.HasPrefix(str, "ufixed"):
		stringMatches := regexp.MustCompile(`^ufixed([1-9][\d]*)x([1-9][\d]*)$`).FindStringSubmatch(str)
		// match string itself, then type-size, and type-precision
		if len(stringMatches) != 3 {
			return Type{}, fmt.Errorf("ill formed ufixed type: %s", str)
		}
		// guaranteed that there are 2 uint strings in ufixed string
		ufixedSize, err := strconv.ParseUint(stringMatches[1], 10, 16)
		if err != nil {
			return Type{}, err
		}
		ufixedPrecision, err := strconv.ParseUint(stringMatches[2], 10, 16)
		if err != nil {
			return Type{}, err
		}
		return MakeUfixedType(uint16(ufixedSize), uint16(ufixedPrecision))
	case str == "bool":
		return MakeBoolType(), nil
	case str == "address":
		return MakeAddressType(), nil
	case str == "string":
		return MakeStringType(), nil
	case len(str) > 2 && str[0] == '(' && str[len(str)-1] == ')':
		tupleContent, err := parseTupleContent(str[1 : len(str)-1])
		if err != nil {
			return Type{}, err
		}
		tupleTypes := make([]Type, len(tupleContent))
		for i := 0; i < len(tupleContent); i++ {
			ti, err := TypeFromString(tupleContent[i])
			if err != nil {
				return Type{}, err
			}
			tupleTypes[i] = ti
		}
		return MakeTupleType(tupleTypes)
	default:
		return Type{}, fmt.Errorf("cannot convert a string %s to an ABI type", str)
	}
}

// segment keeps track of the start and end of a segment in a string.
type segment struct{ left, right int }

// parseTupleContent splits an ABI encoded string for tuple type into multiple sub-strings.
// Each sub-string represents a content type of the tuple type.
func parseTupleContent(str string) ([]string, error) {
	// argument str is the content between parentheses of tuple, i.e.
	// (...... str ......)
	//  ^               ^
	parenSegmentRecord := make([]segment, 0)
	stack := make([]int, 0)
	// get the most exterior parentheses segment (not overlapped by other parentheses)
	// illustration: "*****,(*****),*****" => ["*****", "(*****)", "*****"]
	for index, chr := range str {
		if chr == '(' {
			stack = append(stack, index)
		} else if chr == ')' {
			if len(stack) == 0 {
				return []string{}, fmt.Errorf("unpaired parentheses: %s", str)
			}
			leftParenIndex := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				parenSegmentRecord = append(parenSegmentRecord, segment{
					left:  leftParenIndex,
					right: index,
				})
			}
		}
	}
	if len(stack) != 0 {
		return []string{}, fmt.Errorf("unpaired parentheses: %s", str)
	}

	// kudos to Jason Paulos
	if strings.Contains(str, ",,") {
		return []string{}, fmt.Errorf("no consecutive commas")
	}

	// take out tuple-formed type str in tuple argument
	strCopied := str
	for i := len(parenSegmentRecord) - 1; i >= 0; i-- {
		parenSeg := parenSegmentRecord[i]
		strCopied = strCopied[:parenSeg.left] + strCopied[parenSeg.right+1:]
	}

	// maintain list of empty strings as placeholders for tuple-formed type str
	tupleStrSegs := strings.Split(strCopied, ",")
	emptyStrIndex := make([]int, 0)
	for index, segStr := range tupleStrSegs {
		if segStr == "" {
			emptyStrIndex = append(emptyStrIndex, index)
		}
	}

	// check if the number of empty block placeholder is equal to number of sub-tuples
	// if number do not match, this might be incurred by head/tail commas
	// e.g. (,uint64,(bool,bool)) => ["", uint64, ""], with sub-tuple ["(bool,bool)"]
	if len(emptyStrIndex) != len(parenSegmentRecord) {
		return []string{},
			fmt.Errorf("parsing error: cannot replace tuple segment back: " +
				"number of empty placeholders do not match with number of sub-tuples")
	}

	// replace back the tuple-formed type str
	for index, replaceIndex := range emptyStrIndex {
		tupleStrSegs[replaceIndex] = str[parenSegmentRecord[index].left : parenSegmentRecord[index].right+1]
	}

	return tupleStrSegs, nil
}

// MakeUintType makes `Uint` ABI type by taking a type size argument.
// The range of type size is [8, 512] and type size % 8 == 0.
func MakeUintType(typeSize uint16) (Type, error) {
	if typeSize%8 != 0 || typeSize < 8 || typeSize > 512 {
		return Type{}, fmt.Errorf("unsupported uint type size: %d", typeSize)
	}
	return Type{
		enumIndex: Uint,
		size:      typeSize,
	}, nil
}

// MakeByteType makes `Byte` ABI type.
func MakeByteType() Type {
	return Type{
		enumIndex: Byte,
	}
}

// MakeUfixedType makes `UFixed` ABI type by taking type size and type precision as arguments.
// The range of type size is [8, 512] and type size % 8 == 0.
// The range of type precision is [1, 160].
func MakeUfixedType(typeSize uint16, typePrecision uint16) (Type, error) {
	if typeSize%8 != 0 || typeSize < 8 || typeSize > 512 {
		return Type{}, fmt.Errorf("unsupported ufixed type size: %d", typeSize)
	}
	if typePrecision > 160 || typePrecision < 1 {
		return Type{}, fmt.Errorf("unsupported ufixed type precision: %d", typePrecision)
	}
	return Type{
		enumIndex: Ufixed,
		size:      typeSize,
		precision: typePrecision,
	}, nil
}

// MakeBoolType makes `Bool` ABI type.
func MakeBoolType() Type {
	return Type{
		enumIndex: Bool,
	}
}

// MakeStaticArrayType makes static length array ABI type by taking
// array element type and array length as arguments.
func MakeStaticArrayType(argumentType Type, arrayLength uint16) Type {
	return Type{
		enumIndex:    ArrayStatic,
		childTypes:   []Type{argumentType},
		staticLength: arrayLength,
	}
}

// MakeAddressType makes `Address` ABI type.
func MakeAddressType() Type {
	return Type{
		enumIndex: Address,
	}
}

// MakeDynamicArrayType makes dynamic length array by taking array element type as argument.
func MakeDynamicArrayType(argumentType Type) Type {
	return Type{
		enumIndex:  ArrayDynamic,
		childTypes: []Type{argumentType},
	}
}

// MakeStringType makes `String` ABI type.
func MakeStringType() Type {
	return Type{
		enumIndex: String,
	}
}

// MakeTupleType makes tuple ABI type by taking an array of tuple element types as argument.
func MakeTupleType(argumentTypes []Type) (Type, error) {
	if len(argumentTypes) >= (1 << 16) {
		return Type{}, fmt.Errorf("tuple type child type number >= 2^16 error")
	}
	return Type{
		enumIndex:    Tuple,
		childTypes:   argumentTypes,
		staticLength: uint16(len(argumentTypes)),
	}, nil
}

// Equal method decides the equality of two types: t == t0.
func (t Type) Equal(t0 Type) bool {
	if t.enumIndex != t0.enumIndex {
		return false
	} else if t.precision != t0.precision || t.size != t0.size {
		return false
	} else if t.staticLength != t0.staticLength {
		return false
	} else {
		if len(t.childTypes) != len(t0.childTypes) {
			return false
		}
		for i := 0; i < len(t.childTypes); i++ {
			if !t.childTypes[i].Equal(t0.childTypes[i]) {
				return false
			}
		}
	}
	return true
}

// IsDynamic method decides if an ABI type is dynamic or static.
func (t Type) IsDynamic() bool {
	switch t.enumIndex {
	case ArrayDynamic, String:
		return true
	default:
		for _, childT := range t.childTypes {
			if childT.IsDynamic() {
				return true
			}
		}
		return false
	}
}

// Assume that the current index on the list of type is an ABI bool type.
// It returns the difference between the current index and the index of the furthest consecutive Bool type.
func findBoolLR(typeList []Type, index int, delta int) int {
	until := 0
	for {
		curr := index + delta*until
		if typeList[curr].enumIndex == Bool {
			if curr != len(typeList)-1 && delta > 0 {
				until++
			} else if curr > 0 && delta < 0 {
				until++
			} else {
				break
			}
		} else {
			until--
			break
		}
	}
	return until
}

// ByteLen method calculates the byte length of a static ABI type.
func (t Type) ByteLen() (int, error) {
	switch t.enumIndex {
	case Address:
		return 32, nil
	case Byte:
		return 1, nil
	case Uint, Ufixed:
		return int(t.size / 8), nil
	case Bool:
		return 1, nil
	case ArrayStatic:
		if t.childTypes[0].enumIndex == Bool {
			byteLen := int(t.staticLength) / 8
			if t.staticLength%8 != 0 {
				byteLen++
			}
			return byteLen, nil
		}
		elemByteLen, err := t.childTypes[0].ByteLen()
		if err != nil {
			return -1, err
		}
		return int(t.staticLength) * elemByteLen, nil
	case Tuple:
		size := 0
		for i := 0; i < len(t.childTypes); i++ {
			if t.childTypes[i].enumIndex == Bool {
				// search previous bool
				before := findBoolLR(t.childTypes, i, -1)
				// search after bool
				after := findBoolLR(t.childTypes, i, 1)
				// append to heads and tails
				if before%8 != 0 {
					return -1, fmt.Errorf("expected before has number of bool mod 8 = 0")
				}
				if after > 7 {
					after = 7
				}
				i += after
				size++
			} else {
				childByteSize, err := t.childTypes[i].ByteLen()
				if err != nil {
					return -1, err
				}
				size += childByteSize
			}
		}
		return size, nil
	default:
		return -1, fmt.Errorf("%s is a dynamic type", t.String())
	}
}
