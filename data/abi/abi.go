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
	"encoding/binary"
	"fmt"
	"math/big"
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
				"number of empty placeholder unmatch with sub-tuple number")
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
	if len(argumentTypes) >= (1<<16) || len(argumentTypes) == 0 {
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

// Value struct is the ABI Value, holding ABI Type information and the ABI value representation.
type Value struct {
	ABIType Type
	value   interface{}
}

// arrayToTuple casts an array-like ABI Value into an ABI Value of Tuple type.
// This is used in both ABI Encoding and Decoding.
func (v Value) arrayToTuple() (Value, error) {
	var childT []Type
	var valueArr []Value

	switch v.ABIType.enumIndex {
	case String:
		strValue, err := v.GetString()
		if err != nil {
			return Value{}, err
		}
		strByte := []byte(strValue)
		childT, valueArr = make([]Type, len(strByte)), make([]Value, len(strByte))
		for i := 0; i < len(strByte); i++ {
			childT[i] = MakeByteType()
			valueArr[i] = MakeByte(strByte[i])
		}
	case Address:
		addr, err := v.GetAddress()
		if err != nil {
			return Value{}, err
		}
		childT, valueArr = make([]Type, 32), make([]Value, 32)
		for i := 0; i < 32; i++ {
			childT[i] = MakeByteType()
			valueArr[i] = MakeByte(addr[i])
		}
	case ArrayStatic:
		childT = make([]Type, v.ABIType.staticLength)
		for i := 0; i < int(v.ABIType.staticLength); i++ {
			childT[i] = v.ABIType.childTypes[0]
		}
		valueArr = v.value.([]Value)
	case ArrayDynamic:
		arrayElems := v.value.([]Value)
		childT = make([]Type, len(arrayElems))
		for i := 0; i < len(arrayElems); i++ {
			childT[i] = v.ABIType.childTypes[0]
		}
		valueArr = arrayElems
	default:
		return Value{}, fmt.Errorf("value type not supported to conversion to tuple")
	}

	castedTupleType, err := MakeTupleType(childT)
	if err != nil {
		return Value{}, err
	}

	return Value{
		ABIType: castedTupleType,
		value:   valueArr,
	}, nil
}

// Encode method serialize the ABI value into a byte string of ABI encoding rule.
func (v Value) Encode() ([]byte, error) {
	switch v.ABIType.enumIndex {
	case Uint:
		bigIntValue, err := v.GetUint()
		if err != nil {
			return []byte{}, err
		}
		// NOTE: ugly work-round for golang 1.14. if upgraded to 1.15, should use fillbytes
		bigIntBytes := bigIntValue.Bytes()
		buffer := make([]byte, v.ABIType.size/8-uint16(len(bigIntBytes)))
		buffer = append(buffer, bigIntBytes...)
		return buffer, nil
	case Ufixed:
		ufixedValue, err := v.GetUfixed()
		if err != nil {
			return []byte{}, err
		}
		// NOTE: ugly work-round for golang 1.14. if upgraded to 1.15, should use fillbytes
		encodeBuffer := ufixedValue.Bytes()
		buffer := make([]byte, v.ABIType.size/8-uint16(len(encodeBuffer)))
		buffer = append(buffer, encodeBuffer...)
		return buffer, nil
	case Bool:
		boolValue, err := v.GetBool()
		if err != nil {
			return []byte{}, err
		}
		if boolValue {
			return []byte{0x80}, nil
		}
		return []byte{0x00}, nil
	case Byte:
		bytesValue, err := v.GetByte()
		if err != nil {
			return []byte{}, nil
		}
		return []byte{bytesValue}, nil
	case ArrayStatic, Address:
		convertedTuple, err := v.arrayToTuple()
		if err != nil {
			return []byte{}, err
		}
		return tupleEncoding(convertedTuple)
	case ArrayDynamic, String:
		convertedTuple, err := v.arrayToTuple()
		if err != nil {
			return []byte{}, err
		}
		length := len(convertedTuple.ABIType.childTypes)
		lengthEncode := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthEncode, uint16(length))

		encoded, err := tupleEncoding(convertedTuple)
		if err != nil {
			return []byte{}, err
		}
		return append(lengthEncode, encoded...), nil
	case Tuple:
		return tupleEncoding(v)
	default:
		return []byte{}, fmt.Errorf("bruh you should not be here in encoding: unknown type error")
	}
}

// findBoolLR takes a list of type, the current index, and search direction (+1/-1).
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

// compressMultipleBool compress consecutive bool values into a byte in ABI tuple/array value.
func compressMultipleBool(valueList []Value) (uint8, error) {
	var res uint8 = 0
	if len(valueList) > 8 {
		return 0, fmt.Errorf("value list passed in should be less than length 8")
	}
	for i := 0; i < len(valueList); i++ {
		if valueList[i].ABIType.enumIndex != Bool {
			return 0, fmt.Errorf("bool type not matching in compressMultipleBool")
		}
		boolVal, err := valueList[i].GetBool()
		if err != nil {
			return 0, err
		}
		if boolVal {
			res |= 1 << uint(7-i)
		}
	}
	return res, nil
}

// tupleEncoding encodes an ABI value of tuple type into an ABI encoded byte string.
func tupleEncoding(v Value) ([]byte, error) {
	if v.ABIType.enumIndex != Tuple {
		return []byte{}, fmt.Errorf("type not supported in tupleEncoding")
	}
	if len(v.ABIType.childTypes) >= (1 << 16) {
		return []byte{}, fmt.Errorf("value abi type exceed 2^16")
	}
	tupleElems := v.value.([]Value)
	if len(tupleElems) != len(v.ABIType.childTypes) {
		return []byte{}, fmt.Errorf("tuple abi child type number unmatch with tuple argument number")
	}
	heads, tails := make([][]byte, len(v.ABIType.childTypes)), make([][]byte, len(v.ABIType.childTypes))
	isDynamicIndex := make(map[int]bool)
	for i := 0; i < len(v.ABIType.childTypes); i++ {
		if tupleElems[i].ABIType.IsDynamic() {
			headsPlaceholder := []byte{0x00, 0x00}
			heads[i] = headsPlaceholder
			isDynamicIndex[i] = true
			tailEncoding, err := tupleElems[i].Encode()
			if err != nil {
				return []byte{}, err
			}
			tails[i] = tailEncoding
		} else {
			if tupleElems[i].ABIType.enumIndex == Bool {
				// search previous bool
				before := findBoolLR(v.ABIType.childTypes, i, -1)
				// search after bool
				after := findBoolLR(v.ABIType.childTypes, i, 1)
				// append to heads and tails
				if before%8 != 0 {
					return []byte{}, fmt.Errorf("expected before has number of bool mod 8 = 0")
				}
				if after > 7 {
					after = 7
				}
				compressed, err := compressMultipleBool(tupleElems[i : i+after+1])
				if err != nil {
					return []byte{}, err
				}
				heads[i] = []byte{compressed}
				i += after
			} else {
				encodeTi, err := tupleElems[i].Encode()
				if err != nil {
					return []byte{}, err
				}
				heads[i] = encodeTi
			}
			isDynamicIndex[i] = false
		}
	}

	// adjust heads for dynamic type
	headLength := 0
	for _, headTi := range heads {
		headLength += len(headTi)
	}

	tailCurrLength := 0
	for i := 0; i < len(heads); i++ {
		if isDynamicIndex[i] {
			headValue := headLength + tailCurrLength
			if headValue >= (1 << 16) {
				return []byte{}, fmt.Errorf("encoding error: byte length exceed 2^16")
			}
			binary.BigEndian.PutUint16(heads[i], uint16(headValue))
		}
		tailCurrLength += len(tails[i])
	}

	head, tail := make([]byte, 0), make([]byte, 0)
	for i := 0; i < len(v.ABIType.childTypes); i++ {
		head = append(head, heads[i]...)
		tail = append(tail, tails[i]...)
	}
	return append(head, tail...), nil
}

// Decode takes an ABI encoded byte string and a target ABI type,
// and decodes the bytes into an ABI Value.
func Decode(valueByte []byte, valueType Type) (Value, error) {
	switch valueType.enumIndex {
	case Uint:
		if len(valueByte) != int(valueType.size)/8 {
			return Value{},
				fmt.Errorf("uint%d decode: expected byte length %d, but got byte length %d",
					valueType.size, valueType.size/8, len(valueByte))
		}
		uintValue := big.NewInt(0).SetBytes(valueByte)
		return MakeUint(uintValue, valueType.size)
	case Ufixed:
		if len(valueByte) != int(valueType.size)/8 {
			return Value{},
				fmt.Errorf("ufixed%dx%d decode: expected length %d, got byte length %d",
					valueType.size, valueType.precision, valueType.size/8, len(valueByte))
		}
		ufixedNumerator := big.NewInt(0).SetBytes(valueByte)
		return MakeUfixed(ufixedNumerator, valueType.size, valueType.precision)
	case Bool:
		if len(valueByte) != 1 {
			return Value{}, fmt.Errorf("boolean byte should be length 1 byte")
		}
		boolValue := valueByte[0] > 0
		return MakeBool(boolValue), nil
	case Byte:
		if len(valueByte) != 1 {
			return Value{}, fmt.Errorf("byte should be length 1")
		}
		return MakeByte(valueByte[0]), nil
	case ArrayStatic:
		childT := make([]Type, valueType.staticLength)
		for i := 0; i < int(valueType.staticLength); i++ {
			childT[i] = valueType.childTypes[0]
		}
		converted, err := MakeTupleType(childT)
		if err != nil {
			return Value{}, err
		}
		tupleDecoded, err := tupleDecoding(valueByte, converted)
		if err != nil {
			return Value{}, err
		}
		tupleDecoded.ABIType = valueType
		return tupleDecoded, nil
	case Address:
		if len(valueByte) != 32 {
			return Value{}, fmt.Errorf("address should be length 32")
		}
		var byteAssign [32]byte
		copy(byteAssign[:], valueByte)
		return MakeAddress(byteAssign), nil
	case ArrayDynamic:
		if len(valueByte) < 2 {
			return Value{}, fmt.Errorf("dynamic array format corrupted")
		}
		dynamicLen := binary.BigEndian.Uint16(valueByte[:2])
		childT := make([]Type, dynamicLen)
		for i := 0; i < int(dynamicLen); i++ {
			childT[i] = valueType.childTypes[0]
		}
		converted, err := MakeTupleType(childT)
		if err != nil {
			return Value{}, err
		}
		tupleDecoded, err := tupleDecoding(valueByte[2:], converted)
		if err != nil {
			return Value{}, err
		}
		tupleDecoded.ABIType = valueType
		return tupleDecoded, nil
	case String:
		if len(valueByte) < 2 {
			return Value{}, fmt.Errorf("string format corrupted")
		}
		stringLenBytes := valueByte[:2]
		byteLen := binary.BigEndian.Uint16(stringLenBytes)
		if len(valueByte[2:]) != int(byteLen) {
			return Value{}, fmt.Errorf("string representation in byte: length not matching")
		}
		return MakeString(string(valueByte[2:])), nil
	case Tuple:
		return tupleDecoding(valueByte, valueType)
	default:
		return Value{}, fmt.Errorf("decode: unknown type error")
	}
}

// tupleDecoding takes a byte string and an ABI tuple type,
// and decodes the bytes into an ABI tuple value.
func tupleDecoding(valueBytes []byte, valueType Type) (Value, error) {
	dynamicSegments, valuePartition := make([]segment, 0), make([][]byte, 0)
	iterIndex := 0
	for i := 0; i < len(valueType.childTypes); i++ {
		if valueType.childTypes[i].IsDynamic() {
			if len(valueBytes[iterIndex:]) < 2 {
				return Value{}, fmt.Errorf("ill formed tuple encoding")
			}
			dynamicIndex := binary.BigEndian.Uint16(valueBytes[iterIndex : iterIndex+2])
			if len(dynamicSegments) > 0 {
				dynamicSegments[len(dynamicSegments)-1].right = int(dynamicIndex)
			}
			dynamicSegments = append(dynamicSegments, segment{
				left:  int(dynamicIndex),
				right: -1,
			})
			valuePartition = append(valuePartition, nil)
			iterIndex += 2
		} else {
			// if bool ...
			if valueType.childTypes[i].enumIndex == Bool {
				// search previous bool
				before := findBoolLR(valueType.childTypes, i, -1)
				// search after bool
				after := findBoolLR(valueType.childTypes, i, 1)
				if before%8 == 0 {
					if after > 7 {
						after = 7
					}
					// parse bool in a byte to multiple byte strings
					for boolIndex := uint(0); boolIndex <= uint(after); boolIndex++ {
						boolMask := 0x80 >> boolIndex
						if valueBytes[iterIndex]&byte(boolMask) > 0 {
							valuePartition = append(valuePartition, []byte{0x80})
						} else {
							valuePartition = append(valuePartition, []byte{0x00})
						}
					}
					i += after
					iterIndex++
				}
			} else {
				// not bool ...
				currLen, err := valueType.childTypes[i].ByteLen()
				if err != nil {
					return Value{}, err
				}
				valuePartition = append(valuePartition, valueBytes[iterIndex:iterIndex+currLen])
				iterIndex += currLen
			}
		}
		if i != len(valueType.childTypes)-1 && iterIndex >= len(valueBytes) {
			return Value{}, fmt.Errorf("input byte not enough to decode")
		}
	}
	if len(dynamicSegments) > 0 {
		dynamicSegments[len(dynamicSegments)-1].right = len(valueBytes)
		iterIndex = len(valueBytes)
	}
	if iterIndex < len(valueBytes) {
		return Value{}, fmt.Errorf("input byte not fully consumed")
	}

	// check segment indices are valid
	segIndexArr := make([]int, len(dynamicSegments)*2)
	for index, seg := range dynamicSegments {
		segIndexArr[index*2] = seg.left
		segIndexArr[index*2+1] = seg.right
	}
	for i := 0; i < len(segIndexArr); i++ {
		if i%2 == 1 {
			if i != len(segIndexArr)-1 && segIndexArr[i] != segIndexArr[i+1] {
				return Value{}, fmt.Errorf("dynamic segment should sit next to each other")
			}
		} else {
			if segIndexArr[i] > segIndexArr[i+1] {
				return Value{}, fmt.Errorf("dynamic segment should display a [l, r] space")
			}
		}
	}

	segIndex := 0
	for i := 0; i < len(valueType.childTypes); i++ {
		if valuePartition[i] == nil {
			valuePartition[i] = valueBytes[dynamicSegments[segIndex].left:dynamicSegments[segIndex].right]
			segIndex++
		}
	}

	values := make([]Value, 0)
	for i := 0; i < len(valueType.childTypes); i++ {
		valueTi, err := Decode(valuePartition[i], valueType.childTypes[i])
		if err != nil {
			return Value{}, err
		}
		values = append(values, valueTi)
	}
	return Value{
		ABIType: valueType,
		value:   values,
	}, nil
}

// MakeUint8 takes a go `uint8` and gives an ABI Value of ABI type `uint8`.
func MakeUint8(value uint8) (Value, error) {
	bigInt := big.NewInt(int64(value))
	return MakeUint(bigInt, 8)
}

// MakeUint16 takes a go `uint16` and gives an ABI Value of ABI type `uint16`.
func MakeUint16(value uint16) (Value, error) {
	bigInt := big.NewInt(int64(value))
	return MakeUint(bigInt, 16)
}

// MakeUint32 takes a go `uint32` and gives an ABI Value of ABI type `uint32`.
func MakeUint32(value uint32) (Value, error) {
	bigInt := big.NewInt(int64(value))
	return MakeUint(bigInt, 32)
}

// MakeUint64 takes a go `uint64` and gives an ABI Value of ABI type `uint64`.
func MakeUint64(value uint64) (Value, error) {
	bigInt := big.NewInt(int64(0)).SetUint64(value)
	return MakeUint(bigInt, 64)
}

// MakeUint takes a big integer representation and a type size,
// and returns an ABI Value of ABI Uint<size> type.
func MakeUint(value *big.Int, size uint16) (Value, error) {
	typeUint, err := MakeUintType(size)
	if err != nil {
		return Value{}, err
	}
	upperLimit := big.NewInt(0).Lsh(big.NewInt(1), uint(size))
	if value.Cmp(upperLimit) >= 0 {
		return Value{}, fmt.Errorf("passed value larger than uint size %d", size)
	}
	return Value{
		ABIType: typeUint,
		value:   value,
	}, nil
}

// MakeUfixed takes a big rational number representation, a type size, and a type precision,
// and returns an ABI Value of ABI UFixed<size>x<precision>
func MakeUfixed(value *big.Int, size uint16, precision uint16) (Value, error) {
	ufixedValueType, err := MakeUfixedType(size, precision)
	if err != nil {
		return Value{}, err
	}
	uintVal, err := MakeUint(value, size)
	if err != nil {
		return Value{}, err
	}
	uintVal.ABIType = ufixedValueType
	return uintVal, nil
}

// MakeString takes a string and returns an ABI String type Value.
func MakeString(value string) Value {
	return Value{
		ABIType: MakeStringType(),
		value:   value,
	}
}

// MakeByte takes a byte and returns an ABI Byte type value.
func MakeByte(value byte) Value {
	return Value{
		ABIType: MakeByteType(),
		value:   value,
	}
}

// MakeAddress takes an [32]byte array and returns an ABI Address type value.
func MakeAddress(value [32]byte) Value {
	return Value{
		ABIType: MakeAddressType(),
		value:   value,
	}
}

// MakeDynamicArray takes an array of ABI value and returns an ABI dynamic length array value.
func MakeDynamicArray(values []Value, elemType Type) (Value, error) {
	if len(values) >= (1 << 16) {
		return Value{}, fmt.Errorf("dynamic array make error: pass in argument number larger than 2^16")
	}
	for i := 0; i < len(values); i++ {
		if !values[i].ABIType.Equal(elemType) {
			return Value{}, fmt.Errorf("type mismatch: %s and %s",
				values[i].ABIType.String(), elemType.String())
		}
	}
	return Value{
		ABIType: MakeDynamicArrayType(elemType),
		value:   values,
	}, nil
}

// MakeStaticArray takes an array of ABI value and returns an ABI static length array value.
func MakeStaticArray(values []Value) (Value, error) {
	if len(values) >= (1 << 16) {
		return Value{}, fmt.Errorf("static array make error: pass in argument number larger than 2^16")
	} else if len(values) == 0 {
		return Value{}, fmt.Errorf("static array make error: 0 argument passed in")
	}
	for i := 0; i < len(values); i++ {
		if !values[i].ABIType.Equal(values[0].ABIType) {
			return Value{}, fmt.Errorf("type mismatch: %s and %s",
				values[i].ABIType.String(), values[0].ABIType.String())
		}
	}
	return Value{
		ABIType: MakeStaticArrayType(values[0].ABIType, uint16(len(values))),
		value:   values,
	}, nil
}

// MakeTuple takes an array of ABI values and returns an ABI tuple value.
func MakeTuple(values []Value) (Value, error) {
	if len(values) >= (1 << 16) {
		return Value{}, fmt.Errorf("tuple make error: pass in argument number larger than 2^16")
	}
	tupleType := make([]Type, len(values))
	for i := 0; i < len(values); i++ {
		tupleType[i] = values[i].ABIType
	}

	castedTupleType, err := MakeTupleType(tupleType)
	if err != nil {
		return Value{}, err
	}

	return Value{
		ABIType: castedTupleType,
		value:   values,
	}, nil
}

// MakeBool takes a boolean value and returns an ABI bool value.
func MakeBool(value bool) Value {
	return Value{
		ABIType: MakeBoolType(),
		value:   value,
	}
}

// GetUint8 tries to retreve an uint8 from an ABI Value.
func (v Value) GetUint8() (uint8, error) {
	if v.ABIType.enumIndex != Uint || v.ABIType.size > 8 {
		return 0, fmt.Errorf("value type unmatch or size too large")
	}
	bigIntForm, err := v.GetUint()
	if err != nil {
		return 0, err
	}
	return uint8(bigIntForm.Uint64()), nil
}

// GetUint16 tries to retrieve an uint16 from an ABI Value.
func (v Value) GetUint16() (uint16, error) {
	if v.ABIType.enumIndex != Uint || v.ABIType.size > 16 {
		return 0, fmt.Errorf("value type unmatch or size too large")
	}
	bigIntForm, err := v.GetUint()
	if err != nil {
		return 0, err
	}
	return uint16(bigIntForm.Uint64()), nil
}

// GetUint32 tries to retrieve an uint32 from an ABI Value.
func (v Value) GetUint32() (uint32, error) {
	if v.ABIType.enumIndex != Uint || v.ABIType.size > 32 {
		return 0, fmt.Errorf("value type unmatch or size too large")
	}
	bigIntForm, err := v.GetUint()
	if err != nil {
		return 0, err
	}
	return uint32(bigIntForm.Uint64()), nil
}

// GetUint64 tries to retrieve an uint64 from an ABI Value.
func (v Value) GetUint64() (uint64, error) {
	if v.ABIType.enumIndex != Uint || v.ABIType.size > 64 {
		return 0, fmt.Errorf("value type unmatch or size too large")
	}
	bigIntForm, err := v.GetUint()
	if err != nil {
		return 0, err
	}
	return bigIntForm.Uint64(), nil
}

// GetUint tries to retrieve an big uint from an ABI Value.
func (v Value) GetUint() (*big.Int, error) {
	if v.ABIType.enumIndex != Uint {
		return nil, fmt.Errorf("value type unmatch")
	}
	bigIntForm := v.value.(*big.Int)
	sizeThreshold := big.NewInt(0).Lsh(big.NewInt(1), uint(v.ABIType.size))
	if sizeThreshold.Cmp(bigIntForm) <= 0 {
		return nil, fmt.Errorf("value is larger than uint size")
	}
	return bigIntForm, nil
}

// GetUfixed tries to retrieve an big rational number from an ABI Value.
func (v Value) GetUfixed() (*big.Int, error) {
	if v.ABIType.enumIndex != Ufixed {
		return nil, fmt.Errorf("value type unmatch, should be ufixed")
	}
	bigIntForm := v.value.(*big.Int)
	sizeThreshold := big.NewInt(0).Lsh(big.NewInt(1), uint(v.ABIType.size))
	if sizeThreshold.Cmp(bigIntForm) <= 0 {
		return nil, fmt.Errorf("value is larger than ufixed size")
	}
	return bigIntForm, nil
}

// GetString tries to retrieve a string from ABI Value.
func (v Value) GetString() (string, error) {
	if v.ABIType.enumIndex != String {
		return "", fmt.Errorf("value type unmatch, should be ufixed")
	}
	stringForm := v.value.(string)
	return stringForm, nil
}

// GetByte tries to retrieve a byte from ABI Value.
func (v Value) GetByte() (byte, error) {
	if v.ABIType.enumIndex != Byte {
		return byte(0), fmt.Errorf("value type unmatch, should be bytes")
	}
	bytesForm := v.value.(byte)
	return bytesForm, nil
}

// GetAddress tries to retrieve a [32]byte array from ABI Value.
func (v Value) GetAddress() ([32]byte, error) {
	if v.ABIType.enumIndex != Address {
		return [32]byte{}, fmt.Errorf("value type unmatch, should be address")
	}
	addressForm := v.value.([32]byte)
	return addressForm, nil
}

// GetValueByIndex retrieve value element by the index passed in
func (v Value) GetValueByIndex(index uint16) (Value, error) {
	switch v.ABIType.enumIndex {
	case ArrayDynamic:
		elements := v.value.([]Value)
		if len(elements) <= int(index) {
			return Value{}, fmt.Errorf("cannot get element: index out of scope")
		}
		return elements[index], nil
	case ArrayStatic, Tuple:
		elements := v.value.([]Value)
		if v.ABIType.staticLength <= index {
			return Value{}, fmt.Errorf("cannot get element: index out of scope")
		}
		return elements[index], nil
	default:
		return Value{}, fmt.Errorf("cannot get value by index for non array-like type")
	}
}

// GetBool tries to retrieve a boolean value from the ABI Value.
func (v Value) GetBool() (bool, error) {
	if v.ABIType.enumIndex != Bool {
		return false, fmt.Errorf("value type unmatch, should be bool")
	}
	boolForm := v.value.(bool)
	return boolForm, nil
}
