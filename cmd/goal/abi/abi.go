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
	"unicode"
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
	typeFromEnum BaseType
	childTypes   []Type

	// only can be applied to `uint` size <N> or `ufixed` size <N>
	typeSize uint16
	// only can be applied to `ufixed` precision <M>
	typePrecision uint16

	// length for static array / tuple
	/*
		by ABI spec, len over binary array returns number of bytes
		the type is uint16, which allows for only lenth in [0, 2^16 - 1]
		representation of static length can only be constrained in uint16 type
	*/
	// TODO may want to change back to uint32/uint64
	staticLength uint16
}

// String serialize an ABI Type to a string in ABI encoding.
func (t Type) String() string {
	switch t.typeFromEnum {
	case Uint:
		return "uint" + strconv.Itoa(int(t.typeSize))
	case Byte:
		return "byte"
	case Ufixed:
		return "ufixed" + strconv.Itoa(int(t.typeSize)) + "x" + strconv.Itoa(int(t.typePrecision))
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
		return "Bruh you should not be here"
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
	case strings.HasSuffix(str, "]") && len(str) >= 2 && unicode.IsDigit(rune(str[len(str)-2])):
		stringMatches := regexp.MustCompile(`^[a-z\d\[\](),]+\[([1-9][\d]*)]$`).FindStringSubmatch(str)
		// match the string itself, then array length
		if len(stringMatches) != 2 {
			return Type{}, fmt.Errorf("static array ill formated: %s", str)
		}
		// guaranteed that the length of array is existing
		arrayLengthStr := stringMatches[1]
		arrayLength, err := strconv.ParseUint(arrayLengthStr, 10, 32)
		if err != nil {
			return Type{}, err
		}
		// parse the array element type
		arrayType, err := TypeFromString(str[:len(str)-(2+len(arrayLengthStr))])
		if err != nil {
			return Type{}, err
		}
		return MakeStaticArrayType(arrayType, uint16(arrayLength)), nil
	case strings.HasPrefix(str, "uint"):
		typeSize, err := strconv.ParseUint(str[4:], 10, 16)
		if err != nil {
			return Type{}, fmt.Errorf("ill formed uint type: %s", str)
		}
		uintTypeRes, err := MakeUintType(uint16(typeSize))
		if err != nil {
			return Type{}, err
		}
		return uintTypeRes, nil
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
		ufixedTypeRes, err := MakeUFixedType(uint16(ufixedSize), uint16(ufixedPrecision))
		if err != nil {
			return Type{}, err
		}
		return ufixedTypeRes, nil
	case str == "bool":
		return MakeBoolType(), nil
	case str == "address":
		return MakeAddressType(), nil
	case str == "string":
		return MakeStringType(), nil
	case len(str) > 2 && str[0] == '(' && str[len(str)-1] == ')':
		if strings.Contains(str[1:len(str)-1], " ") {
			return Type{}, fmt.Errorf("tuple should not contain space")
		}
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
		return MakeTupleType(tupleTypes), nil
	default:
		return Type{}, fmt.Errorf("cannot convert a string %s to an ABI type", str)
	}
}

// segmentIndex keeps track of the start and end of a segment in a string.
type segmentIndex struct{ left, right int }

// parseTupleContent splits an ABI encoded string for tuple type into multiple sub-strings.
// Each sub-string represents a content type of the tuple type.
func parseTupleContent(str string) ([]string, error) {
	// argument str is the content between parentheses of tuple, i.e.
	// (...... str ......)
	//  ^               ^
	parenSegmentRecord, stack := make([]segmentIndex, 0), make([]int, 0)
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
				parenSegmentRecord = append(parenSegmentRecord, segmentIndex{
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
		segment := parenSegmentRecord[i]
		strCopied = strCopied[:segment.left] + strCopied[segment.right+1:]
	}

	// maintain list of empty strings as placeholders for tuple-formed type str
	segments := strings.Split(strCopied, ",")
	emptyStrIndex := make([]int, 0)
	for index, str := range segments {
		if str == "" {
			emptyStrIndex = append(emptyStrIndex, index)
		}
	}

	if len(emptyStrIndex) != len(parenSegmentRecord) {
		return []string{}, fmt.Errorf("head tail comma is not allowed")
	}

	// replace back the tuple-formed type str
	for index, replaceIndex := range emptyStrIndex {
		segments[replaceIndex] = str[parenSegmentRecord[index].left : parenSegmentRecord[index].right+1]
	}

	return segments, nil
}

// MakeUintType makes `Uint` ABI type by taking a type size argument.
// The range of type size is [8, 512] and type size % 8 == 0.
func MakeUintType(typeSize uint16) (Type, error) {
	if typeSize%8 != 0 || typeSize < 8 || typeSize > 512 {
		return Type{}, fmt.Errorf("type uint size mod 8 = 0, range [8, 512], error typesize: %d", typeSize)
	}
	return Type{
		typeFromEnum: Uint,
		typeSize:     typeSize,
	}, nil
}

// MakeByteType makes `Byte` ABI type.
func MakeByteType() Type {
	return Type{
		typeFromEnum: Byte,
	}
}

// MakeUFixedType makes `UFixed` ABI type by taking type size and type precision as arguments.
// The range of type size is [8, 512] and type size % 8 == 0.
// The range of type precision is [1, 160].
func MakeUFixedType(typeSize uint16, typePrecision uint16) (Type, error) {
	if typeSize%8 != 0 || typeSize < 8 || typeSize > 512 {
		return Type{}, fmt.Errorf("type uint size mod 8 = 0, range [8, 512], error typesize: %d", typeSize)
	}
	if typePrecision > 160 || typePrecision < 1 {
		return Type{}, fmt.Errorf("type uint precision range [1, 160]")
	}
	return Type{
		typeFromEnum:  Ufixed,
		typeSize:      typeSize,
		typePrecision: typePrecision,
	}, nil
}

// MakeBoolType makes `Bool` ABI type.
func MakeBoolType() Type {
	return Type{
		typeFromEnum: Bool,
	}
}

// MakeStaticArrayType makes static length array ABI type by taking
// array element type and array length as arguments.
func MakeStaticArrayType(argumentType Type, arrayLength uint16) Type {
	return Type{
		typeFromEnum: ArrayStatic,
		childTypes:   []Type{argumentType},
		staticLength: arrayLength,
	}
}

// MakeAddressType makes `Address` ABI type.
func MakeAddressType() Type {
	return Type{
		typeFromEnum: Address,
	}
}

// MakeDynamicArrayType makes dynamic length array by taking array element type as argument.
func MakeDynamicArrayType(argumentType Type) Type {
	return Type{
		typeFromEnum: ArrayDynamic,
		childTypes:   []Type{argumentType},
	}
}

// MakeStringType makes `String` ABI type.
func MakeStringType() Type {
	return Type{
		typeFromEnum: String,
	}
}

// MakeTupleType makes tuple ABI type by taking an array of tuple element types as argument.
func MakeTupleType(argumentTypes []Type) Type {
	return Type{
		typeFromEnum: Tuple,
		childTypes:   argumentTypes,
		staticLength: uint16(len(argumentTypes)),
	}
}

// Equal method decides the equality of two types: t == t0.
func (t Type) Equal(t0 Type) bool {
	// assume t and t0 are well-formed
	switch t.typeFromEnum {
	case Uint:
		return t.typeFromEnum == t0.typeFromEnum && t.typeSize == t0.typeSize
	case Ufixed:
		if t0.typeFromEnum != Ufixed {
			return false
		} else if t0.typePrecision != t.typePrecision || t0.typeSize != t.typeSize {
			return false
		} else {
			return true
		}
	case ArrayStatic:
		if t0.typeFromEnum != ArrayStatic {
			return false
		} else if len(t.childTypes) != len(t0.childTypes) || len(t0.childTypes) != 1 {
			return false
		} else if t.staticLength != t0.staticLength {
			return false
		} else {
			return t.childTypes[0].Equal(t0.childTypes[0])
		}
	case ArrayDynamic:
		if t0.typeFromEnum != ArrayDynamic {
			return false
		} else if len(t.childTypes) != len(t0.childTypes) || len(t0.childTypes) != 1 {
			return false
		} else {
			return t.childTypes[0].Equal(t0.childTypes[0])
		}
	case Tuple:
		if t0.typeFromEnum != Tuple {
			return false
		} else if t.staticLength != t0.staticLength || int(t.staticLength) != len(t0.childTypes) {
			return false
		} else {
			for i := 0; i < int(t.staticLength); i++ {
				compRes := t.childTypes[i].Equal(t0.childTypes[i])
				if !compRes {
					return false
				}
			}
			return true
		}
	default:
		return t.typeFromEnum == t0.typeFromEnum
	}
}

// IsDynamic method decides if an ABI type is dynamic or static.
func (t Type) IsDynamic() bool {
	switch t.typeFromEnum {
	case ArrayStatic:
		return t.childTypes[0].IsDynamic()
	case ArrayDynamic, String:
		return true
	case Tuple:
		for _, childT := range t.childTypes {
			if childT.IsDynamic() {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// ByteLen method calculates the byte length of a static ABI type.
func (t Type) ByteLen() (int, error) {
	if t.IsDynamic() {
		return -1, fmt.Errorf("dynamic type")
	}

	switch t.typeFromEnum {
	case Address:
		return 32, nil
	case Byte:
		return 1, nil
	case Uint, Ufixed:
		return int(t.typeSize / 8), nil
	case Bool:
		return 1, nil
	case ArrayStatic:
		elemByteLen, err := t.childTypes[0].ByteLen()
		if err != nil {
			return -1, err
		}
		return int(t.staticLength) * elemByteLen, nil
	case Tuple:
		size := 0
		for _, childT := range t.childTypes {
			childByteSize, err := childT.ByteLen()
			if err != nil {
				return -1, err
			}
			size += childByteSize
		}
		return size, nil
	default:
		return -1, fmt.Errorf("bruh you should not be here")
	}
}

// Value struct is the ABI Value, holding ABI Type information and the ABI value representation.
type Value struct {
	valueType Type
	value     interface{}
}

// arrayToTuple casts an array-like ABI Value into an ABI Value of Tuple type.
// This is used in both ABI Encoding and Decoding.
func (v Value) arrayToTuple() (Value, error) {
	var childT []Type
	var valueArr []Value

	switch v.valueType.typeFromEnum {
	case String:
		strValue, err := GetString(v)
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
		addr, err := GetAddress(v)
		if err != nil {
			return Value{}, err
		}
		childT, valueArr = make([]Type, 32), make([]Value, 32)
		for i := 0; i < 32; i++ {
			childT[i] = MakeByteType()
			valueArr[i] = MakeByte(addr[i])
		}
	case ArrayStatic:
		childT = make([]Type, v.valueType.staticLength)
		for i := 0; i < int(v.valueType.staticLength); i++ {
			childT[i] = v.valueType.childTypes[0]
		}
		valueArr = v.value.([]Value)
	case ArrayDynamic:
		arrayElems := v.value.([]Value)
		childT = make([]Type, len(arrayElems))
		for i := 0; i < len(arrayElems); i++ {
			childT[i] = v.valueType.childTypes[0]
		}
		valueArr = arrayElems
	default:
		return Value{}, fmt.Errorf("value type not supported to conversion to tuple")
	}

	return Value{
		valueType: MakeTupleType(childT),
		value:     valueArr,
	}, nil
}

// Encode method serialize the ABI value into a byte string of ABI encoding rule.
func (v Value) Encode() ([]byte, error) {
	switch v.valueType.typeFromEnum {
	case Uint:
		bigIntValue, err := GetUint(v)
		if err != nil {
			return []byte{}, err
		}
		bigIntBytes := bigIntValue.Bytes()
		buffer := make([]byte, v.valueType.typeSize/8-uint16(len(bigIntBytes)))
		buffer = append(buffer, bigIntBytes...)
		return buffer, nil
	case Ufixed:
		ufixedValue, err := GetUfixed(v)
		if err != nil {
			return []byte{}, err
		}
		denomSize := big.NewInt(1).Exp(big.NewInt(10), big.NewInt(int64(v.valueType.typePrecision)), nil)
		denomRat := big.NewRat(1, 1).SetFrac(denomSize, big.NewInt(1))
		numRat := denomRat.Mul(denomRat, ufixedValue)
		encodeVal := numRat.Num()
		encodeBuffer := encodeVal.Bytes()
		buffer := make([]byte, v.valueType.typeSize/8-uint16(len(encodeBuffer)))
		buffer = append(buffer, encodeBuffer...)
		return buffer, nil
	case Bool:
		boolValue, err := GetBool(v)
		if err != nil {
			return []byte{}, err
		}
		if boolValue {
			return []byte{0x80}, nil
		}
		return []byte{0x00}, nil
	case Byte:
		bytesValue, err := GetByte(v)
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
		length := len(convertedTuple.valueType.childTypes)
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
	for true {
		curr := index + delta*until
		if typeList[curr].typeFromEnum == Bool {
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
		if valueList[i].valueType.typeFromEnum != Bool {
			return 0, fmt.Errorf("bool type not matching in compressMultipleBool")
		}
		boolVal, err := GetBool(valueList[i])
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
	if v.valueType.typeFromEnum != Tuple {
		return []byte{}, fmt.Errorf("tupe not supported in tupleEncoding")
	}
	heads, tails := make([][]byte, len(v.valueType.childTypes)), make([][]byte, len(v.valueType.childTypes))
	isDynamicIndex := make(map[int]bool)
	tupleElems := v.value.([]Value)
	for i := 0; i < len(v.valueType.childTypes); i++ {
		switch tupleElems[i].valueType.IsDynamic() {
		case true:
			headsPlaceholder := []byte{0x00, 0x00}
			heads[i] = headsPlaceholder
			isDynamicIndex[i] = true
			tailEncoding, err := tupleElems[i].Encode()
			if err != nil {
				return []byte{}, err
			}
			tails[i] = tailEncoding
		case false:
			if tupleElems[i].valueType.typeFromEnum == Bool {
				// search previous bool
				before := findBoolLR(v.valueType.childTypes, i, -1)
				// search after bool
				after := findBoolLR(v.valueType.childTypes, i, 1)
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
				tails[i] = nil
			} else {
				encodeTi, err := tupleElems[i].Encode()
				if err != nil {
					return []byte{}, err
				}
				heads[i] = encodeTi
				tails[i] = nil
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
			binary.BigEndian.PutUint16(heads[i], uint16(headValue))
		}
		tailCurrLength += len(tails[i])
	}

	head, tail := make([]byte, 0), make([]byte, 0)
	for i := 0; i < len(v.valueType.childTypes); i++ {
		head = append(head, heads[i]...)
		tail = append(tail, tails[i]...)
	}
	return append(head, tail...), nil
}

// Decode takes an ABI encoded byte string and a target ABI type,
// and decodes the bytes into an ABI Value.
func Decode(valueByte []byte, valueType Type) (Value, error) {
	switch valueType.typeFromEnum {
	case Uint:
		if len(valueByte) != int(valueType.typeSize)/8 {
			return Value{},
				fmt.Errorf("uint size %d byte, given byte size unmatch", int(valueType.typeSize)/8)
		}
		uintValue := big.NewInt(0).SetBytes(valueByte)
		return MakeUint(uintValue, valueType.typeSize)
	case Ufixed:
		if len(valueByte) != int(valueType.typeSize)/8 {
			return Value{},
				fmt.Errorf("ufixed size %d byte, given byte size unmatch", int(valueType.typeSize)/8)
		}
		ufixedNumerator := big.NewInt(0).SetBytes(valueByte)
		ufixedDenominator := big.NewInt(0).Exp(
			big.NewInt(10), big.NewInt(int64(valueType.typePrecision)),
			nil,
		)
		ufixedValue := big.NewRat(1, 1).SetFrac(ufixedNumerator, ufixedDenominator)
		return MakeUfixed(ufixedValue, valueType.typeSize, valueType.typePrecision)
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
		converted := MakeTupleType(childT)
		tupleDecoded, err := tupleDecoding(valueByte, converted)
		if err != nil {
			return Value{}, err
		}
		tupleDecoded.valueType = valueType
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
		converted := MakeTupleType(childT)
		tupleDecoded, err := tupleDecoding(valueByte[2:], converted)
		if err != nil {
			return Value{}, err
		}
		tupleDecoded.valueType = valueType
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
		return Value{}, fmt.Errorf("bruh you should not be here in decoding: unknown type error")
	}
}

// tupleDecoding takes a byte string and an ABI tuple type,
// and decodes the bytes into an ABI tuple value.
func tupleDecoding(valueBytes []byte, valueType Type) (Value, error) {
	dynamicSegments, valuePartition := make([]segmentIndex, 0), make([][]byte, 0)
	iterIndex := 0
	for i := 0; i < len(valueType.childTypes); i++ {
		if valueType.childTypes[i].IsDynamic() {
			if len(valueBytes[iterIndex:]) < 2 {
				return Value{}, fmt.Errorf("ill formed tuple encoding")
			}
			dynamicIndex := binary.BigEndian.Uint16(valueBytes[iterIndex : iterIndex+2])
			if len(dynamicSegments) > 0 {
				dynamicSegments[len(dynamicSegments)-1].right = int(dynamicIndex) - 1
			}
			dynamicSegments = append(dynamicSegments, segmentIndex{
				left:  int(dynamicIndex),
				right: -1,
			})
			valuePartition = append(valuePartition, nil)
			iterIndex += 2
		} else {
			// if bool ...
			if valueType.childTypes[i].typeFromEnum == Bool {
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
						// each time check the significant bit, from left to right
						boolValue := valueBytes[iterIndex] << boolIndex
						if boolValue >= 0x80 {
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
		dynamicSegments[len(dynamicSegments)-1].right = len(valueBytes) - 1
		iterIndex = len(valueBytes)
	}
	if iterIndex < len(valueBytes) {
		return Value{}, fmt.Errorf("input byte not fully consumed")
	}

	// check segment indices are valid
	segIndexArr := make([]int, len(dynamicSegments)*2)
	for index, segment := range dynamicSegments {
		segIndexArr[index*2] = segment.left
		segIndexArr[index*2+1] = segment.right
	}
	for i := 0; i < len(segIndexArr); i++ {
		if i%2 == 1 {
			if i != len(segIndexArr)-1 && segIndexArr[i]+1 != segIndexArr[i+1] {
				return Value{}, fmt.Errorf("dynamic segment should sit next to each other")
			}
		} else {
			if segIndexArr[i] >= segIndexArr[i+1] {
				return Value{}, fmt.Errorf("dynamic segment should display a [l, r] space")
			}
		}
	}

	segIndex := 0
	for i := 0; i < len(valueType.childTypes); i++ {
		if valuePartition[i] == nil {
			valuePartition[i] = valueBytes[dynamicSegments[segIndex].left : dynamicSegments[segIndex].right+1]
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
		valueType: valueType,
		value:     values,
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
		valueType: typeUint,
		value:     value,
	}, nil
}

// MakeUfixed takes a big rational number representation, a type size, and a type precision,
// and returns an ABI Value of ABI UFixed<size>x<precision>
func MakeUfixed(value *big.Rat, size uint16, precision uint16) (Value, error) {
	ufixedValueType, err := MakeUFixedType(size, precision)
	if err != nil {
		return Value{}, nil
	}
	denomSize := big.NewInt(0).Exp(
		big.NewInt(10), big.NewInt(int64(precision)),
		nil,
	)
	numUpperLimit := big.NewInt(0).Lsh(big.NewInt(1), uint(size))
	ufixedLimit := big.NewRat(1, 1).SetFrac(numUpperLimit, denomSize)
	if value.Denom().Cmp(denomSize) > 0 {
		return Value{}, fmt.Errorf("value precision overflow")
	}
	if value.Cmp(big.NewRat(0, 1)) < 0 || value.Cmp(ufixedLimit) >= 0 {
		return Value{}, fmt.Errorf("ufixed value out of scope")
	}
	return Value{
		valueType: ufixedValueType,
		value:     value,
	}, nil
}

// MakeString takes a string and returns an ABI String type Value.
func MakeString(value string) Value {
	return Value{
		valueType: MakeStringType(),
		value:     value,
	}
}

// MakeByte takes a byte and returns an ABI Byte type value.
func MakeByte(value byte) Value {
	return Value{
		valueType: MakeByteType(),
		value:     value,
	}
}

// MakeAddress takes an [32]byte array and returns an ABI Address type value.
func MakeAddress(value [32]byte) Value {
	return Value{
		valueType: MakeAddressType(),
		value:     value,
	}
}

// MakeDynamicArray takes an array of ABI value of elemType,
// and returns an ABI dynamic length array value.
func MakeDynamicArray(values []Value, elemType Type) (Value, error) {
	for i := 0; i < len(values); i++ {
		if !values[i].valueType.Equal(elemType) {
			return Value{}, fmt.Errorf("type mismatch: %s and %s",
				values[i].valueType.String(), elemType.String())
		}
	}
	return Value{
		valueType: MakeDynamicArrayType(elemType),
		value:     values,
	}, nil
}

// MakeStaticArray takes an array of ABI value of elemType,
// and returns an ABI static length array value.
func MakeStaticArray(values []Value, elemType Type) (Value, error) {
	for i := 0; i < len(values); i++ {
		if !values[i].valueType.Equal(elemType) {
			return Value{}, fmt.Errorf("type mismatch: %s and %s",
				values[i].valueType.String(), elemType.String())
		}
	}
	return Value{
		valueType: MakeStaticArrayType(elemType, uint16(len(values))),
		value:     values,
	}, nil
}

// MakeTuple takes an array of ABI values and an array of ABI types,
// and returns an ABI tuple value.
func MakeTuple(values []Value, tupleType []Type) (Value, error) {
	if len(values) != len(tupleType) {
		return Value{}, fmt.Errorf("tuple make: tuple element number unmatch with tuple type number")
	}
	if len(values) == 0 {
		return Value{}, fmt.Errorf("empty tuple")
	}
	for i := 0; i < len(values); i++ {
		if !values[i].valueType.Equal(tupleType[i]) {
			return Value{}, fmt.Errorf("type mismatch: %s and %s",
				values[i].valueType.String(), tupleType[i].String())
		}
	}
	return Value{
		valueType: MakeTupleType(tupleType),
		value:     values,
	}, nil
}

// MakeBool takes a boolean value and returns an ABI bool value.
func MakeBool(value bool) Value {
	return Value{
		valueType: MakeBoolType(),
		value:     value,
	}
}

// GetUint8 tries to retreve an uint8 from an ABI Value.
func GetUint8(value Value) (uint8, error) {
	if value.valueType.typeFromEnum != Uint || value.valueType.typeSize > 8 {
		return 0, fmt.Errorf("value type unmatch or size too large")
	}
	bigIntForm, err := GetUint(value)
	if err != nil {
		return 0, err
	}
	return uint8(bigIntForm.Uint64()), nil
}

// GetUint16 tries to retrieve an uint16 from an ABI Value.
func GetUint16(value Value) (uint16, error) {
	if value.valueType.typeFromEnum != Uint || value.valueType.typeSize > 16 {
		return 0, fmt.Errorf("value type unmatch or size too large")
	}
	bigIntForm, err := GetUint(value)
	if err != nil {
		return 0, err
	}
	return uint16(bigIntForm.Uint64()), nil
}

// GetUint32 tries to retrieve an uint32 from an ABI Value.
func GetUint32(value Value) (uint32, error) {
	if value.valueType.typeFromEnum != Uint || value.valueType.typeSize > 32 {
		return 0, fmt.Errorf("value type unmatch or size too large")
	}
	bigIntForm, err := GetUint(value)
	if err != nil {
		return 0, err
	}
	return uint32(bigIntForm.Uint64()), nil
}

// GetUint64 tries to retrieve an uint64 from an ABI Value.
func GetUint64(value Value) (uint64, error) {
	if value.valueType.typeFromEnum != Uint || value.valueType.typeSize > 64 {
		return 0, fmt.Errorf("value type unmatch or size too large")
	}
	bigIntForm, err := GetUint(value)
	if err != nil {
		return 0, err
	}
	return bigIntForm.Uint64(), nil
}

// GetUint tries to retrieve an big uint from an ABI Value.
func GetUint(value Value) (*big.Int, error) {
	if value.valueType.typeFromEnum != Uint {
		return nil, fmt.Errorf("value type unmatch")
	}
	bigIntForm := value.value.(*big.Int)
	sizeThreshold := big.NewInt(0).Lsh(big.NewInt(1), uint(value.valueType.typeSize))
	if sizeThreshold.Cmp(bigIntForm) <= 0 {
		return nil, fmt.Errorf("value is larger than uint size")
	}
	return bigIntForm, nil
}

// GetUfixed tries to retrieve an big rational number from an ABI Value.
func GetUfixed(value Value) (*big.Rat, error) {
	if value.valueType.typeFromEnum != Ufixed {
		return nil, fmt.Errorf("value type unmatch, should be ufixed")
	}
	ufixedForm := value.value.(*big.Rat)
	numinatorSize := big.NewInt(0).Lsh(big.NewInt(1), uint(value.valueType.typeSize))
	denomSize := big.NewInt(0).Exp(
		big.NewInt(10), big.NewInt(int64(value.valueType.typePrecision)),
		nil,
	)
	ufixedLimit := big.NewRat(1, 1).SetFrac(numinatorSize, denomSize)
	if ufixedForm.Denom().Cmp(denomSize) > 0 {
		return nil, fmt.Errorf("denominator size overflow")
	}
	if ufixedForm.Cmp(big.NewRat(0, 1)) < 0 || ufixedForm.Cmp(ufixedLimit) >= 0 {
		return nil, fmt.Errorf("ufixed < 0 or ufixed larger than limit")
	}
	return ufixedForm, nil
}

// GetString tries to retrieve a string from ABI Value.
func GetString(value Value) (string, error) {
	if value.valueType.typeFromEnum != String {
		return "", fmt.Errorf("value type unmatch, should be ufixed")
	}
	stringForm := value.value.(string)
	return stringForm, nil
}

// GetByte tries to retrieve a byte from ABI Value.
func GetByte(value Value) (byte, error) {
	if value.valueType.typeFromEnum != Byte {
		return byte(0), fmt.Errorf("value type unmatch, should be bytes")
	}
	bytesForm := value.value.(byte)
	return bytesForm, nil
}

// GetAddress tries to retrieve a [32]byte array from ABI Value.
func GetAddress(value Value) ([32]byte, error) {
	if value.valueType.typeFromEnum != Address {
		return [32]byte{}, fmt.Errorf("value type unmatch, should be address")
	}
	addressForm := value.value.([32]byte)
	return addressForm, nil
}

// GetDynamicArrayByIndex takes an index and tries to retrieve the element ABI Value.
func GetDynamicArrayByIndex(value Value, index uint16) (Value, error) {
	if value.valueType.typeFromEnum != ArrayDynamic {
		return Value{}, fmt.Errorf("value type unmatch, should be dynamic array")
	}
	elements := value.value.([]Value)
	if int(index) >= len(elements) {
		return Value{}, fmt.Errorf("dynamic array cannot get element: index out of scope")
	}
	return elements[index], nil
}

// GetStaticArrayByIndex takes an index and tries to retrieve the element ABI Value.
func GetStaticArrayByIndex(value Value, index uint16) (Value, error) {
	if value.valueType.typeFromEnum != ArrayStatic {
		return Value{}, fmt.Errorf("value type unmatch, should be static array")
	}
	if index >= value.valueType.staticLength {
		return Value{}, fmt.Errorf("static array cannot get element: index out of scope")
	}
	elements := value.value.([]Value)
	return elements[index], nil
}

// GetTupleByIndex takes an index and tries to retrieve the eleemnt ABI Value.
func GetTupleByIndex(value Value, index uint16) (Value, error) {
	if value.valueType.typeFromEnum != Tuple {
		return Value{}, fmt.Errorf("value type unmatch, should be tuple")
	}
	elements := value.value.([]Value)
	if int(index) >= len(elements) {
		return Value{}, fmt.Errorf("tuple cannot get element: index out of scope")
	}
	return elements[index], nil
}

// GetBool tries to retrieve a boolean value from the ABI Value.
func GetBool(value Value) (bool, error) {
	if value.valueType.typeFromEnum != Bool {
		return false, fmt.Errorf("value type unmatch, should be bool")
	}
	boolForm := value.value.(bool)
	return boolForm, nil
}
