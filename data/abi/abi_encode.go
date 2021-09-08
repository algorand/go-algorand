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
)

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

		childT = make([]Type, len(strByte))
		valueArr = make([]Value, len(strByte))

		for i := 0; i < len(strByte); i++ {
			childT[i] = MakeByteType()
			valueArr[i] = MakeByte(strByte[i])
		}
	case Address:
		addr, err := v.GetAddress()
		if err != nil {
			return Value{}, err
		}

		childT = make([]Type, 32)
		valueArr = make([]Value, 32)

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

	heads := make([][]byte, len(v.ABIType.childTypes))
	tails := make([][]byte, len(v.ABIType.childTypes))
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
	dynamicSegments := make([]segment, 0)
	valuePartition := make([][]byte, 0)
	iterIndex := 0

	for i := 0; i < len(valueType.childTypes); i++ {
		if valueType.childTypes[i].IsDynamic() {
			if len(valueBytes[iterIndex:]) < 2 {
				return Value{}, fmt.Errorf("ill formed tuple dynamic typed value encoding")
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
				} else {
					return Value{}, fmt.Errorf("expected before bool number mod 8 == 0")
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
	for index, seg := range dynamicSegments {
		if seg.left > seg.right {
			return Value{}, fmt.Errorf("dynamic segment should display a [l, r] space with l <= r")
		}
		if index != len(dynamicSegments)-1 && seg.right != dynamicSegments[index+1].left {
			return Value{}, fmt.Errorf("dynamic segment should be consecutive")
		}
	}

	segIndex := 0
	for i := 0; i < len(valueType.childTypes); i++ {
		if valueType.childTypes[i].IsDynamic() {
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

// MakeDynamicArray takes an array of ABI value (can be empty) and element type,
// returns an ABI dynamic length array value.
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
