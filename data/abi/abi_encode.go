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

// arrayToTuple casts an array-like ABI Value into an ABI Value of Tuple type.
// This is used in both ABI Encoding and Decoding.
func (v Value) arrayToTuple() (Value, error) {
	var childT []Type
	var valueArr []Value

	switch v.ABIType.abiTypeID {
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

		childT = make([]Type, addressByteSize)
		valueArr = make([]Value, addressByteSize)

		for i := 0; i < addressByteSize; i++ {
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
	switch v.ABIType.abiTypeID {
	case Uint:
		bigIntValue, err := v.GetUint()
		if err != nil {
			return []byte{}, err
		}
		// NOTE: ugly work-round for golang 1.14. if upgraded to 1.15, should use `fillbytes`
		bigIntBytes := bigIntValue.Bytes()
		buffer := make([]byte, v.ABIType.bitSize/8-uint16(len(bigIntBytes)))
		buffer = append(buffer, bigIntBytes...)
		return buffer, nil
	case Ufixed:
		ufixedValue, err := v.GetUfixed()
		if err != nil {
			return []byte{}, err
		}
		// NOTE: ugly work-round for golang 1.14. if upgraded to 1.15, should use `fillbytes`
		encodeBuffer := ufixedValue.Bytes()
		buffer := make([]byte, v.ABIType.bitSize/8-uint16(len(encodeBuffer)))
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
		lengthEncode := make([]byte, lengthEncodeByteSize)
		binary.BigEndian.PutUint16(lengthEncode, uint16(length))

		encoded, err := tupleEncoding(convertedTuple)
		if err != nil {
			return []byte{}, err
		}
		return append(lengthEncode, encoded...), nil
	case Tuple:
		return tupleEncoding(v)
	default:
		return []byte{}, fmt.Errorf("Encoding: unknown type error (bruh why you are here)")
	}
}

// compressMultipleBool compress consecutive bool values into a byte in ABI tuple/array value.
func compressMultipleBool(valueList []Value) (uint8, error) {
	var res uint8 = 0
	if len(valueList) > 8 {
		return 0, fmt.Errorf("value list passed in should be no greater than length 8")
	}
	for i := 0; i < len(valueList); i++ {
		if valueList[i].ABIType.abiTypeID != Bool {
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
	if v.ABIType.abiTypeID != Tuple {
		return []byte{}, fmt.Errorf("type not supported in tupleEncoding")
	}
	if len(v.ABIType.childTypes) >= (1 << 16) {
		return []byte{}, fmt.Errorf("value abi type exceed 2^16")
	}
	tupleElems := v.value.([]Value)
	if len(tupleElems) != len(v.ABIType.childTypes) {
		return []byte{}, fmt.Errorf("tuple abi child type number unmatch with tuple argument number")
	}

	// for each tuple element value, it has a head/tail component
	// we create slots for head/tail bytes now, store them and concat them later
	heads := make([][]byte, len(v.ABIType.childTypes))
	tails := make([][]byte, len(v.ABIType.childTypes))
	isDynamicIndex := make(map[int]bool)

	for i := 0; i < len(v.ABIType.childTypes); i++ {
		if tupleElems[i].ABIType.IsDynamic() {
			// if it is a dynamic value, the head component is not pre-determined
			// we store an empty placeholder first, since we will need it in byte length calculation
			headsPlaceholder := []byte{0x00, 0x00}
			heads[i] = headsPlaceholder
			// we keep track that the index points to a dynamic value
			isDynamicIndex[i] = true
			tailEncoding, err := tupleElems[i].Encode()
			if err != nil {
				return []byte{}, err
			}
			tails[i] = tailEncoding
		} else {
			if tupleElems[i].ABIType.abiTypeID == Bool {
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
	// since head size can be pre-determined (for we are storing static value and dynamic value index in head)
	// we accumulate the head size first
	// (also note that though head size is pre-determined, head value is not necessarily pre-determined)
	headLength := 0
	for _, headTi := range heads {
		headLength += len(headTi)
	}

	// when we iterate through the heads (byte slice), we need to find heads for dynamic values
	// the head should correspond to the start index: len( head(x[1]) ... head(x[N]) tail(x[1]) ... tail(x[i-1]) ).
	tailCurrLength := 0
	for i := 0; i < len(heads); i++ {
		if isDynamicIndex[i] {
			// calculate where the index of dynamic value encoding byte start
			headValue := headLength + tailCurrLength
			if headValue >= (1 << 16) {
				return []byte{}, fmt.Errorf("encoding error: byte length exceed 2^16")
			}
			binary.BigEndian.PutUint16(heads[i], uint16(headValue))
		}
		// accumulate the current tailing dynamic encoding bytes length.
		tailCurrLength += len(tails[i])
	}

	// concat everything as the abi encoded bytes
	encoded := make([]byte, 0, headLength+tailCurrLength)
	for _, head := range heads {
		encoded = append(encoded, head...)
	}
	for _, tail := range tails {
		encoded = append(encoded, tail...)
	}
	return encoded, nil
}

// Decode takes an ABI encoded byte string and a target ABI type,
// and decodes the bytes into an ABI Value.
func Decode(valueByte []byte, valueType Type) (Value, error) {
	switch valueType.abiTypeID {
	case Uint:
		if len(valueByte) != int(valueType.bitSize)/8 {
			return Value{},
				fmt.Errorf("uint%d decode: expected byte length %d, but got byte length %d",
					valueType.bitSize, valueType.bitSize/8, len(valueByte))
		}
		uintValue := new(big.Int).SetBytes(valueByte)
		return MakeUint(uintValue, valueType.bitSize)
	case Ufixed:
		if len(valueByte) != int(valueType.bitSize)/8 {
			return Value{},
				fmt.Errorf("ufixed%dx%d decode: expected length %d, got byte length %d",
					valueType.bitSize, valueType.precision, valueType.bitSize/8, len(valueByte))
		}
		ufixedNumerator := new(big.Int).SetBytes(valueByte)
		return MakeUfixed(ufixedNumerator, valueType.bitSize, valueType.precision)
	case Bool:
		if len(valueByte) != 1 {
			return Value{}, fmt.Errorf("boolean byte should be length 1 byte")
		}
		var boolValue bool
		if valueByte[0] == 0x00 {
			boolValue = false
		} else if valueByte[0] == 0x80 {
			boolValue = true
		} else {
			return Value{}, fmt.Errorf("sinble boolean encoded byte should be of form 0x80 or 0x00")
		}
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
		if len(valueByte) != addressByteSize {
			return Value{}, fmt.Errorf("address should be length 32")
		}
		var byteAssign [addressByteSize]byte
		copy(byteAssign[:], valueByte)
		return MakeAddress(byteAssign), nil
	case ArrayDynamic:
		if len(valueByte) < lengthEncodeByteSize {
			return Value{}, fmt.Errorf("dynamic array format corrupted")
		}
		dynamicLen := binary.BigEndian.Uint16(valueByte[:lengthEncodeByteSize])
		childT := make([]Type, dynamicLen)
		for i := 0; i < int(dynamicLen); i++ {
			childT[i] = valueType.childTypes[0]
		}
		converted, err := MakeTupleType(childT)
		if err != nil {
			return Value{}, err
		}
		tupleDecoded, err := tupleDecoding(valueByte[lengthEncodeByteSize:], converted)
		if err != nil {
			return Value{}, err
		}
		tupleDecoded.ABIType = valueType
		return tupleDecoded, nil
	case String:
		if len(valueByte) < lengthEncodeByteSize {
			return Value{}, fmt.Errorf("string format corrupted")
		}
		stringLenBytes := valueByte[:lengthEncodeByteSize]
		byteLen := binary.BigEndian.Uint16(stringLenBytes)
		if len(valueByte[lengthEncodeByteSize:]) != int(byteLen) {
			return Value{}, fmt.Errorf("string representation in byte: length not matching")
		}
		return MakeString(string(valueByte[lengthEncodeByteSize:])), nil
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
			if len(valueBytes[iterIndex:]) < lengthEncodeByteSize {
				return Value{}, fmt.Errorf("ill formed tuple dynamic typed value encoding")
			}
			dynamicIndex := binary.BigEndian.Uint16(valueBytes[iterIndex : iterIndex+lengthEncodeByteSize])
			if len(dynamicSegments) > 0 {
				dynamicSegments[len(dynamicSegments)-1].right = int(dynamicIndex)
			}
			// we know where encoded bytes for dynamic value start, but we do not know where it ends
			// unless we see the start of the next encoded bytes for dynamic value
			dynamicSegments = append(dynamicSegments, segment{
				left:  int(dynamicIndex),
				right: -1,
			})
			valuePartition = append(valuePartition, nil)
			iterIndex += lengthEncodeByteSize
		} else {
			// if bool ...
			if valueType.childTypes[i].abiTypeID == Bool {
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
	// if the dynamic segment are not consecutive and well-ordered, we return error
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

	// decode each tuple element bytes
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
