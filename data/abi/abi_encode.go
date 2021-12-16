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
	"reflect"
	"strings"
)

// typeCastToTuple cast an array-like ABI type into an ABI tuple type.
func (t Type) typeCastToTuple(tupLen ...int) (Type, error) {
	var childT []Type

	switch t.abiTypeID {
	case String:
		if len(tupLen) != 1 {
			return Type{}, fmt.Errorf("string type conversion to tuple need 1 length argument")
		}
		childT = make([]Type, tupLen[0])
		for i := 0; i < tupLen[0]; i++ {
			childT[i] = byteType
		}
	case Address:
		childT = make([]Type, addressByteSize)
		for i := 0; i < addressByteSize; i++ {
			childT[i] = byteType
		}
	case ArrayStatic:
		childT = make([]Type, t.staticLength)
		for i := 0; i < int(t.staticLength); i++ {
			childT[i] = t.childTypes[0]
		}
	case ArrayDynamic:
		if len(tupLen) != 1 {
			return Type{}, fmt.Errorf("dynamic array type conversion to tuple need 1 length argument")
		}
		childT = make([]Type, tupLen[0])
		for i := 0; i < tupLen[0]; i++ {
			childT[i] = t.childTypes[0]
		}
	default:
		return Type{}, fmt.Errorf("type cannot support conversion to tuple")
	}

	tuple, err := MakeTupleType(childT)
	if err != nil {
		return Type{}, err
	}
	return tuple, nil
}

// Encode is an ABI type method to encode go values into bytes following ABI encoding rules
func (t Type) Encode(value interface{}) ([]byte, error) {
	switch t.abiTypeID {
	case Uint, Ufixed:
		return encodeInt(value, t.bitSize)
	case Bool:
		boolValue, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("cannot cast value to bool in bool encoding")
		}
		if boolValue {
			return []byte{0x80}, nil
		}
		return []byte{0x00}, nil
	case Byte:
		byteValue, ok := value.(byte)
		if !ok {
			return nil, fmt.Errorf("cannot cast value to byte in byte encoding")
		}
		return []byte{byteValue}, nil
	case ArrayStatic, Address:
		castedType, err := t.typeCastToTuple()
		if err != nil {
			return nil, err
		}
		return castedType.Encode(value)
	case ArrayDynamic:
		dynamicArray, err := inferToSlice(value)
		if err != nil {
			return nil, err
		}
		castedType, err := t.typeCastToTuple(len(dynamicArray))
		if err != nil {
			return nil, err
		}
		lengthEncode := make([]byte, lengthEncodeByteSize)
		binary.BigEndian.PutUint16(lengthEncode, uint16(len(dynamicArray)))
		encoded, err := castedType.Encode(value)
		if err != nil {
			return nil, err
		}
		encoded = append(lengthEncode, encoded...)
		return encoded, nil
	case String:
		stringValue, okString := value.(string)
		if !okString {
			return nil, fmt.Errorf("cannot cast value to string or array dynamic in encoding")
		}
		byteValue := []byte(stringValue)
		castedType, err := t.typeCastToTuple(len(byteValue))
		if err != nil {
			return nil, err
		}
		lengthEncode := make([]byte, lengthEncodeByteSize)
		binary.BigEndian.PutUint16(lengthEncode, uint16(len(byteValue)))
		encoded, err := castedType.Encode(byteValue)
		if err != nil {
			return nil, err
		}
		encoded = append(lengthEncode, encoded...)
		return encoded, nil
	case Tuple:
		return encodeTuple(value, t.childTypes)
	default:
		return nil, fmt.Errorf("cannot infer type for encoding")
	}
}

// encodeInt encodes int-alike golang values to bytes, following ABI encoding rules
func encodeInt(intValue interface{}, bitSize uint16) ([]byte, error) {
	var bigInt *big.Int

	switch intValue := intValue.(type) {
	case int8:
		bigInt = big.NewInt(int64(intValue))
	case uint8:
		bigInt = new(big.Int).SetUint64(uint64(intValue))
	case int16:
		bigInt = big.NewInt(int64(intValue))
	case uint16:
		bigInt = new(big.Int).SetUint64(uint64(intValue))
	case int32:
		bigInt = big.NewInt(int64(intValue))
	case uint32:
		bigInt = new(big.Int).SetUint64(uint64(intValue))
	case int64:
		bigInt = big.NewInt(intValue)
	case uint64:
		bigInt = new(big.Int).SetUint64(intValue)
	case uint:
		bigInt = new(big.Int).SetUint64(uint64(intValue))
	case int:
		bigInt = big.NewInt(int64(intValue))
	case *big.Int:
		bigInt = intValue
	default:
		return nil, fmt.Errorf("cannot infer go type for uint encode")
	}

	if bigInt.Sign() < 0 {
		return nil, fmt.Errorf("passed in numeric value should be non negative")
	}

	bytes := bigInt.Bytes()
	if len(bytes) > int(bitSize/8) {
		return nil, fmt.Errorf("input value bit size %d > abi type bit size %d", len(bytes)*8, bitSize)
	}

	zeroPadding := make([]byte, bitSize/8-uint16(len(bytes)))
	buffer := append(zeroPadding, bytes...)
	return buffer, nil
}

// inferToSlice infers an interface element to a slice of interface{}, returns error if it cannot infer successfully
func inferToSlice(value interface{}) ([]interface{}, error) {
	reflectVal := reflect.ValueOf(value)
	if reflectVal.Kind() != reflect.Slice && reflectVal.Kind() != reflect.Array {
		return nil, fmt.Errorf("cannot infer an interface value as a slice of interface element")
	}
	if reflectVal.IsNil() {
		if reflectVal.Kind() == reflect.Slice {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot infer nil value for array kind interface")
	}
	values := make([]interface{}, reflectVal.Len())
	for i := 0; i < reflectVal.Len(); i++ {
		values[i] = reflectVal.Index(i).Interface()
	}
	return values, nil
}

// encodeTuple encodes slice-of-interface of golang values to bytes, following ABI encoding rules
func encodeTuple(value interface{}, childT []Type) ([]byte, error) {
	if len(childT) >= (1 << 16) {
		return nil, fmt.Errorf("abi child type number exceeds uint16 maximum")
	}
	values, err := inferToSlice(value)
	if err != nil {
		return nil, err
	}
	if len(values) != len(childT) {
		return nil, fmt.Errorf("cannot encode abi tuple: value slice length != child type number")
	}

	// for each tuple element value, it has a head/tail component
	// we create slots for head/tail bytes now, store them and concat them later
	heads := make([][]byte, len(childT))
	tails := make([][]byte, len(childT))
	isDynamicIndex := make(map[int]bool)

	for i := 0; i < len(childT); i++ {
		if childT[i].IsDynamic() {
			// if it is a dynamic value, the head component is not pre-determined
			// we store an empty placeholder first, since we will need it in byte length calculation
			headsPlaceholder := []byte{0x00, 0x00}
			heads[i] = headsPlaceholder
			// we keep track that the index points to a dynamic value
			isDynamicIndex[i] = true
			tailEncoding, err := childT[i].Encode(values[i])
			if err != nil {
				return nil, err
			}
			tails[i] = tailEncoding
			isDynamicIndex[i] = true
		} else if childT[i].abiTypeID == Bool {
			// search previous bool
			before := findBoolLR(childT, i, -1)
			// search after bool
			after := findBoolLR(childT, i, 1)
			// append to heads and tails
			if before%8 != 0 {
				return nil, fmt.Errorf("cannot encode abi tuple: expected before has number of bool mod 8 == 0")
			}
			if after > 7 {
				after = 7
			}
			compressed, err := compressBools(values[i : i+after+1])
			if err != nil {
				return nil, err
			}
			heads[i] = []byte{compressed}
			i += after
			isDynamicIndex[i] = false
		} else {
			encodeTi, err := childT[i].Encode(values[i])
			if err != nil {
				return nil, err
			}
			heads[i] = encodeTi
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
				return nil, fmt.Errorf("cannot encode abi tuple: encode length exceeds uint16 maximum")
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

// compressBools takes a slice of interface{} (which can be casted to bools) length <= 8
// and compress the bool values into a uint8 integer
func compressBools(boolSlice []interface{}) (uint8, error) {
	var res uint8 = 0
	if len(boolSlice) > 8 {
		return 0, fmt.Errorf("compressBools: cannot have slice length > 8")
	}
	for i := 0; i < len(boolSlice); i++ {
		temp, ok := boolSlice[i].(bool)
		if !ok {
			return 0, fmt.Errorf("compressBools: cannot cast slice element to bool")
		}
		if temp {
			res |= 1 << uint(7-i)
		}
	}
	return res, nil
}

// decodeUint decodes byte slice into golang int/big.Int
func decodeUint(encoded []byte, bitSize uint16) (interface{}, error) {
	if len(encoded) != int(bitSize)/8 {
		return nil,
			fmt.Errorf("uint/ufixed decode: expected byte length %d, but got byte length %d", bitSize/8, len(encoded))
	}
	switch bitSize / 8 {
	case 1:
		return encoded[0], nil
	case 2:
		return uint16(new(big.Int).SetBytes(encoded).Uint64()), nil
	case 3, 4:
		return uint32(new(big.Int).SetBytes(encoded).Uint64()), nil
	case 5, 6, 7, 8:
		return new(big.Int).SetBytes(encoded).Uint64(), nil
	default:
		return new(big.Int).SetBytes(encoded), nil
	}
}

// Decode is an ABI type method to decode bytes to go values from ABI encoding rules
func (t Type) Decode(encoded []byte) (interface{}, error) {
	switch t.abiTypeID {
	case Uint, Ufixed:
		return decodeUint(encoded, t.bitSize)
	case Bool:
		if len(encoded) != 1 {
			return nil, fmt.Errorf("boolean byte should be length 1 byte")
		}
		if encoded[0] == 0x00 {
			return false, nil
		} else if encoded[0] == 0x80 {
			return true, nil
		}
		return nil, fmt.Errorf("single boolean encoded byte should be of form 0x80 or 0x00")
	case Byte:
		if len(encoded) != 1 {
			return nil, fmt.Errorf("byte should be length 1")
		}
		return encoded[0], nil
	case ArrayStatic:
		castedType, err := t.typeCastToTuple()
		if err != nil {
			return nil, err
		}
		return castedType.Decode(encoded)
	case Address:
		if len(encoded) != addressByteSize {
			return nil, fmt.Errorf("address should be length 32")
		}
		return encoded, nil
	case ArrayDynamic:
		if len(encoded) < lengthEncodeByteSize {
			return nil, fmt.Errorf("dynamic array format corrupted")
		}
		dynamicLen := binary.BigEndian.Uint16(encoded[:lengthEncodeByteSize])
		castedType, err := t.typeCastToTuple(int(dynamicLen))
		if err != nil {
			return nil, err
		}
		return castedType.Decode(encoded[lengthEncodeByteSize:])
	case String:
		if len(encoded) < lengthEncodeByteSize {
			return nil, fmt.Errorf("string format corrupted")
		}
		stringLenBytes := encoded[:lengthEncodeByteSize]
		byteLen := binary.BigEndian.Uint16(stringLenBytes)
		if len(encoded[lengthEncodeByteSize:]) != int(byteLen) {
			return nil, fmt.Errorf("string representation in byte: length not matching")
		}
		return string(encoded[lengthEncodeByteSize:]), nil
	case Tuple:
		return decodeTuple(encoded, t.childTypes)
	default:
		return nil, fmt.Errorf("cannot infer type for decoding")
	}
}

// decodeTuple decodes byte slice with ABI type slice, outputting a slice of golang interface values
// following ABI encoding rules
func decodeTuple(encoded []byte, childT []Type) ([]interface{}, error) {
	dynamicSegments := make([]int, 0, len(childT)+1)
	valuePartition := make([][]byte, 0, len(childT))
	iterIndex := 0

	for i := 0; i < len(childT); i++ {
		if childT[i].IsDynamic() {
			if len(encoded[iterIndex:]) < lengthEncodeByteSize {
				return nil, fmt.Errorf("ill formed tuple dynamic typed value encoding")
			}
			dynamicIndex := binary.BigEndian.Uint16(encoded[iterIndex : iterIndex+lengthEncodeByteSize])
			dynamicSegments = append(dynamicSegments, int(dynamicIndex))
			valuePartition = append(valuePartition, nil)
			iterIndex += lengthEncodeByteSize
		} else if childT[i].abiTypeID == Bool {
			// search previous bool
			before := findBoolLR(childT, i, -1)
			// search after bool
			after := findBoolLR(childT, i, 1)
			if before%8 == 0 {
				if after > 7 {
					after = 7
				}
				// parse bool in a byte to multiple byte strings
				for boolIndex := uint(0); boolIndex <= uint(after); boolIndex++ {
					boolMask := 0x80 >> boolIndex
					if encoded[iterIndex]&byte(boolMask) > 0 {
						valuePartition = append(valuePartition, []byte{0x80})
					} else {
						valuePartition = append(valuePartition, []byte{0x00})
					}
				}
				i += after
				iterIndex++
			} else {
				return nil, fmt.Errorf("expected before bool number mod 8 == 0")
			}
		} else {
			// not bool ...
			currLen, err := childT[i].ByteLen()
			if err != nil {
				return nil, err
			}
			valuePartition = append(valuePartition, encoded[iterIndex:iterIndex+currLen])
			iterIndex += currLen
		}
		if i != len(childT)-1 && iterIndex >= len(encoded) {
			return nil, fmt.Errorf("input byte not enough to decode")
		}
	}

	if len(dynamicSegments) > 0 {
		dynamicSegments = append(dynamicSegments, len(encoded))
		iterIndex = len(encoded)
	}
	if iterIndex < len(encoded) {
		return nil, fmt.Errorf("input byte not fully consumed")
	}
	for i := 0; i < len(dynamicSegments)-1; i++ {
		if dynamicSegments[i] > dynamicSegments[i+1] {
			return nil, fmt.Errorf("dynamic segment should display a [l, r] space with l <= r")
		}
	}

	segIndex := 0
	for i := 0; i < len(childT); i++ {
		if childT[i].IsDynamic() {
			valuePartition[i] = encoded[dynamicSegments[segIndex]:dynamicSegments[segIndex+1]]
			segIndex++
		}
	}

	values := make([]interface{}, len(childT))
	for i := 0; i < len(childT); i++ {
		var err error
		values[i], err = childT[i].Decode(valuePartition[i])
		if err != nil {
			return nil, err
		}
	}
	return values, nil
}

// ParseArgJSONtoByteSlice convert input method arguments to ABI encoded bytes
// it converts funcArgTypes into a tuple type and apply changes over input argument string (in JSON format)
// if there are greater or equal to 15 inputs, then we compact the tailing inputs into one tuple
func ParseArgJSONtoByteSlice(argTypes []string, jsonArgs []string, applicationArgs *[][]byte) error {
	abiTypes := make([]Type, len(argTypes))
	for i, typeString := range argTypes {
		abiType, err := TypeOf(typeString)
		if err != nil {
			return err
		}
		abiTypes[i] = abiType
	}

	if len(abiTypes) != len(jsonArgs) {
		return fmt.Errorf("input argument number %d != method argument number %d", len(jsonArgs), len(abiTypes))
	}

	// change the input args to be 1 - 14 + 15 (compacting everything together)
	if len(jsonArgs) > 14 {
		compactedType, err := MakeTupleType(abiTypes[14:])
		if err != nil {
			return err
		}
		abiTypes = append(abiTypes[:14], compactedType)

		remainingJSON := "[" + strings.Join(jsonArgs[14:], ",") + "]"
		jsonArgs = append(jsonArgs[:14], remainingJSON)
	}

	// parse JSON value to ABI encoded bytes
	for i := 0; i < len(jsonArgs); i++ {
		interfaceVal, err := abiTypes[i].UnmarshalFromJSON([]byte(jsonArgs[i]))
		if err != nil {
			return err
		}
		abiEncoded, err := abiTypes[i].Encode(interfaceVal)
		if err != nil {
			return err
		}
		*applicationArgs = append(*applicationArgs, abiEncoded)
	}
	return nil
}

// ParseMethodSignature parses a method of format `method(argType1,argType2,...)retType`
// into `method` {`argType1`,`argType2`,..} and `retType`
func ParseMethodSignature(methodSig string) (name string, argTypes []string, returnType string, err error) {
	argsStart := strings.Index(methodSig, "(")
	if argsStart == -1 {
		err = fmt.Errorf("Invalid method signature: %s", methodSig)
		return
	}

	argsEnd := -1
	depth := 0
	for index, char := range methodSig {
		if char == '(' {
			depth++
		} else if char == ')' {
			if depth == 0 {
				err = fmt.Errorf("Unpaired parenthesis in method signature: %s", methodSig)
				return
			}
			depth--
			if depth == 0 {
				argsEnd = index
				break
			}
		}
	}

	if argsEnd == -1 {
		err = fmt.Errorf("Invalid method signature: %s", methodSig)
		return
	}

	name = methodSig[:argsStart]
	argTypes, err = parseTupleContent(methodSig[argsStart+1 : argsEnd])
	returnType = methodSig[argsEnd+1:]
	return
}
