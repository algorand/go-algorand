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
	"math"
	"math/big"
)

// Value struct is the ABI Value, holding ABI Type information and the ABI value representation.
type Value struct {
	ABIType Type
	value   interface{}
}

// MakeUint8 takes a go `uint8` and gives an ABI Value of ABI type `uint8`.
func MakeUint8(value uint8) Value {
	bigInt := big.NewInt(int64(value))
	res, _ := MakeUint(bigInt, 8)
	return res
}

// MakeUint16 takes a go `uint16` and gives an ABI Value of ABI type `uint16`.
func MakeUint16(value uint16) Value {
	bigInt := big.NewInt(int64(value))
	res, _ := MakeUint(bigInt, 16)
	return res
}

// MakeUint32 takes a go `uint32` and gives an ABI Value of ABI type `uint32`.
func MakeUint32(value uint32) Value {
	bigInt := big.NewInt(int64(value))
	res, _ := MakeUint(bigInt, 32)
	return res
}

// MakeUint64 takes a go `uint64` and gives an ABI Value of ABI type `uint64`.
func MakeUint64(value uint64) Value {
	bigInt := new(big.Int).SetUint64(value)
	res, _ := MakeUint(bigInt, 64)
	return res
}

// MakeUint takes a big integer representation and a type bitSize,
// and returns an ABI Value of ABI Uint<bitSize> type.
func MakeUint(value *big.Int, size uint16) (Value, error) {
	typeUint, err := MakeUintType(size)
	if err != nil {
		return Value{}, err
	}
	upperLimit := new(big.Int).Lsh(big.NewInt(1), uint(size))
	if value.Cmp(upperLimit) >= 0 {
		return Value{}, fmt.Errorf("passed value larger than uint bitSize %d", size)
	}
	return Value{
		ABIType: typeUint,
		value:   value,
	}, nil
}

// MakeUfixed takes a big integer representation, a type bitSize, and a type precision,
// and returns an ABI Value of ABI UFixed<bitSize>x<precision>
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
	if len(values) >= math.MaxUint16 {
		return Value{}, fmt.Errorf("dynamic array make error: pass in array length larger than maximum of uint16")
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
	if len(values) >= math.MaxUint16 {
		return Value{}, fmt.Errorf("static array make error: pass in array length larger than maximum of uint16")
	} else if len(values) == 0 {
		return Value{}, fmt.Errorf("static array make error: 0 array element passed in")
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
	if len(values) >= math.MaxUint16 {
		return Value{}, fmt.Errorf("tuple make error: pass in tuple length larger than maximum of uint16")
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

func checkUintValid(t Type, bitSize uint16) bool {
	return t.abiTypeID == Uint && t.bitSize <= bitSize
}

// GetUint8 tries to retreve an uint8 from an ABI Value.
func (v Value) GetUint8() (uint8, error) {
	if !checkUintValid(v.ABIType, 8) {
		return 0, fmt.Errorf("value type mismatch or bitSize too large")
	}
	bigIntForm, err := v.GetUint()
	if err != nil {
		return 0, err
	}
	return uint8(bigIntForm.Uint64()), nil
}

// GetUint16 tries to retrieve an uint16 from an ABI Value.
func (v Value) GetUint16() (uint16, error) {
	if !checkUintValid(v.ABIType, 16) {
		return 0, fmt.Errorf("value type mismatch or bitSize too large")
	}
	bigIntForm, err := v.GetUint()
	if err != nil {
		return 0, err
	}
	return uint16(bigIntForm.Uint64()), nil
}

// GetUint32 tries to retrieve an uint32 from an ABI Value.
func (v Value) GetUint32() (uint32, error) {
	if !checkUintValid(v.ABIType, 32) {
		return 0, fmt.Errorf("value type mismatch or bitSize too large")
	}
	bigIntForm, err := v.GetUint()
	if err != nil {
		return 0, err
	}
	return uint32(bigIntForm.Uint64()), nil
}

// GetUint64 tries to retrieve an uint64 from an ABI Value.
func (v Value) GetUint64() (uint64, error) {
	if !checkUintValid(v.ABIType, 64) {
		return 0, fmt.Errorf("value type mismatch or bitSize too large")
	}
	bigIntForm, err := v.GetUint()
	if err != nil {
		return 0, err
	}
	return bigIntForm.Uint64(), nil
}

// GetUint tries to retrieve an big uint from an ABI Value.
func (v Value) GetUint() (*big.Int, error) {
	if v.ABIType.abiTypeID != Uint {
		return nil, fmt.Errorf("value type mismatch")
	}
	bigIntForm := v.value.(*big.Int)
	sizeThreshold := new(big.Int).Lsh(big.NewInt(1), uint(v.ABIType.bitSize))
	if sizeThreshold.Cmp(bigIntForm) <= 0 {
		return nil, fmt.Errorf("value exceeds uint bitSize scope")
	}
	return bigIntForm, nil
}

// GetUfixed tries to retrieve an big integer number from an ABI Value.
func (v Value) GetUfixed() (*big.Int, error) {
	if v.ABIType.abiTypeID != Ufixed {
		return nil, fmt.Errorf("value type mismatch, should be ufixed")
	}
	bigIntForm := v.value.(*big.Int)
	sizeThreshold := new(big.Int).Lsh(big.NewInt(1), uint(v.ABIType.bitSize))
	if sizeThreshold.Cmp(bigIntForm) <= 0 {
		return nil, fmt.Errorf("value exceeds ufixed bitSize scope")
	}
	return bigIntForm, nil
}

// GetString tries to retrieve a string from ABI Value.
func (v Value) GetString() (string, error) {
	if v.ABIType.abiTypeID != String {
		return "", fmt.Errorf("value type mismatch, should be ufixed")
	}
	stringForm := v.value.(string)
	return stringForm, nil
}

// GetByte tries to retrieve a byte from ABI Value.
func (v Value) GetByte() (byte, error) {
	if v.ABIType.abiTypeID != Byte {
		return byte(0), fmt.Errorf("value type mismatch, should be bytes")
	}
	bytesForm := v.value.(byte)
	return bytesForm, nil
}

// GetAddress tries to retrieve a [32]byte array from ABI Value.
func (v Value) GetAddress() ([32]byte, error) {
	if v.ABIType.abiTypeID != Address {
		return [32]byte{}, fmt.Errorf("value type mismatch, should be address")
	}
	addressForm := v.value.([32]byte)
	return addressForm, nil
}

// GetValueByIndex retrieve value element by the index passed in
func (v Value) GetValueByIndex(index uint16) (Value, error) {
	switch v.ABIType.abiTypeID {
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
	if v.ABIType.abiTypeID != Bool {
		return false, fmt.Errorf("value type mismatch, should be bool")
	}
	boolForm := v.value.(bool)
	return boolForm, nil
}
