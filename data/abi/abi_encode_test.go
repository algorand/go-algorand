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
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/chrismcguire/gobberish"
	"github.com/stretchr/testify/require"
)

func TestEncodeValid(t *testing.T) {
	partitiontest.PartitionTest(t)

	// encoding test for uint type, iterating through all uint sizes
	// randomly pick 1000 valid uint values and check if encoded value match with expected
	for intSize := 8; intSize <= 512; intSize += 8 {
		upperLimit := big.NewInt(0).Lsh(big.NewInt(1), uint(intSize))
		for i := 0; i < 1000; i++ {
			randomInt, err := rand.Int(rand.Reader, upperLimit)
			require.NoError(t, err, "cryptographic random int init fail")

			randomIntByte := randomInt.Bytes()
			expected := make([]byte, intSize/8-len(randomIntByte))
			expected = append(expected, randomIntByte...)

			uintValue, err := MakeUint(randomInt, uint16(intSize))
			require.NoError(t, err, "makeUint Fail")
			uintBytesActual, err := uintValue.Encode()

			require.NoError(t, err, "uint encode fail")
			require.Equal(t, expected, uintBytesActual, "encode uint not match with expected")
		}
		// 2^[bitSize] - 1 test
		// check if uint<bitSize> can contain max uint value (2^bitSize - 1)
		largest := big.NewInt(0).Add(
			upperLimit,
			big.NewInt(1).Neg(big.NewInt(1)),
		)
		valueLargest, err := MakeUint(largest, uint16(intSize))
		require.NoError(t, err, "make largest uint fail")
		encoded, err := valueLargest.Encode()
		require.NoError(t, err, "largest uint encode error")
		require.Equal(t, largest.Bytes(), encoded, "encode uint largest do not match with expected")
	}

	// encoding test for ufixed, iterating through all the valid ufixed bitSize and precision
	// randomly generate 10 big int values for ufixed numerator and check if encoded value match with expected
	// also check if ufixed can fit max numerator (2^bitSize - 1) under specific byte bitSize
	for size := 8; size <= 512; size += 8 {
		upperLimit := big.NewInt(0).Lsh(big.NewInt(1), uint(size))
		largest := big.NewInt(0).Add(
			upperLimit,
			big.NewInt(1).Neg(big.NewInt(1)),
		)
		for precision := 1; precision <= 160; precision++ {
			for i := 0; i < 10; i++ {
				randomInt, err := rand.Int(rand.Reader, upperLimit)
				require.NoError(t, err, "cryptographic random int init fail")

				valueUfixed, err := MakeUfixed(randomInt, uint16(size), uint16(precision))
				require.NoError(t, err, "makeUfixed Fail")

				encodedUfixed, err := valueUfixed.Encode()
				require.NoError(t, err, "ufixed encode fail")

				randomBytes := randomInt.Bytes()
				buffer := make([]byte, size/8-len(randomBytes))
				buffer = append(buffer, randomBytes...)
				require.Equal(t, buffer, encodedUfixed, "encode ufixed not match with expected")
			}
			// (2^[bitSize] - 1) / (10^[precision]) test
			ufixedLargestValue, err := MakeUfixed(largest, uint16(size), uint16(precision))
			require.NoError(t, err, "make largest ufixed fail")
			ufixedLargestEncode, err := ufixedLargestValue.Encode()
			require.NoError(t, err, "largest ufixed encode error")
			require.Equal(t, largest.Bytes(), ufixedLargestEncode,
				"encode ufixed largest do not match with expected")
		}
	}

	// encoding test for address, since address is 32 byte, it can be considered as 256 bit uint
	// randomly generate 1000 uint256 and make address values, check if encoded value match with expected
	upperLimit := big.NewInt(0).Lsh(big.NewInt(1), 256)
	for i := 0; i < 1000; i++ {
		randomAddrInt, err := rand.Int(rand.Reader, upperLimit)
		require.NoError(t, err, "cryptographic random int init fail")

		rand256Bytes := randomAddrInt.Bytes()
		addrBytesExpected := make([]byte, 32-len(rand256Bytes))
		addrBytesExpected = append(addrBytesExpected, rand256Bytes...)

		var addrBytes [32]byte
		copy(addrBytes[:], addrBytesExpected[:32])

		addressValue := MakeAddress(addrBytes)
		addrBytesActual, err := addressValue.Encode()
		require.NoError(t, err, "address encode fail")
		require.Equal(t, addrBytesExpected, addrBytesActual, "encode addr not match with expected")
	}

	// encoding test for bool values
	for i := 0; i < 2; i++ {
		boolValue := MakeBool(i == 1)
		boolEncode, err := boolValue.Encode()
		require.NoError(t, err, "bool encode fail")
		expected := []byte{0x00}
		if i == 1 {
			expected = []byte{0x80}
		}
		require.Equal(t, expected, boolEncode, "encode bool not match with expected")
	}

	// encoding test for byte values
	for i := 0; i < (1 << 8); i++ {
		byteValue := MakeByte(byte(i))
		byteEncode, err := byteValue.Encode()
		require.NoError(t, err, "byte encode fail")
		expected := []byte{byte(i)}
		require.Equal(t, expected, byteEncode, "encode byte not match with expected")
	}

	// encoding test for string values, since strings in ABI contain utf-8 symbols
	// we use `gobberish` to generate random utf-8 symbols
	// randomly generate utf-8 str from length 1 to 100, each length draw 10 random strs
	// check if encoded ABI str match with expected value
	for length := 1; length <= 100; length++ {
		for i := 0; i < 10; i++ {
			// generate utf8 strings from `gobberish` at some length
			utf8Str := gobberish.GenerateString(length)
			strValue := MakeString(utf8Str)
			// since string is just type alias of `byte[]`, we need to store number of bytes in encoding
			utf8ByteLen := len([]byte(utf8Str))
			lengthBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(lengthBytes, uint16(utf8ByteLen))
			expected := append(lengthBytes, []byte(utf8Str)...)

			strEncode, err := strValue.Encode()
			require.NoError(t, err, "string encode fail")
			require.Equal(t, expected, strEncode, "encode string not match with expected")
		}
	}

	// encoding test for static bool array, the expected behavior of encoding is to
	// compress multiple bool into a single byte.
	// input: {T, F, F, T, T}, encode expected: {0b10011000}
	t.Run("static bool array encoding", func(t *testing.T) {
		inputBase := []bool{true, false, false, true, true}
		arrayElems := make([]Value, len(inputBase))
		for index, bVal := range inputBase {
			arrayElems[index] = MakeBool(bVal)
		}
		expected := []byte{
			0b10011000,
		}
		boolArr, err := MakeStaticArray(arrayElems)
		require.NoError(t, err, "make static array should not return error")
		boolArrEncode, err := boolArr.Encode()
		require.NoError(t, err, "static bool array encoding should not return error")
		require.Equal(t, expected, boolArrEncode, "static bool array encode not match expected")
	})

	// encoding test for static bool array
	// input: {F, F, F, T, T, F, T, F, T, F, T}, encode expected: {0b00011010, 0b10100000}
	t.Run("static bool array encoding", func(t *testing.T) {
		inputBase := []bool{false, false, false, true, true, false, true, false, true, false, true}
		arrayElems := make([]Value, len(inputBase))
		for index, bVal := range inputBase {
			arrayElems[index] = MakeBool(bVal)
		}
		expected := []byte{
			0b00011010, 0b10100000,
		}
		boolArr, err := MakeStaticArray(arrayElems)
		require.NoError(t, err, "make static array should not return error")
		boolArrEncode, err := boolArr.Encode()
		require.NoError(t, err, "static bool array encoding should not return error")
		require.Equal(t, expected, boolArrEncode, "static bool array encode not match expected")
	})

	// encoding test for dynamic bool array
	// input: {F, T, F, T, F, T, F, T, F, T}, encode expected: {0b01010101, 0b01000000}
	t.Run("dynamic bool array encoding", func(t *testing.T) {
		inputBase := []bool{false, true, false, true, false, true, false, true, false, true}
		arrayElems := make([]Value, len(inputBase))
		for index, bVal := range inputBase {
			arrayElems[index] = MakeBool(bVal)
		}
		expected := []byte{
			0x00, 0x0A, 0b01010101, 0b01000000,
		}
		boolArr, err := MakeDynamicArray(arrayElems, MakeBoolType())
		require.NoError(t, err, "make dynamic array should not return error")
		boolArrEncode, err := boolArr.Encode()
		require.NoError(t, err, "dynamic bool array encoding should not return error")
		require.Equal(t, expected, boolArrEncode, "dynamic bool array encode not match expected")
	})

	// encoding test for dynamic tuple values
	// input type: (string, bool, bool, bool, bool, string)
	// input value: ("ABC", T, F, T, F, "DEF")
	/*
	   encode expected:
	   0x00, 0x05                        (first string start at 5th byte)
	   0b10100000                        (4 bool tuple element compacted together)
	   0x00, 0x0A                        (second string start at 10th byte)
	   0x00, 0x03                        (first string byte length 3)
	   byte('A'), byte('B'), byte('C')   (first string encoded bytes)
	   0x00, 0x03                        (second string byte length 3)
	   byte('D'), byte('E'), byte('F')   (second string encoded bytes)
	*/
	t.Run("dynamic tuple encoding", func(t *testing.T) {
		inputBase := []interface{}{
			"ABC", true, false, true, false, "DEF",
		}
		tupleElems := make([]Value, len(inputBase))
		// make tuple element values
		for index, bVal := range inputBase {
			temp, ok := bVal.(string)
			if ok {
				tupleElems[index] = MakeString(temp)
			} else {
				temp := bVal.(bool)
				tupleElems[index] = MakeBool(temp)
			}
		}
		expected := []byte{
			0x00, 0x05, 0b10100000, 0x00, 0x0A,
			0x00, 0x03, byte('A'), byte('B'), byte('C'),
			0x00, 0x03, byte('D'), byte('E'), byte('F'),
		}
		stringTuple, err := MakeTuple(tupleElems)
		require.NoError(t, err, "make string tuple should not return error")
		stringTupleEncode, err := stringTuple.Encode()
		require.NoError(t, err, "string tuple encoding should not return error")
		require.Equal(t, expected, stringTupleEncode, "string tuple encoding not match expected")
	})

	// encoding test for tuples with static bool arrays
	// input type: {bool[2], bool[2]}
	// input value: ({T, T}, {T, T})
	/*
	   encode expected:
	   0b11000000      (first static bool array)
	   0b11000000      (second static bool array)
	*/
	t.Run("static bool array tuple encoding", func(t *testing.T) {
		boolArr := []bool{true, true}
		boolValArr := make([]Value, 2)
		for i := 0; i < 2; i++ {
			boolValArr[i] = MakeBool(boolArr[i])
		}
		boolArrVal, err := MakeStaticArray(boolValArr)
		require.NoError(t, err, "make bool static array should not return error")
		tupleVal, err := MakeTuple([]Value{boolArrVal, boolArrVal})
		require.NoError(t, err, "make tuple value should not return error")
		expected := []byte{
			0b11000000,
			0b11000000,
		}
		actual, err := tupleVal.Encode()
		require.NoError(t, err, "encode tuple value should not return error")
		require.Equal(t, expected, actual, "encode static bool tuple should be equal")
	})

	// encoding test for tuples with static and dynamic bool arrays
	// input type: (bool[2], bool[])
	// input value: ({T, T}, {T, T})
	/*
	   encode expected:
	   0b11000000      (first static bool array)
	   0x00, 0x03      (second dynamic bool array starts at 3rd byte)
	   0x00, 0x02      (dynamic bool array length 2)
	   0b11000000      (second static bool array)
	*/
	t.Run("static/dynamic bool array tuple encoding", func(t *testing.T) {
		boolArr := []bool{true, true}
		boolValArr := make([]Value, 2)
		for i := 0; i < 2; i++ {
			boolValArr[i] = MakeBool(boolArr[i])
		}
		boolArrStaticVal, err := MakeStaticArray(boolValArr)
		require.NoError(t, err, "make static bool array should not return error")
		boolArrDynamicVal, err := MakeDynamicArray(boolValArr, MakeBoolType())
		require.NoError(t, err, "make dynamic bool array should not return error")
		tupleVal, err := MakeTuple([]Value{boolArrStaticVal, boolArrDynamicVal})
		require.NoError(t, err, "make tuple for static/dynamic bool array should not return error")
		expected := []byte{
			0b11000000,
			0x00, 0x03,
			0x00, 0x02, 0b11000000,
		}
		actual, err := tupleVal.Encode()
		require.NoError(t, err, "tuple value encoding should not return error")
		require.Equal(t, expected, actual, "encode static/dynamic bool array tuple should not return error")
	})

	// encoding test for tuples with all dynamic bool arrays
	// input type: (bool[], bool[])
	// input values: ({}, {})
	/*
	   encode expected:
	   0x00, 0x04      (first dynamic bool array starts at 4th byte)
	   0x00, 0x06      (second dynamic bool array starts at 6th byte)
	   0x00, 0x00      (first dynamic bool array length 0)
	   0x00, 0x00      (second dynamic bool array length 0)
	*/
	t.Run("empty dynamic array tuple encoding", func(t *testing.T) {
		emptyDynamicArray, err := MakeDynamicArray([]Value{}, MakeBoolType())
		require.NoError(t, err, "make empty dynamic array should not return error")
		tupleVal, err := MakeTuple([]Value{emptyDynamicArray, emptyDynamicArray})
		require.NoError(t, err, "make empty dynamic array tuple should not return error")
		expected := []byte{
			0x00, 0x04, 0x00, 0x06,
			0x00, 0x00, 0x00, 0x00,
		}
		actual, err := tupleVal.Encode()
		require.NoError(t, err, "encode empty dynamic array tuple should not return error")
		require.Equal(t, expected, actual, "encode empty dynamic array tuple does not match with expected")
	})

	// encoding test for empty tuple
	// input: (), expected encoding: ""
	t.Run("empty tuple encoding", func(t *testing.T) {
		emptyTuple, err := MakeTuple([]Value{})
		require.NoError(t, err, "make empty tuple should not return error")
		expected := make([]byte, 0)
		actual, err := emptyTuple.Encode()
		require.NoError(t, err, "encode empty tuple should not return error")
		require.Equal(t, expected, actual, "empty tuple encode should not return error")
	})
}

func TestDecodeValid(t *testing.T) {
	partitiontest.PartitionTest(t)
	// decoding test for uint, iterating through all valid uint bitSize
	// randomly take 1000 tests on each valid bitSize
	// generate bytes from random uint values and decode bytes with additional type information
	for intSize := 8; intSize <= 512; intSize += 8 {
		upperLimit := big.NewInt(0).Lsh(big.NewInt(1), uint(intSize))
		for i := 0; i < 1000; i++ {
			randomInt, err := rand.Int(rand.Reader, upperLimit)
			require.NoError(t, err, "cryptographic random int init fail")
			expected, err := MakeUint(randomInt, uint16(intSize))
			require.NoError(t, err, "makeUint Fail")
			encodedUint, err := expected.Encode()
			require.NoError(t, err, "uint encode fail")
			// attempt to decode from given bytes: encodedUint
			uintType, err := MakeUintType(uint16(intSize))
			require.NoError(t, err, "uint type make fail")
			actual, err := Decode(encodedUint, uintType)
			require.NoError(t, err, "decoding uint should not return error")
			require.Equal(t, expected, actual, "decode uint fail to match expected value")
		}
	}

	// decoding test for ufixed, iterating through all valid ufixed bitSize and precision
	// randomly take 10 tests on each valid setting
	// generate ufixed bytes and try to decode back with additional type information
	for size := 8; size <= 512; size += 8 {
		upperLimit := big.NewInt(0).Lsh(big.NewInt(1), uint(size))
		for precision := 1; precision <= 160; precision++ {
			for i := 0; i < 10; i++ {
				randomInt, err := rand.Int(rand.Reader, upperLimit)
				require.NoError(t, err, "cryptographic random int init fail")

				valueUfixed, err := MakeUfixed(randomInt, uint16(size), uint16(precision))
				require.NoError(t, err, "makeUfixed Fail")

				encodedUfixed, err := valueUfixed.Encode()
				require.NoError(t, err, "ufixed encode fail")

				ufixedType, err := MakeUfixedType(uint16(size), uint16(precision))
				require.NoError(t, err, "ufixed type make fail")

				decodedUfixed, err := Decode(encodedUfixed, ufixedType)
				require.NoError(t, err, "decoding ufixed should not return error")
				require.Equal(t, valueUfixed, decodedUfixed, "decode ufixed fail to match expected value")
			}
		}
	}

	// decoding test for address, randomly take 1000 tests
	// address is type alias of byte[32], we generate address value with random 256 bit big int values
	// we make the expected address value and decode the encoding of expected, check if they match
	upperLimit := big.NewInt(0).Lsh(big.NewInt(1), 256)
	for i := 0; i < 1000; i++ {
		randomAddrInt, err := rand.Int(rand.Reader, upperLimit)
		require.NoError(t, err, "cryptographic random int init fail")

		addressBytes := randomAddrInt.Bytes()
		address := make([]byte, 32-len(addressBytes))
		address = append(address, addressBytes...)

		var addrBytes [32]byte
		copy(addrBytes[:], address[:32])

		addressValue := MakeAddress(addrBytes)
		addrEncode, err := addressValue.Encode()
		require.NoError(t, err, "address encode fail")

		addressDecoded, err := Decode(addrEncode, MakeAddressType())
		require.NoError(t, err, "decoding address should not return error")
		require.Equal(t, addressValue, addressDecoded, "decode addr not match with expected")
	}

	// bool value decoding test
	for i := 0; i < 2; i++ {
		boolValue := MakeBool(i == 1)
		boolEncode, err := boolValue.Encode()
		require.NoError(t, err, "bool encode fail")
		boolDecode, err := Decode(boolEncode, MakeBoolType())
		require.NoError(t, err, "decoding bool should not return error")
		require.Equal(t, boolValue, boolDecode, "decode bool not match with expected")
	}

	// byte value decoding test, iterating through 256 valid byte value
	for i := 0; i < (1 << 8); i++ {
		byteValue := MakeByte(byte(i))
		byteEncode, err := byteValue.Encode()
		require.NoError(t, err, "byte encode fail")
		byteDecode, err := Decode(byteEncode, MakeByteType())
		require.NoError(t, err, "decoding byte should not return error")
		require.Equal(t, byteValue, byteDecode, "decode byte not match with expected")
	}

	// string value decoding test, test from utf string length 1 to 100
	// randomly take 10 utf-8 strings to make ABI string values
	// decode the encoded expected value and check if they match
	for length := 1; length <= 100; length++ {
		for i := 0; i < 10; i++ {
			utf8Str := gobberish.GenerateString(length)
			strValue := MakeString(utf8Str)
			strEncode, err := strValue.Encode()
			require.NoError(t, err, "string encode fail")
			strDecode, err := Decode(strEncode, MakeStringType())
			require.NoError(t, err, "decoding string should not return error")
			require.Equal(t, strValue, strDecode, "encode string not match with expected")
		}
	}

	// decoding test for static bool array
	// expected value: bool[5]: {T, F, F, T, T}
	// input: 0b10011000
	t.Run("static bool array decode", func(t *testing.T) {
		inputBase := []bool{true, false, false, true, true}
		arrayElems := make([]Value, len(inputBase))
		for index, bVal := range inputBase {
			arrayElems[index] = MakeBool(bVal)
		}
		expected, err := MakeStaticArray(arrayElems)
		require.NoError(t, err, "make expected value should not return error")
		actual, err := Decode(
			[]byte{0b10011000},
			MakeStaticArrayType(MakeBoolType(), uint16(len(inputBase))),
		)
		require.NoError(t, err, "decoding static bool array should not return error")
		require.Equal(t, expected, actual, "static bool array decode do not match expected")
	})

	// decoding test for static bool array
	// expected value: bool[11]: F, F, F, T, T, F, T, F, T, F, T
	// input: 0b00011010, 0b10100000
	t.Run("static bool array decode", func(t *testing.T) {
		inputBase := []bool{false, false, false, true, true, false, true, false, true, false, true}
		arrayElems := make([]Value, len(inputBase))
		for index, bVal := range inputBase {
			arrayElems[index] = MakeBool(bVal)
		}
		expected, err := MakeStaticArray(arrayElems)
		require.NoError(t, err, "make expected value should not return error")
		actual, err := Decode(
			[]byte{
				0b00011010, 0b10100000,
			},
			MakeStaticArrayType(MakeBoolType(), uint16(len(inputBase))),
		)
		require.NoError(t, err, "decoding static bool array should not return error")
		require.Equal(t, expected, actual, "static bool array decode do not match expected")
	})

	// decoding test for static uint array
	// expected input: uint64[8]: {1, 2, 3, 4, 5, 6, 7, 8}
	/*
		input: 0, 0, 0, 0, 0, 0, 0, 1      (encoding for uint64 1)
		       0, 0, 0, 0, 0, 0, 0, 2      (encoding for uint64 2)
		       0, 0, 0, 0, 0, 0, 0, 3      (encoding for uint64 3)
		       0, 0, 0, 0, 0, 0, 0, 4      (encoding for uint64 4)
		       0, 0, 0, 0, 0, 0, 0, 5      (encoding for uint64 5)
		       0, 0, 0, 0, 0, 0, 0, 6      (encoding for uint64 6)
		       0, 0, 0, 0, 0, 0, 0, 7      (encoding for uint64 7)
		       0, 0, 0, 0, 0, 0, 0, 8      (encoding for uint64 8)
	*/
	t.Run("static uint array decode", func(t *testing.T) {
		inputUint := []uint64{1, 2, 3, 4, 5, 6, 7, 8}
		arrayElems := make([]Value, len(inputUint))
		for index, uintVal := range inputUint {
			arrayElems[index] = MakeUint64(uintVal)
		}
		uintT, err := MakeUintType(64)
		require.NoError(t, err, "make uint64 type should not return error")
		expected, err := MakeStaticArray(arrayElems)
		require.NoError(t, err, "make uint64 static array should not return error")
		arrayEncoded, err := expected.Encode()
		require.NoError(t, err, "uint64 static array encode should not return error")
		arrayDecoded, err := Decode(arrayEncoded, MakeStaticArrayType(uintT, uint16(len(inputUint))))
		require.NoError(t, err, "uint64 static array decode should not return error")
		require.Equal(t, expected, arrayDecoded, "uint64 static array decode do not match with expected value")
	})

	// decoding test for dynamic bool array
	// expected value: bool[]: {F, T, F, T, F, T, F, T, F, T}
	/*
	   input bytes: 0x00, 0x0A                (dynamic bool array length 10)
	                0b01010101, 0b01000000    (dynamic bool array encoding)
	*/
	t.Run("dynamic bool array decode", func(t *testing.T) {
		inputBool := []bool{false, true, false, true, false, true, false, true, false, true}
		arrayElems := make([]Value, len(inputBool))
		for index, bVal := range inputBool {
			arrayElems[index] = MakeBool(bVal)
		}
		expected, err := MakeDynamicArray(arrayElems, MakeBoolType())
		require.NoError(t, err, "make expected value should not return error")
		inputEncoded := []byte{
			0x00, 0x0A, 0b01010101, 0b01000000,
		}
		actual, err := Decode(inputEncoded, MakeDynamicArrayType(MakeBoolType()))
		require.NoError(t, err, "decode dynamic array should not return error")
		require.Equal(t, expected, actual, "decode dynamic array do not match expected")
	})

	// decoding test for dynamic tuple values
	// expected value type: (string, bool, bool, bool, bool, string)
	// expected value: ("ABC", T, F, T, F, "DEF")
	/*
	   input bytes:
	   0x00, 0x05                        (first string start at 5th byte)
	   0b10100000                        (4 bool tuple element compacted together)
	   0x00, 0x0A                        (second string start at 10th byte)
	   0x00, 0x03                        (first string byte length 3)
	   byte('A'), byte('B'), byte('C')   (first string encoded bytes)
	   0x00, 0x03                        (second string byte length 3)
	   byte('D'), byte('E'), byte('F')   (second string encoded bytes)
	*/
	t.Run("dynamic tuple decoding", func(t *testing.T) {
		inputEncode := []byte{
			0x00, 0x05, 0b10100000, 0x00, 0x0A,
			0x00, 0x03, byte('A'), byte('B'), byte('C'),
			0x00, 0x03, byte('D'), byte('E'), byte('F'),
		}
		expectedBase := []interface{}{
			"ABC", true, false, true, false, "DEF",
		}
		tupleElems := make([]Value, len(expectedBase))
		for index, bVal := range expectedBase {
			temp, ok := bVal.(string)
			if ok {
				tupleElems[index] = MakeString(temp)
			} else {
				temp := bVal.(bool)
				tupleElems[index] = MakeBool(temp)
			}
		}
		expected, err := MakeTuple(tupleElems)
		require.NoError(t, err, "make expected value should not return error")
		actual, err := Decode(
			inputEncode,
			Type{
				abiTypeID: Tuple,
				childTypes: []Type{
					MakeStringType(),
					MakeBoolType(), MakeBoolType(), MakeBoolType(), MakeBoolType(),
					MakeStringType(),
				},
				staticLength: 6,
			},
		)
		require.NoError(t, err, "decoding dynamic tuple should not return error")
		require.Equal(t, expected, actual, "dynamic tuple not match with expected")
	})

	// decoding test for tuple with static bool array
	// expected type: (bool[2], bool[2])
	// expected value: ({T, T}, {T, T})
	/*
	   input bytes:
	   0b11000000      (first static bool array)
	   0b11000000      (second static bool array)
	*/
	t.Run("static bool array tuple decoding", func(t *testing.T) {
		boolArr := []bool{true, true}
		boolValArr := make([]Value, 2)
		for i := 0; i < 2; i++ {
			boolValArr[i] = MakeBool(boolArr[i])
		}
		boolArrVal, err := MakeStaticArray(boolValArr)
		require.NoError(t, err, "make bool static array should not return error")
		tupleVal, err := MakeTuple([]Value{boolArrVal, boolArrVal})
		require.NoError(t, err, "make tuple value should not return error")
		encodedInput := []byte{
			0b11000000,
			0b11000000,
		}
		decoded, err := Decode(encodedInput, Type{
			abiTypeID:    Tuple,
			staticLength: 2,
			childTypes: []Type{
				{
					abiTypeID:    ArrayStatic,
					staticLength: 2,
					childTypes:   []Type{MakeBoolType()},
				},
				{
					abiTypeID:    ArrayStatic,
					staticLength: 2,
					childTypes:   []Type{MakeBoolType()},
				},
			},
		})
		require.NoError(t, err, "decode tuple value should not return error")
		require.Equal(t, tupleVal, decoded, "decoded tuple value do not match with expected")
	})

	// decoding test for tuple with static and dynamic bool array
	// expected type: (bool[2], bool[])
	// expected value: ({T, T}, {T, T})
	/*
	   input bytes:
	   0b11000000      (first static bool array)
	   0x00, 0x03      (second dynamic bool array starts at 3rd byte)
	   0x00, 0x02      (dynamic bool array length 2)
	   0b11000000      (second static bool array)
	*/
	t.Run("static/dynamic bool array tuple decoding", func(t *testing.T) {
		boolArr := []bool{true, true}
		boolValArr := make([]Value, 2)
		for i := 0; i < 2; i++ {
			boolValArr[i] = MakeBool(boolArr[i])
		}
		boolArrStaticVal, err := MakeStaticArray(boolValArr)
		require.NoError(t, err, "make static bool array should not return error")
		boolArrDynamicVal, err := MakeDynamicArray(boolValArr, MakeBoolType())
		require.NoError(t, err, "make dynamic bool array should not return error")
		tupleVal, err := MakeTuple([]Value{boolArrStaticVal, boolArrDynamicVal})
		require.NoError(t, err, "make tuple for static/dynamic bool array should not return error")
		encodedInput := []byte{
			0b11000000,
			0x00, 0x03,
			0x00, 0x02, 0b11000000,
		}
		decoded, err := Decode(encodedInput, Type{
			abiTypeID:    Tuple,
			staticLength: 2,
			childTypes: []Type{
				{
					abiTypeID:    ArrayStatic,
					staticLength: 2,
					childTypes:   []Type{MakeBoolType()},
				},
				{
					abiTypeID:  ArrayDynamic,
					childTypes: []Type{MakeBoolType()},
				},
			},
		})
		require.NoError(t, err, "decode tuple for static/dynamic bool array should not return error")
		require.Equal(t, tupleVal, decoded, "decoded tuple value do not match with expected")
	})

	// decoding test for tuple with all dynamic bool array
	// expected value: (bool[], bool[])
	// expected value: ({}, {})
	/*
	   input bytes:
	   0x00, 0x04      (first dynamic bool array starts at 4th byte)
	   0x00, 0x06      (second dynamic bool array starts at 6th byte)
	   0x00, 0x00      (first dynamic bool array length 0)
	   0x00, 0x00      (second dynamic bool array length 0)
	*/
	t.Run("empty dynamic array tuple decoding", func(t *testing.T) {
		emptyDynamicArray, err := MakeDynamicArray([]Value{}, MakeBoolType())
		require.NoError(t, err, "make empty dynamic array should not return error")
		tupleVal, err := MakeTuple([]Value{emptyDynamicArray, emptyDynamicArray})
		require.NoError(t, err, "make empty dynamic array tuple should not return error")
		encodedInput := []byte{
			0x00, 0x04, 0x00, 0x06,
			0x00, 0x00, 0x00, 0x00,
		}
		decoded, err := Decode(encodedInput, Type{
			abiTypeID:    Tuple,
			staticLength: 2,
			childTypes: []Type{
				{
					abiTypeID:  ArrayDynamic,
					childTypes: []Type{MakeBoolType()},
				},
				{
					abiTypeID:  ArrayDynamic,
					childTypes: []Type{MakeBoolType()},
				},
			},
		})
		require.NoError(t, err, "decode tuple for empty dynamic array should not return error")
		require.Equal(t, tupleVal, decoded, "decoded tuple value do not match with expected")
	})

	// decoding test for empty tuple
	// expected value: ()
	// byte input: ""
	t.Run("empty tuple decoding", func(t *testing.T) {
		emptyTuple, err := MakeTuple([]Value{})
		require.NoError(t, err, "make empty tuple should not return error")
		encodedInput := make([]byte, 0)
		decoded, err := Decode(encodedInput, Type{
			abiTypeID:    Tuple,
			staticLength: 0,
			childTypes:   []Type{},
		})
		require.NoError(t, err, "decode empty tuple should not return error")
		require.Equal(t, emptyTuple, decoded, "empty tuple encode should not return error")
	})
}

func TestDecodeInvalid(t *testing.T) {
	partitiontest.PartitionTest(t)
	// decoding test for *corrupted* static bool array
	// expected 9 elements for static bool array
	// encoded bytes have only 8 bool values
	// should throw error
	t.Run("corrupted static bool array decode", func(t *testing.T) {
		inputBase := []byte{0b11111111}
		arrayType := MakeStaticArrayType(MakeBoolType(), 9)
		_, err := Decode(inputBase, arrayType)
		require.Error(t, err, "decoding corrupted static bool array should return error")
	})

	// decoding test for *corrupted* static bool array
	// expected 8 elements for static bool array
	// encoded bytes have 1 byte more (0b00000000)
	// should throw error
	t.Run("corrupted static bool array decode", func(t *testing.T) {
		inputBase := []byte{0b01001011, 0b00000000}
		arrayType := MakeStaticArrayType(MakeBoolType(), 8)
		_, err := Decode(inputBase, arrayType)
		require.Error(t, err, "decoding corrupted static bool array should return error")
	})

	// decoding test for *corrupted* static uint array
	// expected 8 uint elements in static uint64[8] array
	// encoded bytes provide only 7 uint64 encoding
	// should throw error
	t.Run("static uint array decode", func(t *testing.T) {
		inputBase := []byte{
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 1,
			0, 0, 0, 0, 0, 0, 0, 2,
			0, 0, 0, 0, 0, 0, 0, 3,
			0, 0, 0, 0, 0, 0, 0, 4,
			0, 0, 0, 0, 0, 0, 0, 5,
			0, 0, 0, 0, 0, 0, 0, 6,
		}
		uintT, err := MakeUintType(64)
		require.NoError(t, err, "make uint64 type should not return error")
		uintTArray := MakeStaticArrayType(uintT, 8)
		_, err = Decode(inputBase, uintTArray)
		require.Error(t, err, "corrupted uint64 static array decode should return error")
	})

	// decoding test for *corrupted* static uint array
	// expected 7 uint elements in static uint64[7] array
	// encoded bytes provide 8 uint64 encoding (one more uint64: 7)
	// should throw error
	t.Run("static uint array decode", func(t *testing.T) {
		inputBase := []byte{
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 1,
			0, 0, 0, 0, 0, 0, 0, 2,
			0, 0, 0, 0, 0, 0, 0, 3,
			0, 0, 0, 0, 0, 0, 0, 4,
			0, 0, 0, 0, 0, 0, 0, 5,
			0, 0, 0, 0, 0, 0, 0, 6,
			0, 0, 0, 0, 0, 0, 0, 7,
		}
		uintT, err := MakeUintType(64)
		require.NoError(t, err, "make uint64 type should not return error")
		uintTArray := MakeStaticArrayType(uintT, 7)
		_, err = Decode(inputBase, uintTArray)
		require.Error(t, err, "corrupted uint64 static array decode should return error")
	})

	// decoding test for *corrupted* dynamic bool array
	// expected 0x0A (10) bool elements in encoding head
	// encoded bytes provide only 8 bool elements
	// should throw error
	t.Run("corrupted dynamic bool array decode", func(t *testing.T) {
		inputBase := []byte{
			0x00, 0x0A, 0b10101010,
		}
		dynamicT := MakeDynamicArrayType(MakeBoolType())
		_, err := Decode(inputBase, dynamicT)
		require.Error(t, err, "decode corrupted dynamic array should return error")
	})

	// decoding test for *corrupted* dynamic bool array
	// expected 0x07 (7) bool elements in encoding head
	// encoded bytes provide 1 byte more (0b00000000)
	// should throw error
	t.Run("corrupted dynamic bool array decode", func(t *testing.T) {
		inputBase := []byte{
			0x00, 0x07, 0b10101010, 0b00000000,
		}
		dynamicT := MakeDynamicArrayType(MakeBoolType())
		_, err := Decode(inputBase, dynamicT)
		require.Error(t, err, "decode corrupted dynamic array should return error")
	})

	// decoding test for *corrupted* dynamic tuple value
	// expected type: (string, bool, bool, bool, bool, string)
	// expected value: ("ABC", T, F, T, F, "DEF")
	/*
	   corrupted bytes:
	   0x00, 0x04                        (corrupted: first string start at 4th byte, should be 5th)
	   0b10100000                        (4 bool tuple element compacted together)
	   0x00, 0x0A                        (second string start at 10th byte)
	   0x00, 0x03                        (first string byte length 3)
	   byte('A'), byte('B'), byte('C')   (first string encoded bytes)
	   0x00, 0x03                        (second string byte length 3)
	   byte('D'), byte('E'), byte('F')   (second string encoded bytes)
	*/
	// the result would be: first string have length 0x0A, 0x00
	// the length exceeds the segment it allocated: 0x0A, 0x00, 0x03, byte('A'), byte('B'), byte('C')
	// should throw error
	t.Run("corrupted dynamic tuple decoding", func(t *testing.T) {
		inputEncode := []byte{
			0x00, 0x04, 0b10100000, 0x00, 0x0A,
			0x00, 0x03, byte('A'), byte('B'), byte('C'),
			0x00, 0x03, byte('D'), byte('E'), byte('F'),
		}
		expectedBase := []interface{}{
			"ABC", true, false, true, false, "DEF",
		}
		tupleElems := make([]Value, len(expectedBase))
		for index, bVal := range expectedBase {
			temp, ok := bVal.(string)
			if ok {
				tupleElems[index] = MakeString(temp)
			} else {
				temp := bVal.(bool)
				tupleElems[index] = MakeBool(temp)
			}
		}
		_, err := Decode(
			inputEncode,
			Type{
				abiTypeID: Tuple,
				childTypes: []Type{
					MakeStringType(),
					MakeBoolType(), MakeBoolType(), MakeBoolType(), MakeBoolType(),
					MakeStringType(),
				},
			},
		)
		require.Error(t, err, "corrupted decoding dynamic tuple should return error")
	})

	// decoding test for *corrupted* tuple with static bool arrays
	// expected type: (bool[2], bool[2])
	// expected value: ({T, T}, {T, T})
	/*
		    corrupted bytes test case 0:
			0b11000000
			0b11000000
		    0b00000000  <- corrupted byte, 1 byte more

		   corrupted bytes test case 0:
			0b11000000
		                <- corrupted byte, 1 byte missing
	*/
	t.Run("corrupted static bool array tuple decoding", func(t *testing.T) {
		expectedType := Type{
			abiTypeID:    Tuple,
			staticLength: 2,
			childTypes: []Type{
				{
					abiTypeID:    ArrayStatic,
					staticLength: 2,
					childTypes:   []Type{MakeBoolType()},
				},
				{
					abiTypeID:    ArrayStatic,
					staticLength: 2,
					childTypes:   []Type{MakeBoolType()},
				},
			},
		}

		encodedInput0 := []byte{
			0b11000000,
			0b11000000,
			0b00000000,
		}
		_, err := Decode(encodedInput0, expectedType)
		require.Error(t, err, "decode corrupted tuple value should return error")

		encodedInput1 := []byte{
			0b11000000,
		}
		_, err = Decode(encodedInput1, expectedType)
		require.Error(t, err, "decode corrupted tuple value should return error")
	})

	// decoding test for *corrupted* tuple with static and dynamic bool array
	// expected type: (bool[2], bool[])
	// expected value: ({T, T}, {T, T})
	/*
	   corrupted bytes:
	   0b11000000      (first static bool array)
	   0x03            <- corrupted, missing 0x00 byte (second dynamic bool array starts at 3rd byte)
	   0x00, 0x02      (dynamic bool array length 2)
	   0b11000000      (second static bool array)
	*/
	t.Run("corrupted static/dynamic bool array tuple decoding", func(t *testing.T) {
		encodedInput := []byte{
			0b11000000,
			0x03,
			0x00, 0x02, 0b11000000,
		}
		_, err := Decode(encodedInput, Type{
			abiTypeID:    Tuple,
			staticLength: 2,
			childTypes: []Type{
				{
					abiTypeID:    ArrayStatic,
					staticLength: 2,
					childTypes:   []Type{MakeBoolType()},
				},
				{
					abiTypeID:  ArrayDynamic,
					childTypes: []Type{MakeBoolType()},
				},
			},
		})
		require.Error(t, err, "decode corrupted tuple for static/dynamic bool array should return error")
	})

	// decoding test for *corrupted* tuple with dynamic bool array
	// expected type: (bool[], bool[])
	// expected value: ({}, {})
	/*
	   corrupted bytes:
	   0x00, 0x04      (first dynamic bool array starts at 4th byte)
	   0x00, 0x07      <- corrupted, should be 0x06 (second dynamic bool array starts at 6th byte)
	   0x00, 0x00      (first dynamic bool array length 0)
	   0x00, 0x00      (second dynamic bool array length 0)

	   first dynamic array starts at 0x04, segment is 0x00, 0x00, 0x00, 1 byte 0x00 more
	   second dynamic array starts at 0x07, and only have 0x00 1 byte
	*/
	// should return error
	t.Run("corrupted empty dynamic array tuple decoding", func(t *testing.T) {
		encodedInput := []byte{
			0x00, 0x04, 0x00, 0x07,
			0x00, 0x00, 0x00, 0x00,
		}
		_, err := Decode(encodedInput, Type{
			abiTypeID:    Tuple,
			staticLength: 2,
			childTypes: []Type{
				{
					abiTypeID:  ArrayDynamic,
					childTypes: []Type{MakeBoolType()},
				},
				{
					abiTypeID:  ArrayDynamic,
					childTypes: []Type{MakeBoolType()},
				},
			},
		})
		require.Error(t, err, "decode corrupted tuple for empty dynamic array should return error")
	})

	// decoding test for *corrupted* empty tuple
	// expected value: ()
	// corrupted input: 0xFF, should be empty byte
	// should return error
	t.Run("corrupted empty tuple decoding", func(t *testing.T) {
		encodedInput := []byte{0xFF}
		_, err := Decode(encodedInput, Type{
			abiTypeID:    Tuple,
			staticLength: 0,
			childTypes:   []Type{},
		})
		require.Error(t, err, "decode corrupted empty tuple should return error")
	})
}

func generateStaticArray(t *testing.T, testValuePool *[][]Value) {
	// int
	for intIndex := 0; intIndex < len((*testValuePool)[Uint]); intIndex += 200 {
		staticArrayList := make([]Value, 20)
		for i := 0; i < 20; i++ {
			staticArrayList[i] = (*testValuePool)[Uint][intIndex+i]
		}
		staticArray, err := MakeStaticArray(staticArrayList)
		require.NoError(t, err, "make static array for uint should not return error")
		(*testValuePool)[ArrayStatic] = append((*testValuePool)[ArrayStatic], staticArray)
	}
	// byte
	byteArrayList := make([]Value, 20)
	for byteIndex := 0; byteIndex < 20; byteIndex++ {
		byteArrayList[byteIndex] = (*testValuePool)[Byte][byteIndex]
	}
	byteStaticArray, err := MakeStaticArray(byteArrayList)
	require.NoError(t, err, "make static array for byte should not return error")
	(*testValuePool)[ArrayStatic] = append((*testValuePool)[ArrayStatic], byteStaticArray)
	// address
	addressArrayList := make([]Value, 20)
	for addrIndex := 0; addrIndex < 20; addrIndex++ {
		addressArrayList[addrIndex] = (*testValuePool)[Address][addrIndex]
	}
	addressStaticArray, err := MakeStaticArray(addressArrayList)
	require.NoError(t, err, "make static array for address should not return error")
	(*testValuePool)[ArrayStatic] = append((*testValuePool)[ArrayStatic], addressStaticArray)
	// string
	stringArrayList := make([]Value, 20)
	for strIndex := 0; strIndex < 20; strIndex++ {
		stringArrayList[strIndex] = (*testValuePool)[String][strIndex]
	}
	stringStaticArray, err := MakeStaticArray(stringArrayList)
	require.NoError(t, err, "make static array for string should not return error")
	(*testValuePool)[ArrayStatic] = append((*testValuePool)[ArrayStatic], stringStaticArray)
	// bool
	boolArrayList := make([]Value, 20)
	for boolIndex := 0; boolIndex < 20; boolIndex++ {
		valBig, err := rand.Int(rand.Reader, big.NewInt(2))
		require.NoError(t, err, "generate random bool index should not return error")
		valIndex := valBig.Int64()
		boolArrayList[boolIndex] = (*testValuePool)[Bool][valIndex]
	}
	boolStaticArray, err := MakeStaticArray(boolArrayList)
	require.NoError(t, err, "make static array for bool should not return error")
	(*testValuePool)[ArrayStatic] = append((*testValuePool)[ArrayStatic], boolStaticArray)
}

func generateDynamicArray(t *testing.T, testValuePool *[][]Value) {
	// int
	for intIndex := 0; intIndex < len((*testValuePool)[Uint]); intIndex += 200 {
		dynamicArrayList := make([]Value, 20)
		for i := 0; i < 20; i++ {
			dynamicArrayList[i] = (*testValuePool)[Uint][intIndex+i]
		}
		dynamicArray, err := MakeDynamicArray(dynamicArrayList, dynamicArrayList[0].ABIType)
		require.NoError(t, err, "make static array for uint should not return error")
		(*testValuePool)[ArrayDynamic] = append((*testValuePool)[ArrayDynamic], dynamicArray)
	}
	// byte
	byteArrayList := make([]Value, 20)
	for byteIndex := 0; byteIndex < 20; byteIndex++ {
		byteArrayList[byteIndex] = (*testValuePool)[Byte][byteIndex]
	}
	byteDynamicArray, err := MakeDynamicArray(byteArrayList, byteArrayList[0].ABIType)
	require.NoError(t, err, "make dynamic array for byte should not return error")
	(*testValuePool)[ArrayDynamic] = append((*testValuePool)[ArrayDynamic], byteDynamicArray)
	// address
	addressArrayList := make([]Value, 20)
	for addrIndex := 0; addrIndex < 20; addrIndex++ {
		addressArrayList[addrIndex] = (*testValuePool)[Address][addrIndex]
	}
	addressDynamicArray, err := MakeDynamicArray(addressArrayList, MakeAddressType())
	require.NoError(t, err, "make dynamic array for address should not return error")
	(*testValuePool)[ArrayDynamic] = append((*testValuePool)[ArrayDynamic], addressDynamicArray)
	// string
	stringArrayList := make([]Value, 20)
	for strIndex := 0; strIndex < 20; strIndex++ {
		stringArrayList[strIndex] = (*testValuePool)[String][strIndex]
	}
	stringDynamicArray, err := MakeDynamicArray(stringArrayList, MakeStringType())
	require.NoError(t, err, "make dynamic array for string should not return error")
	(*testValuePool)[ArrayDynamic] = append((*testValuePool)[ArrayDynamic], stringDynamicArray)
	// bool
	boolArrayList := make([]Value, 20)
	for boolIndex := 0; boolIndex < 20; boolIndex++ {
		valBig, err := rand.Int(rand.Reader, big.NewInt(2))
		require.NoError(t, err, "generate random bool index should not return error")
		valIndex := valBig.Int64()
		boolArrayList[boolIndex] = (*testValuePool)[Bool][valIndex]
	}
	boolDynamicArray, err := MakeDynamicArray(boolArrayList, MakeBoolType())
	require.NoError(t, err, "make dynamic array for bool should not return error")
	(*testValuePool)[ArrayDynamic] = append((*testValuePool)[ArrayDynamic], boolDynamicArray)
}

func generateTuples(t *testing.T, testValuePool *[][]Value, slotRange int) {
	for i := 0; i < 100; i++ {
		tupleLenBig, err := rand.Int(rand.Reader, big.NewInt(2))
		require.NoError(t, err, "generate random tuple length should not return error")
		tupleLen := 1 + tupleLenBig.Int64()
		tupleValList := make([]Value, tupleLen)
		for tupleElemIndex := 0; tupleElemIndex < int(tupleLen); tupleElemIndex++ {
			tupleTypeIndexBig, err := rand.Int(rand.Reader, big.NewInt(int64(slotRange)))
			require.NoError(t, err, "generate random tuple element type index should not return error")
			tupleTypeIndex := tupleTypeIndexBig.Int64()
			tupleElemChoiceRange := len((*testValuePool)[tupleTypeIndex])

			tupleElemRangeIndexBig, err := rand.Int(rand.Reader, big.NewInt(int64(tupleElemChoiceRange)))
			require.NoError(t, err, "generate random tuple element index in test pool should not return error")
			tupleElemRangeIndex := tupleElemRangeIndexBig.Int64()
			tupleElem := (*testValuePool)[tupleTypeIndex][tupleElemRangeIndex]
			tupleValList[tupleElemIndex] = tupleElem
		}
		tupleVal, err := MakeTuple(tupleValList)
		require.NoError(t, err, "make tuple should not return error")
		(*testValuePool)[Tuple] = append((*testValuePool)[Tuple], tupleVal)
	}
}

// round-trip test for random tuple elements
// first we generate base type elements to each slot of testValuePool
// then we generate static/dynamic array based on the pre-generated random values
// we generate base tuples based on base-type elements/static arrays/dynamic arrays
// we also generate cascaded tuples (tuples with tuple elements)
func TestEncodeDecodeRandomTuple(t *testing.T) {
	partitiontest.PartitionTest(t)
	// test pool for 9 distinct types
	testValuePool := make([][]Value, 9)
	for i := 8; i <= 512; i += 8 {
		max := big.NewInt(1).Lsh(big.NewInt(1), uint(i))
		for j := 0; j < 200; j++ {
			randVal, err := rand.Int(rand.Reader, max)
			require.NoError(t, err, "generate largest number bound, should be no error")
			uintTemp, err := MakeUint(randVal, uint16(i))
			require.NoError(t, err, "generate random ABI uint should not return error")
			testValuePool[Uint] = append(testValuePool[Uint], uintTemp)
		}
		for j := 1; j < 160; j++ {
			randVal, err := rand.Int(rand.Reader, max)
			require.NoError(t, err, "generate largest number bound, should be no error")
			ufixedTemp, err := MakeUfixed(randVal, uint16(i), uint16(j))
			require.NoError(t, err, "generate random ABI ufixed should not return error")
			testValuePool[Ufixed] = append(testValuePool[Ufixed], ufixedTemp)
		}
	}
	for i := 0; i < (1 << 8); i++ {
		testValuePool[Byte] = append(testValuePool[Byte], MakeByte(byte(i)))
	}
	for i := 0; i < 2; i++ {
		testValuePool[Bool] = append(testValuePool[Bool], MakeBool(i == 1))
	}
	for i := 0; i < 500; i++ {
		max := big.NewInt(1).Lsh(big.NewInt(1), 256)
		randVal, err := rand.Int(rand.Reader, max)
		require.NoError(t, err, "generate largest number bound, should be no error")
		addrBytes := randVal.Bytes()
		remainBytes := make([]byte, 32-len(addrBytes))
		addrBytes = append(remainBytes, addrBytes...)
		var addrBytesToMake [32]byte
		copy(addrBytesToMake[:], addrBytes)
		testValuePool[Address] = append(testValuePool[Address], MakeAddress(addrBytesToMake))
	}
	for i := 1; i <= 100; i++ {
		for j := 0; j < 4; j++ {
			abiString := MakeString(gobberish.GenerateString(i))
			testValuePool[String] = append(testValuePool[String], abiString)
		}
	}
	// Array static
	generateStaticArray(t, &testValuePool)
	// Array dynamic
	generateDynamicArray(t, &testValuePool)
	// tuple generation
	generateTuples(t, &testValuePool, 8)
	// generate cascaded tuples
	generateTuples(t, &testValuePool, 9)
	// test tuple encode-decode round-trip
	for _, tuple := range testValuePool[Tuple] {
		t.Run("random tuple encode-decode test", func(t *testing.T) {
			encoded, err := tuple.Encode()
			require.NoError(t, err, "encode tuple should not have error")
			decoded, err := Decode(encoded, tuple.ABIType)
			require.NoError(t, err, "decode tuple should not have error")
			require.Equal(t, tuple, decoded, "encoded-decoded tuple should match with expected")
		})
	}
}
