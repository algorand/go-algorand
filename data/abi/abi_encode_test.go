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
		uintType, err := makeUintType(intSize)
		require.NoError(t, err, "make uint type fail")

		for i := 0; i < 1000; i++ {
			randomInt, err := rand.Int(rand.Reader, upperLimit)
			require.NoError(t, err, "cryptographic random int init fail")

			randomIntByte := randomInt.Bytes()
			expected := make([]byte, intSize/8-len(randomIntByte))
			expected = append(expected, randomIntByte...)

			uintEncode, err := uintType.Encode(randomInt)
			require.NoError(t, err, "encoding from uint type fail")

			require.Equal(t, expected, uintEncode, "encode uint not match with expected")
		}
		// 2^[bitSize] - 1 test
		// check if uint<bitSize> can contain max uint value (2^bitSize - 1)
		largest := big.NewInt(0).Add(
			upperLimit,
			big.NewInt(1).Neg(big.NewInt(1)),
		)
		encoded, err := uintType.Encode(largest)
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
			typeUfixed, err := makeUfixedType(size, precision)
			require.NoError(t, err, "make ufixed type fail")

			for i := 0; i < 10; i++ {
				randomInt, err := rand.Int(rand.Reader, upperLimit)
				require.NoError(t, err, "cryptographic random int init fail")

				encodedUfixed, err := typeUfixed.Encode(randomInt)
				require.NoError(t, err, "ufixed encode fail")

				randomBytes := randomInt.Bytes()
				buffer := make([]byte, size/8-len(randomBytes))
				buffer = append(buffer, randomBytes...)
				require.Equal(t, buffer, encodedUfixed, "encode ufixed not match with expected")
			}
			// (2^[bitSize] - 1) / (10^[precision]) test
			ufixedLargestEncode, err := typeUfixed.Encode(largest)
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

		addrBytesActual, err := addressType.Encode(addrBytesExpected)
		require.NoError(t, err, "address encode fail")
		require.Equal(t, addrBytesExpected, addrBytesActual, "encode addr not match with expected")
	}

	// encoding test for bool values
	for i := 0; i < 2; i++ {
		boolEncode, err := boolType.Encode(i == 1)
		require.NoError(t, err, "bool encode fail")
		expected := []byte{0x00}
		if i == 1 {
			expected = []byte{0x80}
		}
		require.Equal(t, expected, boolEncode, "encode bool not match with expected")
	}

	// encoding test for byte values
	for i := 0; i < (1 << 8); i++ {
		byteEncode, err := byteType.Encode(byte(i))
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
			// since string is just type alias of `byte[]`, we need to store number of bytes in encoding
			utf8ByteLen := len([]byte(utf8Str))
			lengthBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(lengthBytes, uint16(utf8ByteLen))
			expected := append(lengthBytes, []byte(utf8Str)...)

			strEncode, err := stringType.Encode(utf8Str)
			require.NoError(t, err, "string encode fail")
			require.Equal(t, expected, strEncode, "encode string not match with expected")
		}
	}

	// encoding test for static bool array, the expected behavior of encoding is to
	// compress multiple bool into a single byte.
	// input: {T, F, F, T, T}, encode expected: {0b10011000}
	staticBoolArrType := makeStaticArrayType(boolType, 5)
	t.Run("static bool array encoding", func(t *testing.T) {
		inputBase := []bool{true, false, false, true, true}
		expected := []byte{
			0b10011000,
		}
		boolArrEncode, err := staticBoolArrType.Encode(inputBase)
		require.NoError(t, err, "static bool array encoding should not return error")
		require.Equal(t, expected, boolArrEncode, "static bool array encode not match expected")
	})

	// encoding test for static bool array
	// input: {F, F, F, T, T, F, T, F, T, F, T}, encode expected: {0b00011010, 0b10100000}
	staticBoolArrType = makeStaticArrayType(boolType, 11)
	t.Run("static bool array encoding", func(t *testing.T) {
		inputBase := []bool{false, false, false, true, true, false, true, false, true, false, true}
		expected := []byte{
			0b00011010, 0b10100000,
		}
		boolArrEncode, err := staticBoolArrType.Encode(inputBase)
		require.NoError(t, err, "static bool array encoding should not return error")
		require.Equal(t, expected, boolArrEncode, "static bool array encode not match expected")
	})

	// encoding test for dynamic bool array
	// input: {F, T, F, T, F, T, F, T, F, T}, encode expected: {0b01010101, 0b01000000}
	dynamicBoolArrayType := makeDynamicArrayType(boolType)
	t.Run("dynamic bool array encoding", func(t *testing.T) {
		inputBase := []bool{false, true, false, true, false, true, false, true, false, true}
		expected := []byte{
			0x00, 0x0A, 0b01010101, 0b01000000,
		}
		boolArrEncode, err := dynamicBoolArrayType.Encode(inputBase)
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
	tupleType, err := TypeOf("(string,bool,bool,bool,bool,string)")
	require.NoError(t, err, "type from string for dynamic tuple type should not return error")
	t.Run("dynamic tuple encoding", func(t *testing.T) {
		inputBase := []interface{}{
			"ABC", true, false, true, false, "DEF",
		}
		expected := []byte{
			0x00, 0x05, 0b10100000, 0x00, 0x0A,
			0x00, 0x03, byte('A'), byte('B'), byte('C'),
			0x00, 0x03, byte('D'), byte('E'), byte('F'),
		}
		stringTupleEncode, err := tupleType.Encode(inputBase)
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
	tupleType, err = TypeOf("(bool[2],bool[2])")
	require.NoError(t, err, "type from string for tuple type should not return error")
	t.Run("static bool array tuple encoding", func(t *testing.T) {
		expected := []byte{
			0b11000000,
			0b11000000,
		}
		actual, err := tupleType.Encode([]interface{}{
			[]bool{true, true},
			[]bool{true, true},
		})
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
	tupleType, err = TypeOf("(bool[2],bool[])")
	require.NoError(t, err, "type from string for tuple type should not return error")
	t.Run("static/dynamic bool array tuple encoding", func(t *testing.T) {
		expected := []byte{
			0b11000000,
			0x00, 0x03,
			0x00, 0x02, 0b11000000,
		}
		actual, err := tupleType.Encode([]interface{}{
			[]bool{true, true},
			[]bool{true, true},
		})
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
	tupleType, err = TypeOf("(bool[],bool[])")
	require.NoError(t, err, "type from string for tuple type should not return error")
	t.Run("empty dynamic array tuple encoding", func(t *testing.T) {
		expected := []byte{
			0x00, 0x04, 0x00, 0x06,
			0x00, 0x00, 0x00, 0x00,
		}
		actual, err := tupleType.Encode([]interface{}{
			[]bool{}, []bool{},
		})
		require.NoError(t, err, "encode empty dynamic array tuple should not return error")
		require.Equal(t, expected, actual, "encode empty dynamic array tuple does not match with expected")
	})

	// encoding test for empty tuple
	// input: (), expected encoding: ""
	tupleType, err = TypeOf("()")
	require.NoError(t, err, "type from string for tuple type should not return error")
	t.Run("empty tuple encoding", func(t *testing.T) {
		expected := make([]byte, 0)
		actual, err := tupleType.Encode([]interface{}{})
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
		uintType, err := makeUintType(intSize)
		require.NoError(t, err, "make uint type failure")
		for i := 0; i < 1000; i++ {
			randBig, err := rand.Int(rand.Reader, upperLimit)
			require.NoError(t, err, "cryptographic random int init fail")

			var expected interface{}
			if intSize <= 64 && intSize > 32 {
				expected = randBig.Uint64()
			} else if intSize <= 32 && intSize > 16 {
				expected = uint32(randBig.Uint64())
			} else if intSize == 16 {
				expected = uint16(randBig.Uint64())
			} else if intSize == 8 {
				expected = uint8(randBig.Uint64())
			} else {
				expected = randBig
			}

			encodedUint, err := uintType.Encode(expected)
			require.NoError(t, err, "uint encode fail")

			actual, err := uintType.Decode(encodedUint)
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
			ufixedType, err := makeUfixedType(size, precision)
			require.NoError(t, err, "make ufixed type failure")
			for i := 0; i < 10; i++ {
				randBig, err := rand.Int(rand.Reader, upperLimit)
				require.NoError(t, err, "cryptographic random int init fail")

				var expected interface{}
				if size <= 64 && size > 32 {
					expected = randBig.Uint64()
				} else if size <= 32 && size > 16 {
					expected = uint32(randBig.Uint64())
				} else if size == 16 {
					expected = uint16(randBig.Uint64())
				} else if size == 8 {
					expected = uint8(randBig.Uint64())
				} else {
					expected = randBig
				}

				encodedUfixed, err := ufixedType.Encode(expected)
				require.NoError(t, err, "ufixed encode fail")
				require.NoError(t, err, "cast big integer to expected value should not return error")

				actual, err := ufixedType.Decode(encodedUfixed)
				require.NoError(t, err, "decoding ufixed should not return error")
				require.Equal(t, expected, actual, "decode ufixed fail to match expected value")
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
		expected := make([]byte, 32-len(addressBytes))
		expected = append(expected, addressBytes...)

		actual, err := addressType.Decode(expected)
		require.NoError(t, err, "decoding address should not return error")
		require.Equal(t, expected, actual, "decode addr not match with expected")
	}

	// bool value decoding test
	for i := 0; i < 2; i++ {
		boolEncode, err := boolType.Encode(i == 1)
		require.NoError(t, err, "bool encode fail")
		actual, err := boolType.Decode(boolEncode)
		require.NoError(t, err, "decoding bool should not return error")
		require.Equal(t, i == 1, actual, "decode bool not match with expected")
	}

	// byte value decoding test, iterating through 256 valid byte value
	for i := 0; i < (1 << 8); i++ {
		byteEncode, err := byteType.Encode(byte(i))
		require.NoError(t, err, "byte encode fail")
		actual, err := byteType.Decode(byteEncode)
		require.NoError(t, err, "decoding byte should not return error")
		require.Equal(t, byte(i), actual, "decode byte not match with expected")
	}

	// string value decoding test, test from utf string length 1 to 100
	// randomly take 10 utf-8 strings to make ABI string values
	// decode the encoded expected value and check if they match
	for length := 1; length <= 100; length++ {
		for i := 0; i < 10; i++ {
			expected := gobberish.GenerateString(length)
			strEncode, err := stringType.Encode(expected)
			require.NoError(t, err, "string encode fail")
			actual, err := stringType.Decode(strEncode)
			require.NoError(t, err, "decoding string should not return error")
			require.Equal(t, expected, actual, "encode string not match with expected")
		}
	}

	// decoding test for static bool array
	// expected value: bool[5]: {T, F, F, T, T}
	// input: 0b10011000
	t.Run("static bool array decode", func(t *testing.T) {
		staticBoolArrT, err := TypeOf("bool[5]")
		require.NoError(t, err, "make static bool array type failure")
		expected := []interface{}{true, false, false, true, true}
		actual, err := staticBoolArrT.Decode([]byte{0b10011000})
		require.NoError(t, err, "decoding static bool array should not return error")
		require.Equal(t, expected, actual, "static bool array decode do not match expected")
	})

	// decoding test for static bool array
	// expected value: bool[11]: F, F, F, T, T, F, T, F, T, F, T
	// input: 0b00011010, 0b10100000
	t.Run("static bool array decode", func(t *testing.T) {
		staticBoolArrT, err := TypeOf("bool[11]")
		require.NoError(t, err, "make static bool array type failure")
		expected := []interface{}{false, false, false, true, true, false, true, false, true, false, true}
		actual, err := staticBoolArrT.Decode([]byte{0b00011010, 0b10100000})
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
		staticUintArrT, err := TypeOf("uint64[8]")
		require.NoError(t, err, "make static uint array type failure")
		expected := []interface{}{
			uint64(1), uint64(2),
			uint64(3), uint64(4),
			uint64(5), uint64(6),
			uint64(7), uint64(8),
		}
		arrayEncoded, err := staticUintArrT.Encode(expected)
		require.NoError(t, err, "uint64 static array encode should not return error")
		actual, err := staticUintArrT.Decode(arrayEncoded)
		require.NoError(t, err, "uint64 static array decode should not return error")
		require.Equal(t, expected, actual, "uint64 static array decode do not match with expected value")
	})

	// decoding test for dynamic bool array
	// expected value: bool[]: {F, T, F, T, F, T, F, T, F, T}
	/*
	   input bytes: 0x00, 0x0A                (dynamic bool array length 10)
	                0b01010101, 0b01000000    (dynamic bool array encoding)
	*/
	t.Run("dynamic bool array decode", func(t *testing.T) {
		dynamicBoolArrT, err := TypeOf("bool[]")
		require.NoError(t, err, "make dynamic bool array type failure")
		expected := []interface{}{false, true, false, true, false, true, false, true, false, true}
		inputEncoded := []byte{
			0x00, 0x0A, 0b01010101, 0b01000000,
		}
		actual, err := dynamicBoolArrT.Decode(inputEncoded)
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
		tupleT, err := TypeOf("(string,bool,bool,bool,bool,string)")
		require.NoError(t, err, "make tuple type failure")
		inputEncode := []byte{
			0x00, 0x05, 0b10100000, 0x00, 0x0A,
			0x00, 0x03, byte('A'), byte('B'), byte('C'),
			0x00, 0x03, byte('D'), byte('E'), byte('F'),
		}
		expected := []interface{}{
			"ABC", true, false, true, false, "DEF",
		}
		actual, err := tupleT.Decode(inputEncode)
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
		tupleT, err := TypeOf("(bool[2],bool[2])")
		require.NoError(t, err, "make tuple type failure")
		expected := []interface{}{
			[]interface{}{true, true},
			[]interface{}{true, true},
		}
		encodedInput := []byte{
			0b11000000,
			0b11000000,
		}
		actual, err := tupleT.Decode(encodedInput)
		require.NoError(t, err, "decode tuple value should not return error")
		require.Equal(t, expected, actual, "decoded tuple value do not match with expected")
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
		tupleT, err := TypeOf("(bool[2],bool[])")
		require.NoError(t, err, "make tuple type failure")
		expected := []interface{}{
			[]interface{}{true, true},
			[]interface{}{true, true},
		}
		encodedInput := []byte{
			0b11000000,
			0x00, 0x03,
			0x00, 0x02, 0b11000000,
		}
		actual, err := tupleT.Decode(encodedInput)
		require.NoError(t, err, "decode tuple for static/dynamic bool array should not return error")
		require.Equal(t, expected, actual, "decoded tuple value do not match with expected")
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
		tupleT, err := TypeOf("(bool[],bool[])")
		require.NoError(t, err, "make tuple type failure")
		expected := []interface{}{
			[]interface{}{}, []interface{}{},
		}
		encodedInput := []byte{
			0x00, 0x04, 0x00, 0x06,
			0x00, 0x00, 0x00, 0x00,
		}
		actual, err := tupleT.Decode(encodedInput)
		require.NoError(t, err, "decode tuple for empty dynamic array should not return error")
		require.Equal(t, expected, actual, "decoded tuple value do not match with expected")
	})

	// decoding test for empty tuple
	// expected value: ()
	// byte input: ""
	t.Run("empty tuple decoding", func(t *testing.T) {
		tupleT, err := TypeOf("()")
		require.NoError(t, err, "make empty tuple type should not return error")
		actual, err := tupleT.Decode([]byte{})
		require.NoError(t, err, "decode empty tuple should not return error")
		require.Equal(t, []interface{}{}, actual, "empty tuple encode should not return error")
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
		arrayType := makeStaticArrayType(boolType, 9)
		_, err := arrayType.Decode(inputBase)
		require.Error(t, err, "decoding corrupted static bool array should return error")
	})

	// decoding test for *corrupted* static bool array
	// expected 8 elements for static bool array
	// encoded bytes have 1 byte more (0b00000000)
	// should throw error
	t.Run("corrupted static bool array decode", func(t *testing.T) {
		inputBase := []byte{0b01001011, 0b00000000}
		arrayType := makeStaticArrayType(boolType, 8)
		_, err := arrayType.Decode(inputBase)
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
		uintTArray, err := TypeOf("uint64[8]")
		require.NoError(t, err, "make uint64 static array type should not return error")
		_, err = uintTArray.Decode(inputBase)
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
		uintTArray, err := TypeOf("uint64[7]")
		require.NoError(t, err, "make uint64 static array type should not return error")
		_, err = uintTArray.Decode(inputBase)
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
		dynamicT := makeDynamicArrayType(boolType)
		_, err := dynamicT.Decode(inputBase)
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
		dynamicT := makeDynamicArrayType(boolType)
		_, err := dynamicT.Decode(inputBase)
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
		tupleT, err := TypeOf("(string,bool,bool,bool,bool,string)")
		require.NoError(t, err, "make tuple type failure")
		_, err = tupleT.Decode(inputEncode)
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
		expectedType, err := TypeOf("(bool[2],bool[2])")
		require.NoError(t, err, "make tuple type failure")
		encodedInput0 := []byte{
			0b11000000,
			0b11000000,
			0b00000000,
		}
		_, err = expectedType.Decode(encodedInput0)
		require.Error(t, err, "decode corrupted tuple value should return error")

		encodedInput1 := []byte{
			0b11000000,
		}
		_, err = expectedType.Decode(encodedInput1)
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
		tupleT, err := TypeOf("(bool[2],bool[])")
		require.NoError(t, err, "make tuple type failure")
		_, err = tupleT.Decode(encodedInput)
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
		tupleT, err := TypeOf("(bool[],bool[])")
		require.NoError(t, err, "make tuple type failure")
		_, err = tupleT.Decode(encodedInput)
		require.Error(t, err, "decode corrupted tuple for empty dynamic array should return error")
	})

	// decoding test for *corrupted* empty tuple
	// expected value: ()
	// corrupted input: 0xFF, should be empty byte
	// should return error
	t.Run("corrupted empty tuple decoding", func(t *testing.T) {
		encodedInput := []byte{0xFF}
		tupleT, err := TypeOf("()")
		require.NoError(t, err, "make tuple type failure")
		_, err = tupleT.Decode(encodedInput)
		require.Error(t, err, "decode corrupted empty tuple should return error")
	})
}

type testUnit struct {
	serializedType string
	value          interface{}
}

func categorySelfRoundTripTest(t *testing.T, category []testUnit) {
	for _, testObj := range category {
		abiType, err := TypeOf(testObj.serializedType)
		require.NoError(t, err, "failure to deserialize type")
		encodedValue, err := abiType.Encode(testObj.value)
		require.NoError(t, err, "failure to encode value")
		actual, err := abiType.Decode(encodedValue)
		require.NoError(t, err, "failure to decode value")
		require.Equal(t, testObj.value, actual, "decoded value not equal to expected")
		jsonEncodedValue, err := abiType.MarshalToJSON(testObj.value)
		require.NoError(t, err, "failure to encode value to JSON type")
		jsonActual, err := abiType.UnmarshalFromJSON(jsonEncodedValue)
		require.NoError(t, err, "failure to decode JSON value back")
		require.Equal(t, testObj.value, jsonActual, "decode JSON value not equal to expected")
	}
}

func addPrimitiveRandomValues(t *testing.T, pool *map[BaseType][]testUnit) {
	(*pool)[Uint] = make([]testUnit, 200*64)
	(*pool)[Ufixed] = make([]testUnit, 160*64)

	uintIndex := 0
	ufixedIndex := 0

	for bitSize := 8; bitSize <= 512; bitSize += 8 {
		max := new(big.Int).Lsh(big.NewInt(1), uint(bitSize))

		uintT, err := makeUintType(bitSize)
		require.NoError(t, err, "make uint type failure")
		uintTstr := uintT.String()

		for j := 0; j < 200; j++ {
			randVal, err := rand.Int(rand.Reader, max)
			require.NoError(t, err, "generate random uint, should be no error")

			narrowest, err := castBigIntToNearestPrimitive(randVal, uint16(bitSize))
			require.NoError(t, err, "cast random uint to nearest primitive failure")

			(*pool)[Uint][uintIndex] = testUnit{serializedType: uintTstr, value: narrowest}
			uintIndex++
		}

		for precision := 1; precision <= 160; precision++ {
			randVal, err := rand.Int(rand.Reader, max)
			require.NoError(t, err, "generate random ufixed, should be no error")

			narrowest, err := castBigIntToNearestPrimitive(randVal, uint16(bitSize))
			require.NoError(t, err, "cast random uint to nearest primitive failure")

			ufixedT, err := makeUfixedType(bitSize, precision)
			require.NoError(t, err, "make ufixed type failure")
			ufixedTstr := ufixedT.String()
			(*pool)[Ufixed][ufixedIndex] = testUnit{serializedType: ufixedTstr, value: narrowest}
			ufixedIndex++
		}
	}
	categorySelfRoundTripTest(t, (*pool)[Uint])
	categorySelfRoundTripTest(t, (*pool)[Ufixed])

	(*pool)[Byte] = make([]testUnit, 1<<8)
	for i := 0; i < (1 << 8); i++ {
		(*pool)[Byte][i] = testUnit{serializedType: byteType.String(), value: byte(i)}
	}
	categorySelfRoundTripTest(t, (*pool)[Byte])

	(*pool)[Bool] = make([]testUnit, 2)
	(*pool)[Bool][0] = testUnit{serializedType: boolType.String(), value: false}
	(*pool)[Bool][1] = testUnit{serializedType: boolType.String(), value: true}
	categorySelfRoundTripTest(t, (*pool)[Bool])

	maxAddress := new(big.Int).Lsh(big.NewInt(1), 256)
	(*pool)[Address] = make([]testUnit, 300)
	for i := 0; i < 300; i++ {
		randAddrVal, err := rand.Int(rand.Reader, maxAddress)
		require.NoError(t, err, "generate random value for address, should be no error")
		addrBytes := randAddrVal.Bytes()
		remainBytes := make([]byte, 32-len(addrBytes))
		addrBytes = append(remainBytes, addrBytes...)
		(*pool)[Address][i] = testUnit{serializedType: addressType.String(), value: addrBytes}
	}
	categorySelfRoundTripTest(t, (*pool)[Address])

	(*pool)[String] = make([]testUnit, 400)
	stringIndex := 0
	for length := 1; length <= 100; length++ {
		for i := 0; i < 4; i++ {
			(*pool)[String][stringIndex] = testUnit{
				serializedType: stringType.String(),
				value:          gobberish.GenerateString(length),
			}
			stringIndex++
		}
	}
	categorySelfRoundTripTest(t, (*pool)[String])
}

func takeSomeFromCategoryAndGenerateArray(
	t *testing.T, abiT BaseType, srtIndex int, takeNum uint16, pool *map[BaseType][]testUnit) {

	tempArray := make([]interface{}, takeNum)
	for i := 0; i < int(takeNum); i++ {
		index := srtIndex + i
		if index >= len((*pool)[abiT]) {
			index = srtIndex
		}
		tempArray[i] = (*pool)[abiT][index].value
	}
	tempT, err := TypeOf((*pool)[abiT][srtIndex].serializedType)
	require.NoError(t, err, "type in test uint cannot be deserialized")
	(*pool)[ArrayStatic] = append((*pool)[ArrayStatic], testUnit{
		serializedType: makeStaticArrayType(tempT, takeNum).String(),
		value:          tempArray,
	})
	(*pool)[ArrayDynamic] = append((*pool)[ArrayDynamic], testUnit{
		serializedType: makeDynamicArrayType(tempT).String(),
		value:          tempArray,
	})
}

func addArrayRandomValues(t *testing.T, pool *map[BaseType][]testUnit) {
	for intIndex := 0; intIndex < len((*pool)[Uint]); intIndex += 200 {
		takeSomeFromCategoryAndGenerateArray(t, Uint, intIndex, 20, pool)
	}
	takeSomeFromCategoryAndGenerateArray(t, Byte, 0, 20, pool)
	takeSomeFromCategoryAndGenerateArray(t, Address, 0, 20, pool)
	takeSomeFromCategoryAndGenerateArray(t, String, 0, 20, pool)
	takeSomeFromCategoryAndGenerateArray(t, Bool, 0, 20, pool)

	categorySelfRoundTripTest(t, (*pool)[ArrayStatic])
	categorySelfRoundTripTest(t, (*pool)[ArrayDynamic])
}

func addTupleRandomValues(t *testing.T, slotRange BaseType, pool *map[BaseType][]testUnit) {
	for i := 0; i < 100; i++ {
		tupleLenBig, err := rand.Int(rand.Reader, big.NewInt(20))
		require.NoError(t, err, "generate random tuple length should not return error")
		tupleLen := tupleLenBig.Int64() + 1
		testUnits := make([]testUnit, tupleLen)
		for index := 0; index < int(tupleLen); index++ {
			tupleTypeIndexBig, err := rand.Int(rand.Reader, big.NewInt(int64(slotRange)+1))
			require.NoError(t, err, "generate random tuple element type index should not return error")
			tupleTypeIndex := BaseType(tupleTypeIndexBig.Int64())
			tupleElemChoiceRange := len((*pool)[tupleTypeIndex])

			tupleElemRangeIndexBig, err := rand.Int(rand.Reader, big.NewInt(int64(tupleElemChoiceRange)))
			require.NoError(t, err, "generate random tuple element index in test pool should not return error")
			tupleElemRangeIndex := tupleElemRangeIndexBig.Int64()
			tupleElem := (*pool)[tupleTypeIndex][tupleElemRangeIndex]
			testUnits[index] = tupleElem
		}
		elemValues := make([]interface{}, tupleLen)
		elemTypes := make([]Type, tupleLen)
		for index := 0; index < int(tupleLen); index++ {
			elemValues[index] = testUnits[index].value
			abiT, err := TypeOf(testUnits[index].serializedType)
			require.NoError(t, err, "deserialize type failure for tuple elements")
			elemTypes[index] = abiT
		}
		tupleT, err := MakeTupleType(elemTypes)
		require.NoError(t, err, "make tuple type failure")
		(*pool)[Tuple] = append((*pool)[Tuple], testUnit{
			serializedType: tupleT.String(),
			value:          elemValues,
		})
	}
}

func TestRandomABIEncodeDecodeRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)
	testValuePool := make(map[BaseType][]testUnit)
	addPrimitiveRandomValues(t, &testValuePool)
	addArrayRandomValues(t, &testValuePool)
	addTupleRandomValues(t, String, &testValuePool)
	addTupleRandomValues(t, Tuple, &testValuePool)
	categorySelfRoundTripTest(t, testValuePool[Tuple])
}

func TestParseMethodSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	tests := []struct {
		signature  string
		name       string
		argTypes   []string
		returnType string
	}{
		{
			signature:  "add(uint8,uint16,pay,account,txn)uint32",
			name:       "add",
			argTypes:   []string{"uint8", "uint16", "pay", "account", "txn"},
			returnType: "uint32",
		},
		{
			signature:  "nothing()void",
			name:       "nothing",
			argTypes:   []string{},
			returnType: "void",
		},
		{
			signature:  "tupleArgs((uint8,uint128),account,(string,(bool,bool)))bool",
			name:       "tupleArgs",
			argTypes:   []string{"(uint8,uint128)", "account", "(string,(bool,bool))"},
			returnType: "bool",
		},
		{
			signature:  "tupleReturn(uint64)(bool,bool,bool)",
			name:       "tupleReturn",
			argTypes:   []string{"uint64"},
			returnType: "(bool,bool,bool)",
		},
		{
			signature:  "tupleArgsAndReturn((uint8,uint128),account,(string,(bool,bool)))(bool,bool,bool)",
			name:       "tupleArgsAndReturn",
			argTypes:   []string{"(uint8,uint128)", "account", "(string,(bool,bool))"},
			returnType: "(bool,bool,bool)",
		},
	}

	for _, test := range tests {
		t.Run(test.signature, func(t *testing.T) {
			name, argTypes, returnType, err := ParseMethodSignature(test.signature)
			require.NoError(t, err)
			require.Equal(t, test.name, name)
			require.Equal(t, test.argTypes, argTypes)
			require.Equal(t, test.returnType, returnType)
		})
	}
}
