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
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestMakeTypeValid(t *testing.T) {
	partitiontest.PartitionTest(t)
	// uint
	for i := 8; i <= 512; i += 8 {
		uintType, err := MakeUintType(uint16(i))
		require.NoError(t, err, "make uint type in valid space should not return error")
		expected := "uint" + strconv.Itoa(i)
		actual := uintType.String()
		require.Equal(t, expected, actual, "MakeUintType: expected %s, actual %s", expected, actual)
	}
	// ufixed
	for i := 8; i <= 512; i += 8 {
		for j := 1; j <= 160; j++ {
			ufixedType, err := MakeUfixedType(uint16(i), uint16(j))
			require.NoError(t, err, "make ufixed type in valid space should not return error")
			expected := "ufixed" + strconv.Itoa(i) + "x" + strconv.Itoa(j)
			actual := ufixedType.String()
			require.Equal(t, expected, actual,
				"TypeFromString ufixed error: expected %s, actual %s", expected, actual)
		}
	}
	// bool/strings/address/byte + dynamic/static array + tuple
	var testcases = []struct {
		input    Type
		testType string
		expected string
	}{
		{input: MakeBoolType(), testType: "bool", expected: "bool"},
		{input: MakeStringType(), testType: "string", expected: "string"},
		{input: MakeAddressType(), testType: "address", expected: "address"},
		{input: MakeByteType(), testType: "byte", expected: "byte"},
		// dynamic array
		{
			input: MakeDynamicArrayType(
				Type{
					abiTypeID: Uint,
					bitSize:   uint16(32),
				},
			),
			testType: "dynamic array",
			expected: "uint32[]",
		},
		{
			input: MakeDynamicArrayType(
				MakeDynamicArrayType(
					MakeByteType(),
				),
			),
			testType: "dynamic array",
			expected: "byte[][]",
		},
		{
			input: MakeStaticArrayType(
				Type{
					abiTypeID: Ufixed,
					bitSize:   uint16(128),
					precision: uint16(10),
				},
				uint16(100),
			),
			testType: "static array",
			expected: "ufixed128x10[100]",
		},
		{
			input: MakeStaticArrayType(
				MakeStaticArrayType(
					MakeBoolType(),
					uint16(128),
				),
				uint16(256),
			),
			testType: "static array",
			expected: "bool[128][256]",
		},
		// tuple type
		{
			input: Type{
				abiTypeID: Tuple,
				childTypes: []Type{
					{
						abiTypeID: Uint,
						bitSize:   uint16(32),
					},
					{
						abiTypeID: Tuple,
						childTypes: []Type{
							MakeAddressType(),
							MakeByteType(),
							MakeStaticArrayType(MakeBoolType(), uint16(10)),
							MakeDynamicArrayType(
								Type{
									abiTypeID: Ufixed,
									bitSize:   uint16(256),
									precision: uint16(10),
								},
							),
						},
						staticLength: 4,
					},
					MakeDynamicArrayType(MakeByteType()),
				},
				staticLength: 3,
			},
			testType: "tuple type",
			expected: "(uint32,(address,byte,bool[10],ufixed256x10[]),byte[])",
		},
	}
	for _, testcase := range testcases {
		t.Run(fmt.Sprintf("MakeType test %s", testcase.testType), func(t *testing.T) {
			actual := testcase.input.String()
			require.Equal(t, testcase.expected, actual,
				"MakeType: expected %s, actual %s", testcase.expected, actual)
		})
	}
}

func TestMakeTypeInvalid(t *testing.T) {
	partitiontest.PartitionTest(t)
	// uint
	for i := 0; i <= 1000; i++ {
		randInput := rand.Uint32() % (1 << 16)
		for randInput%8 == 0 && randInput <= 512 && randInput >= 8 {
			randInput = rand.Uint32() % (1 << 16)
		}
		// note: if a var mod 8 = 0 (or not) in uint32, then it should mod 8 = 0 (or not) in uint16.
		_, err := MakeUintType(uint16(randInput))
		require.Error(t, err, "MakeUintType: should throw error on bitSize input %d", uint16(randInput))
	}
	// ufixed
	for i := 0; i <= 10000; i++ {
		randSize := rand.Uint64() % (1 << 16)
		for randSize%8 == 0 && randSize <= 512 && randSize >= 8 {
			randSize = rand.Uint64() % (1 << 16)
		}
		randPrecision := rand.Uint32()
		for randPrecision >= 1 && randPrecision <= 160 {
			randPrecision = rand.Uint32()
		}
		_, err := MakeUfixedType(uint16(randSize), uint16(randPrecision))
		require.Error(t, err, "MakeUfixedType: should throw error on bitSize %d, precision %d", randSize, randPrecision)
	}
}

func TestTypeFromStringValid(t *testing.T) {
	partitiontest.PartitionTest(t)
	// uint
	for i := 8; i <= 512; i += 8 {
		expected, err := MakeUintType(uint16(i))
		require.NoError(t, err, "make uint type in valid space should not return error")
		actual, err := TypeFromString(expected.String())
		require.NoError(t, err, "TypeFromString: uint parsing error: %s", expected.String())
		require.Equal(t, expected, actual,
			"TypeFromString: expected %s, actual %s", expected.String(), actual.String())
	}
	// ufixed
	for i := 8; i <= 512; i += 8 {
		for j := 1; j <= 160; j++ {
			expected, err := MakeUfixedType(uint16(i), uint16(j))
			require.NoError(t, err, "make ufixed type in valid space should not return error")
			actual, err := TypeFromString("ufixed" + strconv.Itoa(i) + "x" + strconv.Itoa(j))
			require.NoError(t, err, "TypeFromString ufixed parsing error: %s", expected.String())
			require.Equal(t, expected, actual,
				"TypeFromString ufixed: expected %s, actual %s", expected.String(), actual.String())
		}
	}
	var testcases = []struct {
		input    string
		testType string
		expected Type
	}{
		{input: MakeBoolType().String(), testType: "bool", expected: MakeBoolType()},
		{input: MakeStringType().String(), testType: "string", expected: MakeStringType()},
		{input: MakeAddressType().String(), testType: "address", expected: MakeAddressType()},
		{input: MakeByteType().String(), testType: "byte", expected: MakeByteType()},
		{
			input:    "uint256[]",
			testType: "dynamic array",
			expected: MakeDynamicArrayType(Type{abiTypeID: Uint, bitSize: 256}),
		},
		{
			input:    "ufixed256x64[]",
			testType: "dynamic array",
			expected: MakeDynamicArrayType(
				Type{
					abiTypeID: Ufixed,
					bitSize:   256,
					precision: 64,
				},
			),
		},
		{
			input:    "byte[][][][]",
			testType: "dynamic array",
			expected: MakeDynamicArrayType(
				MakeDynamicArrayType(
					MakeDynamicArrayType(
						MakeDynamicArrayType(
							MakeByteType(),
						),
					),
				),
			),
		},
		// static array
		{
			input:    "address[100]",
			testType: "static array",
			expected: MakeStaticArrayType(
				MakeAddressType(),
				uint16(100),
			),
		},
		{
			input:    "uint64[][200]",
			testType: "static array",
			expected: MakeStaticArrayType(
				MakeDynamicArrayType(
					Type{abiTypeID: Uint, bitSize: uint16(64)},
				),
				uint16(200),
			),
		},
		// tuple type
		{
			input:    "()",
			testType: "tuple type",
			expected: Type{
				abiTypeID:    Tuple,
				childTypes:   []Type{},
				staticLength: 0,
			},
		},
		{
			input:    "(uint32,(address,byte,bool[10],ufixed256x10[]),byte[])",
			testType: "tuple type",
			expected: Type{
				abiTypeID: Tuple,
				childTypes: []Type{
					{
						abiTypeID: Uint,
						bitSize:   uint16(32),
					},
					{
						abiTypeID: Tuple,
						childTypes: []Type{
							MakeAddressType(),
							MakeByteType(),
							MakeStaticArrayType(MakeBoolType(), uint16(10)),
							MakeDynamicArrayType(
								Type{
									abiTypeID: Ufixed,
									bitSize:   uint16(256),
									precision: uint16(10),
								},
							),
						},
						staticLength: 4,
					},
					MakeDynamicArrayType(MakeByteType()),
				},
				staticLength: 3,
			},
		},
		{
			input:    "(uint32,(address,byte,bool[10],(ufixed256x10[])))",
			testType: "tuple type",
			expected: Type{
				abiTypeID: Tuple,
				childTypes: []Type{
					{
						abiTypeID: Uint,
						bitSize:   uint16(32),
					},
					{
						abiTypeID: Tuple,
						childTypes: []Type{
							MakeAddressType(),
							MakeByteType(),
							MakeStaticArrayType(MakeBoolType(), uint16(10)),
							{
								abiTypeID: Tuple,
								childTypes: []Type{
									MakeDynamicArrayType(
										Type{
											abiTypeID: Ufixed,
											bitSize:   uint16(256),
											precision: uint16(10),
										},
									),
								},
								staticLength: 1,
							},
						},
						staticLength: 4,
					},
				},
				staticLength: 2,
			},
		},
		{
			input:    "((uint32),(address,(byte,bool[10],ufixed256x10[])))",
			testType: "tuple type",
			expected: Type{
				abiTypeID: Tuple,
				childTypes: []Type{
					{
						abiTypeID: Tuple,
						childTypes: []Type{
							{
								abiTypeID: Uint,
								bitSize:   uint16(32),
							},
						},
						staticLength: 1,
					},
					{
						abiTypeID: Tuple,
						childTypes: []Type{
							MakeAddressType(),
							{
								abiTypeID: Tuple,
								childTypes: []Type{
									MakeByteType(),
									MakeStaticArrayType(MakeBoolType(), uint16(10)),
									MakeDynamicArrayType(
										Type{
											abiTypeID: Ufixed,
											bitSize:   uint16(256),
											precision: uint16(10),
										},
									),
								},
								staticLength: 3,
							},
						},
						staticLength: 2,
					},
				},
				staticLength: 2,
			},
		},
	}
	for _, testcase := range testcases {
		t.Run(fmt.Sprintf("TypeFromString test %s", testcase.testType), func(t *testing.T) {
			actual, err := TypeFromString(testcase.input)
			require.NoError(t, err, "TypeFromString %s parsing error", testcase.testType)
			require.Equal(t, testcase.expected, actual, "TestFromString %s: expected %s, actual %s",
				testcase.testType, testcase.expected.String(), actual.String())
		})
	}
}

func TestTypeFromStringInvalid(t *testing.T) {
	partitiontest.PartitionTest(t)
	for i := 0; i <= 1000; i++ {
		randSize := rand.Uint64()
		for randSize%8 == 0 && randSize <= 512 && randSize >= 8 {
			randSize = rand.Uint64()
		}
		errorInput := "uint" + strconv.FormatUint(randSize, 10)
		_, err := TypeFromString(errorInput)
		require.Error(t, err, "MakeUintType: should throw error on bitSize input %d", randSize)
	}
	for i := 0; i <= 10000; i++ {
		randSize := rand.Uint64()
		for randSize%8 == 0 && randSize <= 512 && randSize >= 8 {
			randSize = rand.Uint64()
		}
		randPrecision := rand.Uint64()
		for randPrecision >= 1 && randPrecision <= 160 {
			randPrecision = rand.Uint64()
		}
		errorInput := "ufixed" + strconv.FormatUint(randSize, 10) + "x" + strconv.FormatUint(randPrecision, 10)
		_, err := TypeFromString(errorInput)
		require.Error(t, err, "MakeUintType: should throw error on bitSize input %d", randSize)
	}
	var testcases = []string{
		// uint
		"uint123x345",
		"uint 128",
		"uint8 ",
		"uint!8",
		"uint[32]",
		"uint-893",
		"uint#120\\",
		// ufixed
		"ufixed000000000016x0000010",
		"ufixed123x345",
		"ufixed 128 x 100",
		"ufixed64x10 ",
		"ufixed!8x2 ",
		"ufixed[32]x16",
		"ufixed-64x+100",
		"ufixed16x+12",
		// dynamic array
		"uint256 []",
		"byte[] ",
		"[][][]",
		"stuff[]",
		// static array
		"ufixed32x10[0]",
		"byte[10 ]",
		"uint64[0x21]",
		// tuple
		"(ufixed128x10))",
		"(,uint128,byte[])",
		"(address,ufixed64x5,)",
		"(byte[16],somethingwrong)",
		"(                )",
		"((uint32)",
		"(byte,,byte)",
		"((byte),,(byte))",
	}
	for _, testcase := range testcases {
		t.Run(fmt.Sprintf("TypeFromString dynamic array test %s", testcase), func(t *testing.T) {
			_, err := TypeFromString(testcase)
			require.Error(t, err, "%s should throw error", testcase)
		})
	}
}

func generateTupleType(baseTypes []Type, tupleTypes []Type) Type {
	if len(baseTypes) == 0 && len(tupleTypes) == 0 {
		panic("should not pass all nil arrays into generateTupleType")
	}
	tupleLen := 0
	for tupleLen == 0 {
		tupleLen = rand.Intn(20)
	}
	resultTypes := make([]Type, tupleLen)
	for i := 0; i < tupleLen; i++ {
		baseOrTuple := rand.Intn(5)
		if baseOrTuple == 1 && len(tupleTypes) > 0 {
			resultTypes[i] = tupleTypes[rand.Intn(len(tupleTypes))]
		} else {
			resultTypes[i] = baseTypes[rand.Intn(len(baseTypes))]
		}
	}
	return Type{abiTypeID: Tuple, childTypes: resultTypes, staticLength: uint16(tupleLen)}
}

func TestTypeMISC(t *testing.T) {
	partitiontest.PartitionTest(t)
	rand.Seed(time.Now().Unix())

	var testpool = []Type{
		MakeBoolType(),
		MakeAddressType(),
		MakeStringType(),
		MakeByteType(),
	}
	for i := 8; i <= 512; i += 8 {
		uintT, err := MakeUintType(uint16(i))
		require.NoError(t, err, "make uint type error")
		testpool = append(testpool, uintT)
	}
	for i := 8; i <= 512; i += 8 {
		for j := 1; j <= 160; j++ {
			ufixedT, err := MakeUfixedType(uint16(i), uint16(j))
			require.NoError(t, err, "make ufixed type error: bitSize %d, precision %d", i, j)
			testpool = append(testpool, ufixedT)
		}
	}
	for _, testcase := range testpool {
		testpool = append(testpool, MakeDynamicArrayType(testcase))
		testpool = append(testpool, MakeStaticArrayType(testcase, 10))
		testpool = append(testpool, MakeStaticArrayType(testcase, 20))
	}

	for _, testcase := range testpool {
		require.True(t, testcase.Equal(testcase), "test type self equal error")
	}
	baseTestCount := 0
	for baseTestCount < 1000 {
		index0 := rand.Intn(len(testpool))
		index1 := rand.Intn(len(testpool))
		if index0 == index1 {
			continue
		}
		require.False(t, testpool[index0].Equal(testpool[index1]),
			"test type not equal error\n%s\n%s",
			testpool[index0].String(), testpool[index1].String())
		baseTestCount++
	}

	testpoolTuple := make([]Type, 0)
	for i := 0; i < 100; i++ {
		testpoolTuple = append(testpoolTuple, generateTupleType(testpool, testpoolTuple))
	}
	for _, testcaseTuple := range testpoolTuple {
		require.True(t, testcaseTuple.Equal(testcaseTuple), "test type tuple equal error")
	}

	tupleTestCount := 0
	for tupleTestCount < 100 {
		index0 := rand.Intn(len(testpoolTuple))
		index1 := rand.Intn(len(testpoolTuple))
		if testpoolTuple[index0].String() == testpoolTuple[index1].String() {
			continue
		}
		require.False(t, testpoolTuple[index0].Equal(testpoolTuple[index1]),
			"test type tuple not equal error\n%s\n%s",
			testpoolTuple[index0].String(), testpoolTuple[index1].String())
		tupleTestCount++
	}

	testpool = append(testpool, testpoolTuple...)
	isDynamicCount := 0
	for isDynamicCount < 100 {
		index := rand.Intn(len(testpool))
		isDynamicArr := strings.Contains(testpool[index].String(), "[]")
		isDynamicStr := strings.Contains(testpool[index].String(), "string")
		require.Equal(t, isDynamicArr || isDynamicStr, testpool[index].IsDynamic(),
			"test type isDynamic error\n%s", testpool[index].String())
		isDynamicCount++
	}

	addressByteLen, err := MakeAddressType().ByteLen()
	require.NoError(t, err, "address type bytelen should not return error")
	require.Equal(t, 32, addressByteLen, "address type bytelen should be 32")
	byteByteLen, err := MakeByteType().ByteLen()
	require.NoError(t, err, "byte type bytelen should not return error")
	require.Equal(t, 1, byteByteLen, "byte type bytelen should be 1")
	boolByteLen, err := MakeBoolType().ByteLen()
	require.NoError(t, err, "bool type bytelen should be 1")
	require.Equal(t, 1, boolByteLen, "bool type bytelen should be 1")

	byteLenTestCount := 0
	for byteLenTestCount < 100 {
		index := rand.Intn(len(testpool))
		testType := testpool[index]
		byteLen, err := testType.ByteLen()
		if testType.IsDynamic() {
			require.Error(t, err, "byteLen test error on %s dynamic type, should have error",
				testType.String())
		} else {
			require.NoError(t, err, "byteLen test error on %s dynamic type, should not have error")
			if testType.abiTypeID == Tuple {
				sizeSum := 0
				for i := 0; i < len(testType.childTypes); i++ {
					if testType.childTypes[i].abiTypeID == Bool {
						// search previous bool
						before := findBoolLR(testType.childTypes, i, -1)
						// search after bool
						after := findBoolLR(testType.childTypes, i, 1)
						// append to heads and tails
						require.True(t, before%8 == 0, "expected tuple bool compact by 8")
						if after > 7 {
							after = 7
						}
						i += after
						sizeSum++
					} else {
						childByteSize, err := testType.childTypes[i].ByteLen()
						require.NoError(t, err, "byteLen not expected to fail on tuple child type")
						sizeSum += childByteSize
					}
				}

				require.Equal(t, sizeSum, byteLen,
					"%s do not match calculated byte length %d", testType.String(), sizeSum)
			} else if testType.abiTypeID == ArrayStatic {
				if testType.childTypes[0].abiTypeID == Bool {
					expected := testType.staticLength / 8
					if testType.staticLength%8 != 0 {
						expected++
					}
					actual, err := testType.ByteLen()
					require.NoError(t, err, "%s should not return error on byteLen test")
					require.Equal(t, int(expected), actual, "%s do not match calculated byte length %d",
						testType.String(), expected)
				} else {
					childSize, err := testType.childTypes[0].ByteLen()
					require.NoError(t, err, "%s should not return error on byteLen test", testType.childTypes[0].String())
					expected := childSize * int(testType.staticLength)
					require.Equal(t, expected, byteLen,
						"%s do not match calculated byte length %d", testType.String(), expected)
				}
			}
		}
		byteLenTestCount++
	}
}
