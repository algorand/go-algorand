package abi

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TODO need a fuzz test for the parsing

func TestMakeTypeValid(t *testing.T) {
	// uint
	for i := 8; i <= 512; i += 8 {
		uintType, _ := MakeUintType(uint16(i))
		expected := "uint" + strconv.Itoa(i)
		actual := uintType.String()
		require.Equal(t, expected, actual, "MakeUintType: expected %s, actual %s", expected, actual)
	}
	// ufixed
	for i := 8; i <= 512; i += 8 {
		for j := 1; j <= 160; j++ {
			ufixedType, _ := MakeUFixedType(uint16(i), uint16(j))
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
					typeFromEnum: Uint,
					typeSize:     uint16(32),
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
					typeFromEnum:  Ufixed,
					typeSize:      uint16(128),
					typePrecision: uint16(10),
				},
				uint16(100),
			),
			testType: "dynamic array",
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
			testType: "dynamic array",
			expected: "bool[128][256]",
		},
		// tuple type
		{
			input: MakeTupleType(
				[]Type{
					{
						typeFromEnum: Uint,
						typeSize:     uint16(32),
					},
					MakeTupleType(
						[]Type{
							MakeAddressType(),
							MakeByteType(),
							MakeStaticArrayType(MakeBoolType(), uint16(10)),
							MakeDynamicArrayType(
								Type{
									typeFromEnum:  Ufixed,
									typeSize:      uint16(256),
									typePrecision: uint16(10),
								},
							),
						},
					),
					MakeDynamicArrayType(MakeByteType()),
				},
			),
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
	// uint
	for i := 0; i <= 1000; i++ {
		randInput := rand.Uint32()
		for randInput%8 == 0 && randInput <= 512 && randInput >= 8 {
			randInput = rand.Uint32()
		}
		// note: if a var mod 8 = 0 (or not) in uint32, then it should mod 8 = 0 (or not) in uint16.
		_, err := MakeUintType(uint16(randInput))
		require.Error(t, err, "MakeUintType: should throw error on size input %d", randInput)
	}
	// ufixed
	for i := 0; i <= 10000; i++ {
		randSize := rand.Uint64()
		for randSize%8 == 0 && randSize <= 512 && randSize >= 8 {
			randSize = rand.Uint64()
		}
		randPrecision := rand.Uint32()
		for randPrecision >= 1 && randPrecision <= 160 {
			randPrecision = rand.Uint32()
		}
		_, err := MakeUFixedType(uint16(randSize), uint16(randPrecision))
		require.Error(t, err, "MakeUintType: should throw error on size input %d", randSize)
	}
}

func TestTypeFromStringValid(t *testing.T) {
	// uint
	for i := 8; i <= 512; i += 8 {
		expected, _ := MakeUintType(uint16(i))
		actual, err := TypeFromString(expected.String())
		require.Equal(t, nil, err, "TypeFromString: uint parsing error: %s", expected.String())
		require.Equal(t, expected, actual,
			"TypeFromString: expected %s, actual %s", expected.String(), actual.String())
	}
	// ufixed
	for i := 8; i <= 512; i += 8 {
		for j := 1; j <= 160; j++ {
			expected, _ := MakeUFixedType(uint16(i), uint16(j))
			actual, err := TypeFromString("ufixed" + strconv.Itoa(i) + "x" + strconv.Itoa(j))
			require.Equal(t, nil, err, "TypeFromString ufixed parsing error: %s", expected.String())
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
			expected: MakeDynamicArrayType(Type{typeFromEnum: Uint, typeSize: 256}),
		},
		{
			input:    "ufixed256x64[]",
			testType: "dynamic array",
			expected: MakeDynamicArrayType(
				Type{
					typeFromEnum:  Ufixed,
					typeSize:      256,
					typePrecision: 64,
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
					Type{typeFromEnum: Uint, typeSize: uint16(64)},
				),
				uint16(200),
			),
		},
		// tuple type
		{
			input:    "(uint32,(address,byte,bool[10],ufixed256x10[]),byte[])",
			testType: "tuple type",
			expected: MakeTupleType(
				[]Type{
					{
						typeFromEnum: Uint,
						typeSize:     uint16(32),
					},
					MakeTupleType(
						[]Type{
							MakeAddressType(),
							MakeByteType(),
							MakeStaticArrayType(MakeBoolType(), uint16(10)),
							MakeDynamicArrayType(
								Type{
									typeFromEnum:  Ufixed,
									typeSize:      uint16(256),
									typePrecision: uint16(10),
								},
							),
						},
					),
					MakeDynamicArrayType(MakeByteType()),
				},
			),
		},
		{
			input:    "(uint32,(address,byte,bool[10],(ufixed256x10[])))",
			testType: "tuple type",
			expected: MakeTupleType(
				[]Type{
					{
						typeFromEnum: Uint,
						typeSize:     uint16(32),
					},
					MakeTupleType(
						[]Type{
							MakeAddressType(),
							MakeByteType(),
							MakeStaticArrayType(MakeBoolType(), uint16(10)),
							MakeTupleType(
								[]Type{
									MakeDynamicArrayType(
										Type{
											typeFromEnum:  Ufixed,
											typeSize:      uint16(256),
											typePrecision: uint16(10),
										},
									),
								},
							),
						},
					),
				},
			),
		},
		{
			input:    "((uint32),(address,(byte,bool[10],ufixed256x10[])))",
			testType: "tuple type",
			expected: MakeTupleType(
				[]Type{
					MakeTupleType(
						[]Type{
							{
								typeFromEnum: Uint,
								typeSize:     uint16(32),
							},
						},
					),
					MakeTupleType(
						[]Type{
							MakeAddressType(),
							MakeTupleType(
								[]Type{
									MakeByteType(),
									MakeStaticArrayType(MakeBoolType(), uint16(10)),
									MakeDynamicArrayType(
										Type{
											typeFromEnum:  Ufixed,
											typeSize:      uint16(256),
											typePrecision: uint16(10),
										},
									),
								},
							),
						},
					),
				},
			),
		},
	}
	for _, testcase := range testcases {
		t.Run(fmt.Sprintf("TypeFromString test %s", testcase.testType), func(t *testing.T) {
			actual, err := TypeFromString(testcase.input)
			require.Equal(t, nil, err, "TypeFromString %s parsing error", testcase.testType)
			require.Equal(t, testcase.expected, actual, "TestFromString %s: expected %s, actual %s",
				testcase.testType, testcase.expected.String(), actual.String())
		})
	}
}

func TestTypeFromStringInvalid(t *testing.T) {
	for i := 0; i <= 1000; i++ {
		randSize := rand.Uint64()
		for randSize%8 == 0 && randSize <= 512 && randSize >= 8 {
			randSize = rand.Uint64()
		}
		errorInput := "uint" + strconv.FormatUint(randSize, 10)
		_, err := TypeFromString(errorInput)
		require.Error(t, err, "MakeUintType: should throw error on size input %d", randSize)
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
		require.Error(t, err, "MakeUintType: should throw error on size input %d", randSize)
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
		"()",
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
	return MakeTupleType(resultTypes)
}

func TestTypeMISC(t *testing.T) {
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
			ufixedT, err := MakeUFixedType(uint16(i), uint16(j))
			require.NoError(t, err, "make ufixed type error")
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
	for i := 0; i < 1000; i++ {
		testpoolTuple = append(testpoolTuple, generateTupleType(testpool, testpoolTuple))
	}
	for _, testcaseTuple := range testpoolTuple {
		require.True(t, testcaseTuple.Equal(testcaseTuple), "test type tuple equal error")
	}

	tupleTestCount := 0
	for tupleTestCount < 1000 {
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
	for isDynamicCount < 1000 {
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
	for byteLenTestCount < 1000 {
		index := rand.Intn(len(testpool))
		testType := testpool[index]
		byteLen, err := testType.ByteLen()
		if testType.IsDynamic() {
			require.Error(t, err, "byteLen test error on %s dynamic type, should have error",
				testType.String())
		} else {
			if testType.typeFromEnum == Tuple {
				sizeSum := 0
				for _, childT := range testType.childTypes {
					childSize, err := childT.ByteLen()
					require.NoError(t, err, "valid tuple child type should not return error: %s", childT.String())
					sizeSum += childSize
				}
				require.Equal(t, sizeSum, byteLen,
					"%s do not match calculated byte length %d", testType.String(), sizeSum)
			} else if testType.typeFromEnum == ArrayStatic {
				childSize, err := testType.childTypes[0].ByteLen()
				require.NoError(t, err, "%s should not return error", testType.childTypes[0].String())
				expected := childSize * int(testType.staticLength)
				require.Equal(t, expected, byteLen,
					"%s do not match calculated byte length %d", testType.String(), expected)
			}
		}
		byteLenTestCount++
	}
}
