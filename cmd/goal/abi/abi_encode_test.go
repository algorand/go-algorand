package abi

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/chrismcguire/gobberish"
	"github.com/stretchr/testify/require"
)

func TestEncodeValid(t *testing.T) {
	for intSize := 8; intSize <= 512; intSize += 8 {
		upperLimit := big.NewInt(0).Lsh(big.NewInt(1), uint(intSize))
		for i := 0; i < 1000; i++ {
			randomInt, err := rand.Int(rand.Reader, upperLimit)
			require.NoError(t, err, "cryptographic random int init fail")
			valueUint, err := MakeUint(randomInt, uint16(intSize))
			require.NoError(t, err, "makeUint Fail")
			encodedUint, err := valueUint.Encode()
			require.NoError(t, err, "uint encode fail")
			randomIntByte := randomInt.Bytes()
			buffer := make([]byte, intSize/8-len(randomIntByte))
			buffer = append(buffer, randomIntByte...)
			require.Equal(t, buffer, encodedUint, "encode uint not match with expected")
		}
		// 2^[size] - 1 test
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

	for size := 8; size <= 512; size += 8 {
		upperLimit := big.NewInt(0).Lsh(big.NewInt(1), uint(size))
		largest := big.NewInt(0).Add(
			upperLimit,
			big.NewInt(1).Neg(big.NewInt(1)),
		)
		for precision := 1; precision <= 160; precision++ {
			denomLimit := big.NewInt(0).Exp(big.NewInt(10), big.NewInt(int64(precision)), nil)
			for i := 0; i < 10; i++ {
				randomInt, err := rand.Int(rand.Reader, upperLimit)
				require.NoError(t, err, "cryptographic random int init fail")

				ufixedRational := big.NewRat(1, 1).SetFrac(randomInt, denomLimit)
				valueUfixed, err := MakeUfixed(ufixedRational, uint16(size), uint16(precision))
				require.NoError(t, err, "makeUfixed Fail")

				encodedUfixed, err := valueUfixed.Encode()
				require.NoError(t, err, "ufixed encode fail")

				randomBytes := randomInt.Bytes()
				buffer := make([]byte, size/8-len(randomBytes))
				buffer = append(buffer, randomBytes...)
				require.Equal(t, buffer, encodedUfixed, "encode ufixed not match with expected")
			}
			// (2^[size] - 1) / (10^[precision]) test
			ufixedLargest := big.NewRat(1, 1).SetFrac(largest, denomLimit)
			ufixedLargestValue, err := MakeUfixed(ufixedLargest, uint16(size), uint16(precision))
			require.NoError(t, err, "make largest ufixed fail")
			ufixedLargestEncode, err := ufixedLargestValue.Encode()
			require.NoError(t, err, "largest ufixed encode error")
			require.Equal(t, largest.Bytes(), ufixedLargestEncode, "encode ufixed largest do not match with expected")
		}
	}

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
		require.Equal(t, address, addrEncode, "encode addr not match with expected")
	}

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

	for i := 0; i < (1 << 8); i++ {
		byteValue := MakeByte(byte(i))
		byteEncode, err := byteValue.Encode()
		require.NoError(t, err, "byte encode fail")
		expected := []byte{byte(i)}
		require.Equal(t, expected, byteEncode, "encode byte not match with expected")
	}

	for length := 1; length <= 10; length++ {
		for i := 0; i < 10; i++ {
			utf8Str := gobberish.GenerateString(length)
			strValue := MakeString(utf8Str)
			utf8ByteLen := len([]byte(utf8Str))
			head := make([]byte, 2)
			binary.BigEndian.PutUint16(head, uint16(utf8ByteLen))
			expected := append(head, []byte(utf8Str)...)
			strEncode, err := strValue.Encode()
			require.NoError(t, err, "string encode fail")
			require.Equal(t, expected, strEncode, "encode string not match with expected")
		}
	}

	t.Run("static bool array encoding", func(t *testing.T) {
		inputBase := []bool{true, false, false, true, true}
		arrayElems := make([]Value, len(inputBase))
		for index, bVal := range inputBase {
			arrayElems[index] = MakeBool(bVal)
		}
		expected := []byte{
			0b10011000,
		}
		boolArr, err := MakeStaticArray(arrayElems, MakeBoolType())
		require.NoError(t, err, "make static array should not return error")
		boolArrEncode, err := boolArr.Encode()
		require.NoError(t, err, "static bool array encoding should not return error")
		require.Equal(t, expected, boolArrEncode, "static bool array encode not match expected")
	})

	t.Run("static bool array encoding", func(t *testing.T) {
		inputBase := []bool{false, false, false, true, true, false, true, false, true, false, true}
		arrayElems := make([]Value, len(inputBase))
		for index, bVal := range inputBase {
			arrayElems[index] = MakeBool(bVal)
		}
		expected := []byte{
			0b00011010, 0b10100000,
		}
		boolArr, err := MakeStaticArray(arrayElems, MakeBoolType())
		require.NoError(t, err, "make static array should not return error")
		boolArrEncode, err := boolArr.Encode()
		require.NoError(t, err, "static bool array encoding should not return error")
		require.Equal(t, expected, boolArrEncode, "static bool array encode not match expected")
	})

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

	t.Run("dynamic tuple encoding", func(t *testing.T) {
		inputBase := []interface{}{
			"ABC", true, false, true, false, "DEF",
		}
		tupleElems := make([]Value, len(inputBase))
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
		stringTuple, err := MakeTuple(tupleElems, []Type{
			MakeStringType(), MakeBoolType(), MakeBoolType(), MakeBoolType(), MakeBoolType(), MakeStringType(),
		})
		require.NoError(t, err, "make string tuple should not return error")
		stringTupleEncode, err := stringTuple.Encode()
		require.NoError(t, err, "string tuple encoding should not return error")
		require.Equal(t, expected, stringTupleEncode, "string tuple encoding not match expected")
	})
}

func TestDecodeValid(t *testing.T) {
	for intSize := 8; intSize <= 512; intSize += 8 {
		upperLimit := big.NewInt(0).Lsh(big.NewInt(1), uint(intSize))
		for i := 0; i < 1000; i++ {
			randomInt, err := rand.Int(rand.Reader, upperLimit)
			require.NoError(t, err, "cryptographic random int init fail")
			valueUint, err := MakeUint(randomInt, uint16(intSize))
			require.NoError(t, err, "makeUint Fail")
			encodedUint, err := valueUint.Encode()
			require.NoError(t, err, "uint encode fail")
			uintType, err := MakeUintType(uint16(intSize))
			require.NoError(t, err, "uint type make fail")
			decodedUint, err := Decode(encodedUint, uintType)
			require.NoError(t, err, "decoding uint should not return error")
			require.Equal(t, valueUint, decodedUint, "decode uint fail to match expected value")
		}
	}

	for size := 8; size <= 512; size += 8 {
		upperLimit := big.NewInt(0).Lsh(big.NewInt(1), uint(size))
		for precision := 1; precision <= 160; precision++ {
			denomLimit := big.NewInt(0).Exp(big.NewInt(10), big.NewInt(int64(precision)), nil)
			for i := 0; i < 10; i++ {
				randomInt, err := rand.Int(rand.Reader, upperLimit)
				require.NoError(t, err, "cryptographic random int init fail")

				ufixedRational := big.NewRat(1, 1).SetFrac(randomInt, denomLimit)
				valueUfixed, err := MakeUfixed(ufixedRational, uint16(size), uint16(precision))
				require.NoError(t, err, "makeUfixed Fail")

				encodedUfixed, err := valueUfixed.Encode()
				require.NoError(t, err, "ufixed encode fail")

				ufixedType, err := MakeUFixedType(uint16(size), uint16(precision))
				require.NoError(t, err, "ufixed type make fail")

				decodedUfixed, err := Decode(encodedUfixed, ufixedType)
				require.NoError(t, err, "decoding ufixed should not return error")
				require.Equal(t, valueUfixed, decodedUfixed, "decode ufixed fail to match expected value")
			}
		}
	}

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

	for i := 0; i < 2; i++ {
		boolValue := MakeBool(i == 1)
		boolEncode, err := boolValue.Encode()
		require.NoError(t, err, "bool encode fail")
		boolDecode, err := Decode(boolEncode, MakeBoolType())
		require.NoError(t, err, "decoding bool should not return error")
		require.Equal(t, boolValue, boolDecode, "decode bool not match with expected")
	}

	for i := 0; i < (1 << 8); i++ {
		byteValue := MakeByte(byte(i))
		byteEncode, err := byteValue.Encode()
		require.NoError(t, err, "byte encode fail")
		byteDecode, err := Decode(byteEncode, MakeByteType())
		require.NoError(t, err, "decoding byte should not return error")
		require.Equal(t, byteValue, byteDecode, "decode byte not match with expected")
	}

	for length := 1; length <= 10; length++ {
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

	t.Run("static bool array decode", func(t *testing.T) {
		inputBase := []bool{true, false, false, true, true}
		arrayElems := make([]Value, len(inputBase))
		for index, bVal := range inputBase {
			arrayElems[index] = MakeBool(bVal)
		}
		expected, err := MakeStaticArray(arrayElems, MakeBoolType())
		require.NoError(t, err, "make expected value should not return error")
		actual, err := Decode([]byte{0b10011000}, MakeStaticArrayType(MakeBoolType(), uint16(len(inputBase))))
		require.NoError(t, err, "decoding static bool array should not return error")
		require.Equal(t, expected, actual, "static bool array decode do not match expected")
	})

	t.Run("static bool array decode", func(t *testing.T) {
		inputBase := []bool{false, false, false, true, true, false, true, false, true, false, true}
		arrayElems := make([]Value, len(inputBase))
		for index, bVal := range inputBase {
			arrayElems[index] = MakeBool(bVal)
		}
		expected, err := MakeStaticArray(arrayElems, MakeBoolType())
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

	t.Run("static uint array decode", func(t *testing.T) {
		inputUint := []uint64{1, 2, 3, 4, 5, 6, 7, 8}
		arrayElems := make([]Value, len(inputUint))
		for index, uintVal := range inputUint {
			temp, err := MakeUint64(uintVal)
			require.NoError(t, err, "make uint64 should not return error")
			arrayElems[index] = temp
		}
		uintT, err := MakeUintType(64)
		require.NoError(t, err, "make uint64 type should not return error")
		expected, err := MakeStaticArray(arrayElems, uintT)
		require.NoError(t, err, "make uint64 static array should not return error")
		arrayEncoded, err := expected.Encode()
		require.NoError(t, err, "uint64 static array encode should not return error")
		arrayDecoded, err := Decode(arrayEncoded, MakeStaticArrayType(uintT, uint16(len(inputUint))))
		require.NoError(t, err, "uint64 static array decode should not return error")
		require.Equal(t, expected, arrayDecoded, "uint64 static array decode do not match with expected value")
	})

	t.Run("dynamic bool array decode", func(t *testing.T) {
		inputBase := []bool{false, true, false, true, false, true, false, true, false, true}
		arrayElems := make([]Value, len(inputBase))
		for index, bVal := range inputBase {
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
		expected, err := MakeTuple(tupleElems, []Type{
			MakeStringType(), MakeBoolType(), MakeBoolType(), MakeBoolType(), MakeBoolType(), MakeStringType(),
		})
		require.NoError(t, err, "make expected value should not return error")
		actual, err := Decode(inputEncode, MakeTupleType([]Type{
			MakeStringType(), MakeBoolType(), MakeBoolType(), MakeBoolType(), MakeBoolType(), MakeStringType(),
		}))
		require.NoError(t, err, "decoding dynamic tuple should not return error")
		require.Equal(t, expected, actual, "dynamic tuple not match with expected")
	})
}

func TestDecodeInvalid(t *testing.T) {
	t.Run("corrupted static bool array decode", func(t *testing.T) {
		inputBase := []byte{0b11111111}
		arrayType := MakeStaticArrayType(MakeBoolType(), 9)
		_, err := Decode(inputBase, arrayType)
		require.Error(t, err, "decoding corrupted static bool array should return error")
	})

	t.Run("corrupted static bool array decode", func(t *testing.T) {
		inputBase := []byte{0b01001011, 0b00000000}
		arrayType := MakeStaticArrayType(MakeBoolType(), 8)
		_, err := Decode(inputBase, arrayType)
		require.Error(t, err, "decoding corrupted static bool array should return error")
	})

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

	t.Run("corrupted dynamic bool array decode", func(t *testing.T) {
		inputBase := []byte{
			0x00, 0x0A, 0b10101010,
		}
		dynamicT := MakeDynamicArrayType(MakeBoolType())
		_, err := Decode(inputBase, dynamicT)
		require.Error(t, err, "decode corrupted dynamic array should return error")
	})

	t.Run("corrupted dynamic bool array decode", func(t *testing.T) {
		inputBase := []byte{
			0x00, 0x07, 0b10101010, 0b00000000,
		}
		dynamicT := MakeDynamicArrayType(MakeBoolType())
		_, err := Decode(inputBase, dynamicT)
		require.Error(t, err, "decode corrupted dynamic array should return error")
	})

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
		_, err := Decode(inputEncode, MakeTupleType([]Type{
			MakeStringType(), MakeBoolType(), MakeBoolType(), MakeBoolType(), MakeBoolType(), MakeStringType(),
		}))
		require.Error(t, err, "corrupted decoding dynamic tuple should return error")
	})
}
