// Copyright (C) 2019-2022 Algorand, Inc.
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
	"bytes"
	"crypto/sha512"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"math/big"
)

// NOTE: discussion about go-algorand-sdk
// https://github.com/algorand/go-algorand/pull/3375#issuecomment-1007536841

var base32Encoder = base32.StdEncoding.WithPadding(base32.NoPadding)

func addressCheckSum(addressBytes []byte) ([]byte, error) {
	if len(addressBytes) != addressByteSize {
		return nil, fmt.Errorf("address bytes should be of length 32")
	}
	hashed := sha512.Sum512_256(addressBytes[:])
	return hashed[addressByteSize-checksumByteSize:], nil
}

func castBigIntToNearestPrimitive(num *big.Int, bitSize uint16) (interface{}, error) {
	if num.BitLen() > int(bitSize) {
		return nil, fmt.Errorf("cast big int to nearest primitive failure: %v >= 2^%d", num, bitSize)
	} else if num.Sign() < 0 {
		return nil, fmt.Errorf("cannot cast big int to near primitive: %v < 0", num)
	}

	switch bitSize / 8 {
	case 1:
		return uint8(num.Uint64()), nil
	case 2:
		return uint16(num.Uint64()), nil
	case 3, 4:
		return uint32(num.Uint64()), nil
	case 5, 6, 7, 8:
		return num.Uint64(), nil
	default:
		return num, nil
	}
}

// MarshalToJSON convert golang value to JSON format from ABI type
func (t Type) MarshalToJSON(value interface{}) ([]byte, error) {
	switch t.abiTypeID {
	case Uint:
		bytesUint, err := encodeInt(value, t.bitSize)
		if err != nil {
			return nil, err
		}
		return new(big.Int).SetBytes(bytesUint).MarshalJSON()
	case Ufixed:
		denom := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(t.precision)), nil)
		encodedUint, err := encodeInt(value, t.bitSize)
		if err != nil {
			return nil, err
		}
		return []byte(new(big.Rat).SetFrac(new(big.Int).SetBytes(encodedUint), denom).FloatString(int(t.precision))), nil
	case Bool:
		boolValue, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("cannot infer to bool for marshal to JSON")
		}
		return json.Marshal(boolValue)
	case Byte:
		byteValue, ok := value.(byte)
		if !ok {
			return nil, fmt.Errorf("cannot infer to byte for marshal to JSON")
		}
		return json.Marshal(byteValue)
	case Address:
		var addressValueInternal []byte
		switch valueCasted := value.(type) {
		case []byte:
			if len(valueCasted) != addressByteSize {
				return nil, fmt.Errorf("address byte slice length not equal to 32 byte")
			}
			addressValueInternal = valueCasted
		case [addressByteSize]byte:
			copy(addressValueInternal[:], valueCasted[:])
		default:
			return nil, fmt.Errorf("cannot infer to byte slice/array for marshal to JSON")
		}
		checksum, err := addressCheckSum(addressValueInternal)
		if err != nil {
			return nil, err
		}
		addressValueInternal = append(addressValueInternal, checksum...)
		return json.Marshal(base32Encoder.EncodeToString(addressValueInternal))
	case ArrayStatic, ArrayDynamic:
		values, err := inferToSlice(value)
		if err != nil {
			return nil, err
		}
		if t.abiTypeID == ArrayStatic && int(t.staticLength) != len(values) {
			return nil, fmt.Errorf("length of slice %d != type specific length %d", len(values), t.staticLength)
		}
		if t.childTypes[0].abiTypeID == Byte {
			byteArr := make([]byte, len(values))
			for i := 0; i < len(values); i++ {
				tempByte, ok := values[i].(byte)
				if !ok {
					return nil, fmt.Errorf("cannot infer byte element from slice")
				}
				byteArr[i] = tempByte
			}
			return json.Marshal(byteArr)
		}
		rawMsgSlice := make([]json.RawMessage, len(values))
		for i := 0; i < len(values); i++ {
			rawMsgSlice[i], err = t.childTypes[0].MarshalToJSON(values[i])
			if err != nil {
				return nil, err
			}
		}
		return json.Marshal(rawMsgSlice)
	case String:
		stringVal, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("cannot infer to string for marshal to JSON")
		}
		return json.Marshal(stringVal)
	case Tuple:
		values, err := inferToSlice(value)
		if err != nil {
			return nil, err
		}
		if len(values) != int(t.staticLength) {
			return nil, fmt.Errorf("tuple element number != value slice length")
		}
		rawMsgSlice := make([]json.RawMessage, len(values))
		for i := 0; i < len(values); i++ {
			rawMsgSlice[i], err = t.childTypes[i].MarshalToJSON(values[i])
			if err != nil {
				return nil, err
			}
		}
		return json.Marshal(rawMsgSlice)
	default:
		return nil, fmt.Errorf("cannot infer ABI type for marshalling value to JSON")
	}
}

// UnmarshalFromJSON convert bytes to golang value following ABI type and encoding rules
func (t Type) UnmarshalFromJSON(jsonEncoded []byte) (interface{}, error) {
	switch t.abiTypeID {
	case Uint:
		num := new(big.Int)
		if err := num.UnmarshalJSON(jsonEncoded); err != nil {
			return nil, fmt.Errorf("cannot cast JSON encoded (%s) to uint: %v", string(jsonEncoded), err)
		}
		return castBigIntToNearestPrimitive(num, t.bitSize)
	case Ufixed:
		floatTemp := new(big.Rat)
		if err := floatTemp.UnmarshalText(jsonEncoded); err != nil {
			return nil, fmt.Errorf("cannot cast JSON encoded (%s) to ufixed: %v", string(jsonEncoded), err)
		}
		denom := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(t.precision)), nil)
		denomRat := new(big.Rat).SetInt(denom)
		numeratorRat := new(big.Rat).Mul(denomRat, floatTemp)
		if !numeratorRat.IsInt() {
			return nil, fmt.Errorf("cannot cast JSON encoded (%s) to ufixed: precision out of range", string(jsonEncoded))
		}
		return castBigIntToNearestPrimitive(numeratorRat.Num(), t.bitSize)
	case Bool:
		var elem bool
		if err := json.Unmarshal(jsonEncoded, &elem); err != nil {
			return nil, fmt.Errorf("cannot cast JSON encoded (%s) to bool: %v", string(jsonEncoded), err)
		}
		return elem, nil
	case Byte:
		var elem byte
		if err := json.Unmarshal(jsonEncoded, &elem); err != nil {
			return nil, fmt.Errorf("cannot cast JSON encoded to byte: %v", err)
		}
		return elem, nil
	case Address:
		var addrStr string
		if err := json.Unmarshal(jsonEncoded, &addrStr); err != nil {
			return nil, fmt.Errorf("cannot cast JSON encoded to address string: %v", err)
		}
		decoded, err := base32Encoder.DecodeString(addrStr)
		if err != nil {
			return nil,
				fmt.Errorf("cannot cast JSON encoded address string (%s) to address: %v", addrStr, err)
		}
		if len(decoded) != addressByteSize+checksumByteSize {
			return nil,
				fmt.Errorf(
					"cannot cast JSON encoded address string (%s) to address: "+
						"decoded byte length should equal to 36 with address and checksum",
					string(jsonEncoded),
				)
		}
		checksum, err := addressCheckSum(decoded[:addressByteSize])
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(checksum, decoded[addressByteSize:]) {
			return nil, fmt.Errorf("cannot cast JSON encoded address string (%s) to address: decoded checksum unmatch", addrStr)
		}
		return decoded[:addressByteSize], nil
	case ArrayStatic, ArrayDynamic:
		if t.childTypes[0].abiTypeID == Byte && bytes.HasPrefix(jsonEncoded, []byte{'"'}) {
			var byteArr []byte
			err := json.Unmarshal(jsonEncoded, &byteArr)
			if err != nil {
				return nil, fmt.Errorf("cannot cast JSON encoded (%s) to bytes: %v", string(jsonEncoded), err)
			}
			if t.abiTypeID == ArrayStatic && len(byteArr) != int(t.staticLength) {
				return nil, fmt.Errorf("length of slice %d != type specific length %d", len(byteArr), t.staticLength)
			}
			outInterface := make([]interface{}, len(byteArr))
			for i := 0; i < len(byteArr); i++ {
				outInterface[i] = byteArr[i]
			}
			return outInterface, nil
		}
		var elems []json.RawMessage
		if err := json.Unmarshal(jsonEncoded, &elems); err != nil {
			return nil, fmt.Errorf("cannot cast JSON encoded (%s) to array: %v", string(jsonEncoded), err)
		}
		if t.abiTypeID == ArrayStatic && len(elems) != int(t.staticLength) {
			return nil, fmt.Errorf("JSON array element number != ABI array elem number")
		}
		values := make([]interface{}, len(elems))
		for i := 0; i < len(elems); i++ {
			tempValue, err := t.childTypes[0].UnmarshalFromJSON(elems[i])
			if err != nil {
				return nil, err
			}
			values[i] = tempValue
		}
		return values, nil
	case String:
		stringEncoded := string(jsonEncoded)
		if bytes.HasPrefix(jsonEncoded, []byte{'"'}) {
			var stringVar string
			if err := json.Unmarshal(jsonEncoded, &stringVar); err != nil {
				return nil, fmt.Errorf("cannot cast JSON encoded (%s) to string: %v", stringEncoded, err)
			}
			return stringVar, nil
		} else if bytes.HasPrefix(jsonEncoded, []byte{'['}) {
			var elems []byte
			if err := json.Unmarshal(jsonEncoded, &elems); err != nil {
				return nil, fmt.Errorf("cannot cast JSON encoded (%s) to string: %v", stringEncoded, err)
			}
			return string(elems), nil
		} else {
			return nil, fmt.Errorf("cannot cast JSON encoded (%s) to string", stringEncoded)
		}
	case Tuple:
		var elems []json.RawMessage
		if err := json.Unmarshal(jsonEncoded, &elems); err != nil {
			return nil, fmt.Errorf("cannot cast JSON encoded (%s) to array for tuple: %v", string(jsonEncoded), err)
		}
		if len(elems) != int(t.staticLength) {
			return nil, fmt.Errorf("JSON array element number != ABI tuple elem number")
		}
		values := make([]interface{}, len(elems))
		for i := 0; i < len(elems); i++ {
			tempValue, err := t.childTypes[i].UnmarshalFromJSON(elems[i])
			if err != nil {
				return nil, err
			}
			values[i] = tempValue
		}
		return values, nil
	default:
		return nil, fmt.Errorf("cannot cast JSON encoded %s to ABI encoding stuff", string(jsonEncoded))
	}
}
