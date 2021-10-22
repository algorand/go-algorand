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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/algorand/go-algorand/data/basics"
	"math/big"
	"strings"
)

func castBigIntToNearestPrimitive(num *big.Int, bitSize uint16) (interface{}, error) {
	if num.Cmp(new(big.Int).Lsh(big.NewInt(1), uint(bitSize))) >= 0 {
		return nil, fmt.Errorf("cast big int to nearest primitive failure: %v >= 2^%d", num, bitSize)
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
		floatTemp := new(big.Float)
		if err := floatTemp.UnmarshalText(jsonEncoded); err != nil {
			return nil, fmt.Errorf("cannot cast JSON encoded (%s) to ufixed: %v", string(jsonEncoded), err)
		}
		ratTemp, accuracy := floatTemp.Rat(nil)
		if ratTemp == nil || accuracy != big.Exact {
			return nil, fmt.Errorf("cannot cast JSON encoded (%s) to big Rat", string(jsonEncoded))
		}
		denom := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(t.precision)), nil)
		denomRat := new(big.Rat).SetInt(denom)
		numeratorRat := new(big.Rat).Mul(denomRat, ratTemp)
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
		addr, err := basics.UnmarshalChecksumAddress(string(jsonEncoded))
		if err != nil {
			return nil, fmt.Errorf("cannot cast JSON encoded (%s) to address: %v", string(jsonEncoded), err)
		}
		return addr, nil
	case ArrayStatic, ArrayDynamic:
		stringEncoded := string(jsonEncoded)
		if t.childTypes[0].abiTypeID == Byte && strings.HasPrefix(stringEncoded, `"`) {
			// decode base64 and return array of byte
			var stringB64 string
			err := json.Unmarshal(jsonEncoded, &stringB64)
			if err != nil {
				return nil, fmt.Errorf("cannot cast JSON encoded (%s) to b64 string: %v", stringEncoded, err)
			}
			out, err := base64.StdEncoding.DecodeString(stringB64)
			if err != nil {
				return nil, fmt.Errorf("cannot cast JSON encoded (%s) to bytes: %v", stringEncoded, err)
			}
			outInterface := make([]interface{}, len(out))
			for i := 0; i < len(out); i++ {
				outInterface[i] = out[i]
			}
			return outInterface, nil
		}
		var elems []json.RawMessage
		if err := json.Unmarshal(jsonEncoded, &elems); err != nil {
			return nil, fmt.Errorf("cannot cast JSON encoded (%s) to array: %v", stringEncoded, err)
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
		if strings.HasPrefix(stringEncoded, "\"") {
			var stringVar string
			if err := json.Unmarshal(jsonEncoded, &stringVar); err != nil {
				return nil, fmt.Errorf("cannot cast JSON encoded (%s) to string: %v", stringEncoded, err)
			}
			return stringVar, nil
		} else if strings.HasPrefix(stringEncoded, "[") {
			var elems []json.RawMessage
			if err := json.Unmarshal(jsonEncoded, &elems); err != nil {
				return nil, fmt.Errorf("cannot cast JSON encoded (%s) to string: %v", stringEncoded, err)
			}
			elemsBytes := make([]byte, len(elems))
			for i := 0; i < len(elems); i++ {
				tempByte, err := byteType.UnmarshalFromJSON(elems[i])
				if err != nil {
					return nil, err
				}
				elemsBytes[i] = tempByte.(byte)
			}
			return string(elemsBytes), nil
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
