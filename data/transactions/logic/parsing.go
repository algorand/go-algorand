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

package logic

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/algorand/avm-abi/abi"
	"github.com/algorand/go-algorand/data/basics"
)

// AppCallBytes represents an encoding and a value of an app call argument.
type AppCallBytes struct {
	Encoding string `codec:"encoding"`
	Value    string `codec:"value"`
}

// NewAppCallBytes parses an argument of the form "encoding:value" to AppCallBytes.
func NewAppCallBytes(arg string) (AppCallBytes, error) {
	parts := strings.SplitN(arg, ":", 2)
	if len(parts) != 2 {
		return AppCallBytes{}, fmt.Errorf("all arguments and box names should be of the form 'encoding:value'")
	}
	return AppCallBytes{
		Encoding: parts[0],
		Value:    parts[1],
	}, nil
}

// Raw converts an AppCallBytes arg to a byte array.
func (arg AppCallBytes) Raw() (rawValue []byte, parseErr error) {
	switch arg.Encoding {
	case "str", "string":
		rawValue = []byte(arg.Value)
	case "int", "integer":
		num, err := strconv.ParseUint(arg.Value, 10, 64)
		if err != nil {
			parseErr = fmt.Errorf("Could not parse uint64 from string (%s): %v", arg.Value, err)
			return
		}
		ibytes := make([]byte, 8)
		binary.BigEndian.PutUint64(ibytes, num)
		rawValue = ibytes
	case "addr", "address":
		addr, err := basics.UnmarshalChecksumAddress(arg.Value)
		if err != nil {
			parseErr = fmt.Errorf("Could not unmarshal checksummed address from string (%s): %v", arg.Value, err)
			return
		}
		rawValue = addr[:]
	case "b32", "base32", "byte base32":
		data, err := base32.StdEncoding.DecodeString(arg.Value)
		if err != nil {
			parseErr = fmt.Errorf("Could not decode base32-encoded string (%s): %v", arg.Value, err)
			return
		}
		rawValue = data
	case "b64", "base64", "byte base64":
		data, err := base64.StdEncoding.DecodeString(arg.Value)
		if err != nil {
			parseErr = fmt.Errorf("Could not decode base64-encoded string (%s): %v", arg.Value, err)
			return
		}
		rawValue = data
	case "abi":
		typeAndValue := strings.SplitN(arg.Value, ":", 2)
		if len(typeAndValue) != 2 {
			parseErr = fmt.Errorf("Could not decode abi string (%s): should split abi-type and abi-value with colon", arg.Value)
			return
		}
		abiType, err := abi.TypeOf(typeAndValue[0])
		if err != nil {
			parseErr = fmt.Errorf("Could not decode abi type string (%s): %v", typeAndValue[0], err)
			return
		}
		value, err := abiType.UnmarshalFromJSON([]byte(typeAndValue[1]))
		if err != nil {
			parseErr = fmt.Errorf("Could not decode abi value string (%s):%v ", typeAndValue[1], err)
			return
		}
		return abiType.Encode(value)
	default:
		parseErr = fmt.Errorf("Unknown encoding: %s", arg.Encoding)
	}
	return
}
