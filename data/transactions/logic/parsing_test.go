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
	"math"
	"testing"

	"github.com/algorand/avm-abi/abi"
	"github.com/algorand/go-algorand/data/basics"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestNewAppCallBytes(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("errors", func(t *testing.T) {
		_, err := NewAppCallBytes("hello")
		require.Error(t, err)

		for _, v := range []string{":x", "int:-1"} {
			acb, err := NewAppCallBytes(v)
			_, err = acb.Raw()
			require.Error(t, err)
		}
	})

	for _, v := range []string{"hello", "1:2"} {
		for _, e := range []string{"str", "string"} {
			t.Run(fmt.Sprintf("encoding=%v,value=%v", e, v), func(t *testing.T) {
				acb, err := NewAppCallBytes(fmt.Sprintf("%v:%v", e, v))
				require.NoError(t, err)
				r, err := acb.Raw()
				require.NoError(t, err)
				require.Equal(t, v, string(r))
			})
		}

		for _, e := range []string{"b32", "base32", "byte base32"} {
			ve := base32.StdEncoding.EncodeToString([]byte(v))
			t.Run(fmt.Sprintf("encoding=%v,value=%v", e, ve), func(t *testing.T) {
				acb, err := NewAppCallBytes(fmt.Sprintf("%v:%v", e, ve))
				require.NoError(t, err)
				r, err := acb.Raw()
				require.NoError(t, err)
				require.Equal(t, ve, base32.StdEncoding.EncodeToString(r))
			})
		}

		for _, e := range []string{"b64", "base64", "byte base64"} {
			ve := base64.StdEncoding.EncodeToString([]byte(v))
			t.Run(fmt.Sprintf("encoding=%v,value=%v", e, ve), func(t *testing.T) {
				acb, err := NewAppCallBytes(fmt.Sprintf("%v:%v", e, ve))
				require.NoError(t, err)
				r, err := acb.Raw()
				require.NoError(t, err)
				require.Equal(t, ve, base64.StdEncoding.EncodeToString(r))
			})
		}
	}

	for _, v := range []uint64{1, 0, math.MaxUint64} {
		for _, e := range []string{"int", "integer"} {
			t.Run(fmt.Sprintf("encoding=%v,value=%v", e, v), func(t *testing.T) {
				acb, err := NewAppCallBytes(fmt.Sprintf("%v:%v", e, v))
				require.NoError(t, err)
				r, err := acb.Raw()
				require.NoError(t, err)
				require.Equal(t, v, binary.BigEndian.Uint64(r))
			})
		}
	}

	for _, v := range []string{"737777777777777777777777777777777777777777777777777UFEJ2CI"} {
		for _, e := range []string{"addr", "address"} {
			t.Run(fmt.Sprintf("encoding=%v,value=%v", e, v), func(t *testing.T) {
				acb, err := NewAppCallBytes(fmt.Sprintf("%v:%v", e, v))
				require.NoError(t, err)
				r, err := acb.Raw()
				require.NoError(t, err)
				addr, err := basics.UnmarshalChecksumAddress(v)
				require.NoError(t, err)
				expectedBytes := []byte{}
				expectedBytes = addr[:]
				require.Equal(t, expectedBytes, r)
			})
		}
	}

	type abiCase struct {
		abiType, rawValue string
	}
	for _, v := range []abiCase{
		{
			`(uint64,string,bool[])`,
			`[399,"should pass",[true,false,false,true]]`,
		}} {
		for _, e := range []string{"abi"} {
			t.Run(fmt.Sprintf("encoding=%v,value=%v", e, v), func(t *testing.T) {
				acb, err := NewAppCallBytes(fmt.Sprintf(
					"%v:%v:%v", e, v.abiType, v.rawValue))
				require.NoError(t, err)
				r, err := acb.Raw()
				require.NoError(t, err)
				require.NotEmpty(t, r)

				// Confirm round-trip works.
				abiType, err := abi.TypeOf(v.abiType)
				require.NoError(t, err)
				d, err := abiType.Decode(r)
				require.NoError(t, err)
				vv, err := abiType.Encode(d)
				require.NoError(t, err)
				require.Equal(t, r, vv)
			})
		}
	}
}
