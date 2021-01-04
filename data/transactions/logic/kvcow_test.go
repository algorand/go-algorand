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

package logic

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
)

var byteVal = basics.TealValue{
	Type:  basics.TealBytesType,
	Bytes: "hello",
}

var byteVal2 = basics.TealValue{
	Type:  basics.TealBytesType,
	Bytes: "goodbye",
}

var uintVal = basics.TealValue{
	Type: basics.TealUintType,
	Uint: 1234,
}

func TestKeyValueCowReadWriteDelete(t *testing.T) {
	base := make(basics.TealKeyValue)
	delta := make(basics.StateDelta)
	maxSchema := basics.StateSchema{
		NumByteSlice: 100,
		NumUint:      100,
	}
	proto := &config.ConsensusParams{
		MaxAppKeyLen:        100,
		MaxAppBytesValueLen: 100,
	}

	base["hi"] = byteVal

	kvCow, err := makeKeyValueCow(base, delta, maxSchema, proto)
	require.NoError(t, err)
	require.NotNil(t, kvCow)

	// Check that we can read through to the base map
	v, ok := kvCow.read("hi")
	require.True(t, ok)
	require.Equal(t, v, base["hi"])

	// Check that we can delete through to base map
	err = kvCow.del("hi")
	require.NoError(t, err)
	require.Equal(t, 1, len(kvCow.delta))
	_, ok = kvCow.read("hi")
	require.False(t, ok)

	// Check that writing the same value as backing map yields no delta
	err = kvCow.write("hi", byteVal)
	require.NoError(t, err)
	require.Equal(t, 0, len(kvCow.delta))

	// Check that deleting a key that does not exist yields no delta
	err = kvCow.del("bye")
	require.NoError(t, err)
	require.Equal(t, 0, len(kvCow.delta))
}

func TestKeyValueCowSchemaCounts(t *testing.T) {
	base := make(basics.TealKeyValue)
	delta := make(basics.StateDelta)
	maxSchema := basics.StateSchema{
		NumByteSlice: 4,
		NumUint:      4,
	}
	proto := &config.ConsensusParams{
		MaxAppKeyLen:        100,
		MaxAppBytesValueLen: 100,
	}

	base["a"] = byteVal
	base["b"] = uintVal
	base["c"] = uintVal

	kvCow, err := makeKeyValueCow(base, delta, maxSchema, proto)
	require.NoError(t, err)
	require.NotNil(t, kvCow)

	// Check that the initial count is correct
	require.Equal(t, uint64(2), kvCow.calcSchema.NumUint)
	require.Equal(t, uint64(1), kvCow.calcSchema.NumByteSlice)

	// Write a new integer and check counts
	err = kvCow.write("d", uintVal)
	require.NoError(t, err)
	require.Equal(t, uint64(3), kvCow.calcSchema.NumUint)
	require.Equal(t, uint64(1), kvCow.calcSchema.NumByteSlice)

	// Delete base byte slice and check counts
	err = kvCow.del("a")
	require.NoError(t, err)
	require.Equal(t, uint64(3), kvCow.calcSchema.NumUint)
	require.Equal(t, uint64(0), kvCow.calcSchema.NumByteSlice)

	// Delete again, counts shouldn't change
	err = kvCow.del("a")
	require.NoError(t, err)
	require.Equal(t, uint64(3), kvCow.calcSchema.NumUint)
	require.Equal(t, uint64(0), kvCow.calcSchema.NumByteSlice)

	// Write an integer over deleted byte slice
	err = kvCow.write("a", uintVal)
	require.NoError(t, err)
	require.Equal(t, uint64(4), kvCow.calcSchema.NumUint)
	require.Equal(t, uint64(0), kvCow.calcSchema.NumByteSlice)

	// Overwrite an integer with a byte slice
	err = kvCow.write("c", byteVal)
	require.NoError(t, err)
	require.Equal(t, uint64(3), kvCow.calcSchema.NumUint)
	require.Equal(t, uint64(1), kvCow.calcSchema.NumByteSlice)

	// Overwrite a byte slice with a different byte slice
	err = kvCow.write("c", byteVal2)
	require.NoError(t, err)
	require.Equal(t, uint64(3), kvCow.calcSchema.NumUint)
	require.Equal(t, uint64(1), kvCow.calcSchema.NumByteSlice)

	// Overwrite a byte slice with the same byte slice
	err = kvCow.write("c", byteVal2)
	require.NoError(t, err)
	require.Equal(t, uint64(3), kvCow.calcSchema.NumUint)
	require.Equal(t, uint64(1), kvCow.calcSchema.NumByteSlice)

	// Write two more integers, second should fail with limit
	err = kvCow.write("e", uintVal)
	require.NoError(t, err)
	require.Equal(t, uint64(4), kvCow.calcSchema.NumUint)
	require.Equal(t, uint64(1), kvCow.calcSchema.NumByteSlice)

	// Write two more integers, second should fail with limit
	err = kvCow.write("f", uintVal)
	require.Error(t, err)
	require.Contains(t, err.Error(), "integer count 5 exceeds")
}

func TestKeyValueCowLengthLimits(t *testing.T) {
	base := make(basics.TealKeyValue)
	delta := make(basics.StateDelta)
	maxSchema := basics.StateSchema{
		NumByteSlice: 4,
		NumUint:      4,
	}
	proto := &config.ConsensusParams{
		MaxAppKeyLen:        5,
		MaxAppBytesValueLen: 5,
	}

	kvCow, err := makeKeyValueCow(base, delta, maxSchema, proto)
	require.NoError(t, err)
	require.NotNil(t, kvCow)

	// Writing a long key should fail
	err = kvCow.write("aaaaaa", uintVal)
	require.Error(t, err)
	require.Contains(t, err.Error(), "key too long")

	// Writing a long value should fail
	err = kvCow.write("a", byteVal2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "value too long")

	// Writing both too long should fial
	err = kvCow.write("aaaaaa", byteVal2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "too long")
}
