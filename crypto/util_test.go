// Copyright (C) 2019-2023 Algorand, Inc.
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

package crypto

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecode(t *testing.T) {
	partitiontest.PartitionTest(t)
	toBeHashed := []byte("this is a test")
	hashed := Hash(toBeHashed)
	hashedStr := hashed.String()
	recovered, err := DigestFromString(hashedStr)

	require.Equal(t, nil, err)
	require.Equal(t, recovered, hashed)
}

func TestDigest_IsZero(t *testing.T) {
	partitiontest.PartitionTest(t)
	d := Digest{}
	require.True(t, d.IsZero())
	require.Zero(t, d)

	d2 := Digest{}
	RandBytes(d2[:])
	require.False(t, d2.IsZero())
	require.NotZero(t, d2)

}
