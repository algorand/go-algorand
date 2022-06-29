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
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestNewAppCallBytes(t *testing.T) {
	partitiontest.PartitionTest(t)
	acb, err := NewAppCallBytes("str:hello")
	require.NoError(t, err)
	require.Equal(t, "str", acb.Encoding)
	require.Equal(t, "hello", acb.Value)
	_, err = acb.Raw()
	require.NoError(t, err)

	acb, err = NewAppCallBytes("hello")
	require.Error(t, err)

	acb, err = NewAppCallBytes("str:1:2")
	require.Equal(t, "str", acb.Encoding)
	require.Equal(t, "1:2", acb.Value)
	_, err = acb.Raw()
	require.NoError(t, err)

	acb, err = NewAppCallBytes(":x")
	_, err = acb.Raw()
	require.Error(t, err)
}
