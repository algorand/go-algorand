// Copyright (C) 2019-2025 Algorand, Inc.
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

package basics

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestStateDeltaEqual(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	var d1 StateDelta = nil
	var d2 StateDelta = nil
	a.True(d1.Equal(d2))

	d2 = StateDelta{}
	a.True(d1.Equal(d2))

	d2 = StateDelta{"test": {Action: SetUintAction, Uint: 0}}
	a.False(d1.Equal(d2))

	d1 = StateDelta{}
	d2 = StateDelta{}
	a.True(d1.Equal(d2))

	d2 = StateDelta{"test": {Action: SetUintAction, Uint: 0}}
	a.False(d1.Equal(d2))

	d1 = StateDelta{"test2": {Action: SetBytesAction, Uint: 0}}
	a.False(d1.Equal(d2))

	d1 = StateDelta{"test": {Action: SetUintAction, Uint: 0}}
	d2 = StateDelta{"test": {Action: SetUintAction, Uint: 0}}
	a.True(d1.Equal(d2))

	d1 = StateDelta{"test": {Action: SetBytesAction, Bytes: "val"}}
	d2 = StateDelta{"test": {Action: SetBytesAction, Bytes: "val"}}
	a.True(d1.Equal(d2))

	d2 = StateDelta{"test": {Action: SetBytesAction, Bytes: "val1"}}
	a.False(d1.Equal(d2))
}
