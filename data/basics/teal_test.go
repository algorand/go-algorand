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
	"pgregory.net/rapid"

	"github.com/algorand/go-algorand/data/basics/testing/roundtrip"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// genTealValue generates a valid TealValue with proper Type/field correspondence.
func genTealValue() *rapid.Generator[TealValue] {
	return rapid.Custom(func(t *rapid.T) TealValue {
		tealType := rapid.OneOf(rapid.Just(TealUintType), rapid.Just(TealBytesType)).Draw(t, "type")

		if tealType == TealUintType {
			return TealValue{Type: TealUintType, Uint: rapid.Uint64().Draw(t, "uint")}
		}
		return TealValue{Type: TealBytesType, Bytes: rapid.String().Draw(t, "bytes")}
	})
}

// genValueDelta generates a valid ValueDelta with proper Action/field correspondence.
// Note: DeleteAction is excluded as it doesn't round-trip to TealValue.
func genValueDelta() *rapid.Generator[ValueDelta] {
	return rapid.Custom(func(t *rapid.T) ValueDelta {
		action := rapid.OneOf(rapid.Just(SetUintAction), rapid.Just(SetBytesAction)).Draw(t, "action")

		if action == SetUintAction {
			return ValueDelta{Action: SetUintAction, Uint: rapid.Uint64().Draw(t, "uint")}
		}
		return ValueDelta{Action: SetBytesAction, Bytes: rapid.String().Draw(t, "bytes")}
	})
}

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

func TestTealValueRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Test with a simple example value
	example := TealValue{Type: TealUintType, Uint: 17}

	// Use roundtrip.Check with WithRapid for property-based testing
	require.True(t, roundtrip.Check(t, example,
		func(tv TealValue) ValueDelta { return tv.ToValueDelta() },
		func(vd ValueDelta) TealValue {
			tv, ok := vd.ToTealValue()
			require.True(t, ok)
			return tv
		},
		roundtrip.WithRapid(genTealValue())))
}

func TestValueDeltaRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Test with a simple example value
	example := ValueDelta{Action: SetUintAction, Uint: 42}

	// Use roundtrip.Check with WithRapid for property-based testing
	require.True(t, roundtrip.Check(t, example,
		func(vd ValueDelta) TealValue {
			tv, ok := vd.ToTealValue()
			require.True(t, ok)
			return tv
		},
		func(tv TealValue) ValueDelta { return tv.ToValueDelta() },
		roundtrip.WithRapid(genValueDelta())))
}

func TestValueDeltaDeleteDoesNotRoundTrip(t *testing.T) {
	partitiontest.PartitionTest(t)

	vd := ValueDelta{Action: DeleteAction}
	_, ok := vd.ToTealValue()
	require.False(t, ok)
}
