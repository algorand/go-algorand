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

package basics

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/protocol"
)

func TestStateDeltaValid(t *testing.T) {
	a := require.New(t)

	// test pre-applications proto
	protoPreF := config.Consensus[protocol.ConsensusV23]
	a.False(protoPreF.Application)
	sd := StateDelta{"key": ValueDelta{Action: SetBytesAction, Bytes: "val"}}
	err := sd.Valid(&protoPreF)
	a.Error(err)
	a.Contains(err.Error(), "proto.MaxAppKeyLen is 0")

	sd = StateDelta{"": ValueDelta{Action: SetUintAction, Uint: 1}}
	err = sd.Valid(&protoPreF)
	a.Error(err)
	a.Contains(err.Error(), "proto.MaxAppKeyLen is 0")

	sd = StateDelta{"": ValueDelta{Action: SetBytesAction, Bytes: ""}}
	err = sd.Valid(&protoPreF)
	a.Error(err)
	a.Contains(err.Error(), "proto.MaxAppKeyLen is 0")

	// test proto with applications
	sd = StateDelta{"key": ValueDelta{Action: SetBytesAction, Bytes: "val"}}
	protoF := config.Consensus[protocol.ConsensusFuture]
	err = sd.Valid(&protoF)
	a.NoError(err)

	tooLongKey := strings.Repeat("a", protoF.MaxAppKeyLen+1)
	sd[tooLongKey] = ValueDelta{Action: SetBytesAction, Bytes: "val"}
	err = sd.Valid(&protoF)
	a.Error(err)
	a.Contains(err.Error(), "key too long")
	delete(sd, tooLongKey)

	longKey := tooLongKey[1:]
	tooLongValue := strings.Repeat("b", protoF.MaxAppBytesValueLen+1)
	sd[longKey] = ValueDelta{Action: SetBytesAction, Bytes: tooLongValue}
	err = sd.Valid(&protoF)
	a.Error(err)
	a.Contains(err.Error(), "cannot set value for key")

	sd[longKey] = ValueDelta{Action: SetBytesAction, Bytes: tooLongValue[1:]}
	sd["intval"] = ValueDelta{Action: DeltaAction(10), Uint: 0}
	err = sd.Valid(&protoF)
	a.Error(err)
	a.Contains(err.Error(), "unknown delta action")

	sd["intval"] = ValueDelta{Action: SetUintAction, Uint: 0}
	sd["delval"] = ValueDelta{Action: DeleteAction, Uint: 0, Bytes: tooLongValue}
	err = sd.Valid(&protoF)
	a.NoError(err)
}

func TestSatisfiesSchema(t *testing.T) {
	a := require.New(t)

	tkv := TealKeyValue{}
	schema := StateSchema{}
	err := tkv.SatisfiesSchema(schema)
	a.NoError(err)

	tkv["key"] = TealValue{Type: TealType(10), Uint: 1}
	err = tkv.SatisfiesSchema(schema)
	a.Error(err)
	a.Contains(err.Error(), "unknown type")

	tkv["key"] = TealValue{Type: TealUintType, Uint: 1}
	err = tkv.SatisfiesSchema(schema)
	a.Error(err)
	a.Contains(err.Error(), "exceeds schema integer count")

	tkv["key"] = TealValue{Type: TealBytesType, Uint: 1, Bytes: "value"}
	err = tkv.SatisfiesSchema(schema)
	a.Error(err)
	a.Contains(err.Error(), "exceeds schema bytes count")

	schema.NumUint = 1
	err = tkv.SatisfiesSchema(schema)
	a.Error(err)
	a.Contains(err.Error(), "exceeds schema bytes count")

	schema.NumByteSlice = 1
	err = tkv.SatisfiesSchema(schema)
	a.NoError(err)
}

func TestStateDeltaEqual(t *testing.T) {
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

func TestEvalDeltaEqual(t *testing.T) {
	a := require.New(t)

	d1 := EvalDelta{}
	d2 := EvalDelta{}
	a.True(d1.Equal(d2))

	d2 = EvalDelta{
		GlobalDelta: nil,
		LocalDeltas: nil,
	}
	a.True(d1.Equal(d2))

	d2 = EvalDelta{
		GlobalDelta: StateDelta{},
		LocalDeltas: map[uint64]StateDelta{},
	}
	a.True(d1.Equal(d2))

	d2 = EvalDelta{
		GlobalDelta: StateDelta{"test": {Action: SetUintAction, Uint: 0}},
	}
	a.False(d1.Equal(d2))

	d1 = EvalDelta{
		GlobalDelta: StateDelta{"test": {Action: SetUintAction, Uint: 0}},
	}
	a.True(d1.Equal(d2))

	d2 = EvalDelta{
		LocalDeltas: map[uint64]StateDelta{
			0: {"test": {Action: SetUintAction, Uint: 0}},
		},
	}
	a.False(d1.Equal(d2))

	d1 = EvalDelta{
		LocalDeltas: map[uint64]StateDelta{
			0: {"test": {Action: SetUintAction, Uint: 1}},
		},
	}
	a.False(d1.Equal(d2))

	d2 = EvalDelta{
		LocalDeltas: map[uint64]StateDelta{
			0: {"test": {Action: SetUintAction, Uint: 1}},
		},
	}
	a.True(d1.Equal(d2))

	d1 = EvalDelta{
		LocalDeltas: map[uint64]StateDelta{
			0: {"test": {Action: SetBytesAction, Bytes: "val"}},
		},
	}
	d2 = EvalDelta{
		LocalDeltas: map[uint64]StateDelta{
			0: {"test": {Action: SetBytesAction, Bytes: "val"}},
		},
	}
	a.True(d1.Equal(d2))

	d2 = EvalDelta{
		LocalDeltas: map[uint64]StateDelta{
			0: {"test": {Action: SetBytesAction, Bytes: "val1"}},
		},
	}
	a.False(d1.Equal(d2))

	d2 = EvalDelta{
		LocalDeltas: map[uint64]StateDelta{
			1: {"test": {Action: SetBytesAction, Bytes: "val"}},
		},
	}
	a.False(d1.Equal(d2))
}
