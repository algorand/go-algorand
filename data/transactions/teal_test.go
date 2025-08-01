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

package transactions

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestEvalDeltaEqual(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(t)

	d1 := EvalDelta{}
	d2 := EvalDelta{}
	a.True(d1.Equal(d2))

	d2 = EvalDelta{
		GlobalDelta: nil,
		LocalDeltas: nil,
		Logs:        nil,
	}
	a.True(d1.Equal(d2))

	d2 = EvalDelta{
		GlobalDelta: basics.StateDelta{},
		LocalDeltas: map[uint64]basics.StateDelta{},
		Logs:        []string{},
	}
	a.True(d1.Equal(d2))

	d2 = EvalDelta{
		GlobalDelta: basics.StateDelta{"test": {Action: basics.SetUintAction, Uint: 0}},
	}
	a.False(d1.Equal(d2))

	d1 = EvalDelta{
		GlobalDelta: basics.StateDelta{"test": {Action: basics.SetUintAction, Uint: 0}},
	}
	a.True(d1.Equal(d2))

	d2 = EvalDelta{
		LocalDeltas: map[uint64]basics.StateDelta{
			0: {"test": {Action: basics.SetUintAction, Uint: 0}},
		},
	}
	a.False(d1.Equal(d2))

	d1 = EvalDelta{
		LocalDeltas: map[uint64]basics.StateDelta{
			0: {"test": {Action: basics.SetUintAction, Uint: 1}},
		},
	}
	a.False(d1.Equal(d2))

	d2 = EvalDelta{
		LocalDeltas: map[uint64]basics.StateDelta{
			0: {"test": {Action: basics.SetUintAction, Uint: 1}},
		},
	}
	a.True(d1.Equal(d2))

	d1 = EvalDelta{
		LocalDeltas: map[uint64]basics.StateDelta{
			0: {"test": {Action: basics.SetBytesAction, Bytes: "val"}},
		},
	}
	d2 = EvalDelta{
		LocalDeltas: map[uint64]basics.StateDelta{
			0: {"test": {Action: basics.SetBytesAction, Bytes: "val"}},
		},
	}
	a.True(d1.Equal(d2))

	d2 = EvalDelta{
		LocalDeltas: map[uint64]basics.StateDelta{
			0: {"test": {Action: basics.SetBytesAction, Bytes: "val1"}},
		},
	}
	a.False(d1.Equal(d2))

	d2 = EvalDelta{
		LocalDeltas: map[uint64]basics.StateDelta{
			1: {"test": {Action: basics.SetBytesAction, Bytes: "val"}},
		},
	}
	a.False(d1.Equal(d2))

	d2 = EvalDelta{
		Logs: []string{"val"},
	}
	a.False(d1.Equal(d2))

	d1 = EvalDelta{
		Logs: []string{"val2"},
	}
	a.False(d1.Equal(d2))

	d1 = EvalDelta{
		Logs: []string{"val", "val2"},
	}
	a.False(d1.Equal(d2))

	d1 = EvalDelta{
		Logs: []string{"val"},
	}
	a.True(d1.Equal(d2))

	// Test inner transaction equality
	d1 = EvalDelta{
		InnerTxns: []SignedTxnWithAD{},
	}
	d2 = EvalDelta{
		InnerTxns: nil,
	}
	a.True(d1.Equal(d2))

	// Test inner transaction equality
	d1 = EvalDelta{
		InnerTxns: []SignedTxnWithAD{{
			SignedTxn: SignedTxn{
				Lsig: LogicSig{
					Logic: []byte{0x01},
				},
			},
		}},
	}
	d2 = EvalDelta{
		InnerTxns: []SignedTxnWithAD{{
			SignedTxn: SignedTxn{
				Lsig: LogicSig{
					Logic: []byte{0x01},
				},
			},
		}},
	}
	a.True(d1.Equal(d2))
	d2 = EvalDelta{
		InnerTxns: []SignedTxnWithAD{{
			SignedTxn: SignedTxn{
				Lsig: LogicSig{
					Logic: []byte{0x02},
					Args:  [][]byte{},
				},
			},
		}},
	}
	a.False(d1.Equal(d2))

	d1 = EvalDelta{
		InnerTxns: []SignedTxnWithAD{{
			SignedTxn: SignedTxn{
				Txn: Transaction{
					Type: protocol.TxType("pay"),
				},
			},
		}},
	}
	d2 = EvalDelta{
		InnerTxns: []SignedTxnWithAD{{
			SignedTxn: SignedTxn{
				Txn: Transaction{
					Type: protocol.TxType("axfer"),
				},
			},
		}},
	}
	a.False(d1.Equal(d2))

}

// TestUnchangedAllocBounds ensure that the allocbounds on EvalDelta have not
// changed.  If they change, EvalDelta.checkAllocBounds must be changed, or at
// least reconsidered, as well. We must give plenty of thought to whether a new
// allocbound, used by new versions, is compatible with old code. If the change
// can only show up in new protocol versions, it should be ok. But if we change
// a bound, it will go into effect immediately, not with Protocol upgrade. So we
// must be extremely careful that old protocol versions can not emit messages
// that take advnatage of a new, bigger bound. (Or, if the bound is *lowered* it
// had better be the case that such messages cannot be emitted in old code.)
func TestUnchangedAllocBounds(t *testing.T) {
	partitiontest.PartitionTest(t)

	delta := &EvalDelta{}
	max := 256 // Hardcodes bounds.MaxEvalDeltaAccounts
	for i := 0; i < max; i++ {
		delta.InnerTxns = append(delta.InnerTxns, SignedTxnWithAD{})
		msg := delta.MarshalMsg(nil)
		_, err := delta.UnmarshalMsg(msg)
		require.NoError(t, err)
	}
	delta.InnerTxns = append(delta.InnerTxns, SignedTxnWithAD{})
	msg := delta.MarshalMsg(nil)
	_, err := delta.UnmarshalMsg(msg)
	require.Error(t, err)

	delta = &EvalDelta{}
	max = 2048 // Hardcodes bounds.MaxLogCalls, currently MaxAppProgramLen
	for i := 0; i < max; i++ {
		delta.Logs = append(delta.Logs, "junk")
		msg := delta.MarshalMsg(nil)
		_, err := delta.UnmarshalMsg(msg)
		require.NoError(t, err)
	}
	delta.Logs = append(delta.Logs, "junk")
	msg = delta.MarshalMsg(nil)
	_, err = delta.UnmarshalMsg(msg)
	require.Error(t, err)

	delta = &EvalDelta{}
	max = 256 // Hardcodes bounds.MaxInnerTransactionsPerDelta
	for i := 0; i < max; i++ {
		delta.InnerTxns = append(delta.InnerTxns, SignedTxnWithAD{})
		msg := delta.MarshalMsg(nil)
		_, err := delta.UnmarshalMsg(msg)
		require.NoError(t, err)
	}
	delta.InnerTxns = append(delta.InnerTxns, SignedTxnWithAD{})
	msg = delta.MarshalMsg(nil)
	_, err = delta.UnmarshalMsg(msg)
	require.Error(t, err)

	// This one appears wildly conservative. The real max is something like
	// MaxAppTxnAccounts (4) + 1, since the key must be an index in the static
	// array of touchable accounts.
	delta = &EvalDelta{LocalDeltas: make(map[uint64]basics.StateDelta)}
	max = 2048 // Hardcodes bounds.MaxEvalDeltaAccounts
	for i := 0; i < max; i++ {
		delta.LocalDeltas[uint64(i)] = basics.StateDelta{}
		msg := delta.MarshalMsg(nil)
		_, err := delta.UnmarshalMsg(msg)
		require.NoError(t, err)
	}
	delta.LocalDeltas[uint64(max)] = basics.StateDelta{}
	msg = delta.MarshalMsg(nil)
	_, err = delta.UnmarshalMsg(msg)
	require.Error(t, err)

	// This one *might* be wildly conservative. Only 64 keys can be set in
	// globals, but I don't know what happens if you set and delete 65 (or way
	// more) keys in a single transaction.
	delta = &EvalDelta{GlobalDelta: make(basics.StateDelta)}
	max = 2048 // Hardcodes bounds.MaxStateDeltaKeys
	for i := 0; i < max; i++ {
		delta.GlobalDelta[fmt.Sprintf("%d", i)] = basics.ValueDelta{}
		msg := delta.MarshalMsg(nil)
		_, err := delta.UnmarshalMsg(msg)
		require.NoError(t, err)
	}
	delta.GlobalDelta[fmt.Sprintf("%d", max)] = basics.ValueDelta{}
	msg = delta.MarshalMsg(nil)
	_, err = delta.UnmarshalMsg(msg)
	require.Error(t, err)

}
