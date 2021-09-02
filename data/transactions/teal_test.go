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

package transactions

import (
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
