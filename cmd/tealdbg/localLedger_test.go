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

package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

// Current implementation uses LegderForCowBase interface to plug into evaluator.
// LedgerForLogic in this case is created inside ledger package, and it is the same
// as used in on-chain evaluation.
// This test ensures TEAL program sees data provided by LegderForCowBase, and sees all
// intermediate changes.
func TestBalanceAdapterStateChanges(t *testing.T) {
	a := require.New(t)

	source := `#pragma version 2
// read initial value, must be 1
byte "gkeyint"
app_global_get
int 2
==
// write a new value
byte "gkeyint"
int 3
app_global_put
// read updated value, must be 2
byte "gkeyint"
app_global_get
int 3
==
&&
//
// repeat the same for some local key
//
int 0
byte "lkeyint"
app_local_get
int 1
==
&&
int 0
byte "lkeyint"
int 2
app_local_put
int 0
byte "lkeyint"
app_local_get
int 2
==
&&
`
	ops, err := logic.AssembleString(source)
	a.NoError(err)
	program := ops.Program
	addr, err := basics.UnmarshalChecksumAddress("47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU")
	a.NoError(err)

	assetIdx := basics.AssetIndex(50)
	appIdx := basics.AppIndex(100)
	br := makeSampleBalanceRecord(addr, assetIdx, appIdx)
	balances := map[basics.Address]basics.AccountData{
		addr: br.AccountData,
	}

	// make transaction group: app call + sample payment
	txn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Header: transactions.Header{
				Sender: addr,
				Fee:    basics.MicroAlgos{Raw: 100},
				Note:   []byte{1, 2, 3},
			},
			ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
				ApplicationID:   appIdx,
				ApplicationArgs: [][]byte{[]byte("ALGO"), []byte("RAND")},
			},
		},
	}

	ba, _, err := makeBalancesAdapter(
		balances, []transactions.SignedTxn{txn}, 0, string(protocol.ConsensusCurrentVersion),
		100, 102030, appIdx, false, "", "",
	)
	a.NoError(err)

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	ep := logic.EvalParams{
		Txn:        &txn,
		Proto:      &proto,
		TxnGroup:   []transactions.SignedTxn{txn},
		GroupIndex: 0,
	}
	pass, delta, err := ba.StatefulEval(ep, appIdx, program)
	a.NoError(err)
	a.True(pass)
	a.Equal(1, len(delta.GlobalDelta))
	a.Equal(basics.SetUintAction, delta.GlobalDelta["gkeyint"].Action)
	a.Equal(uint64(3), delta.GlobalDelta["gkeyint"].Uint)
	a.Equal(1, len(delta.LocalDeltas))
	a.Equal(1, len(delta.LocalDeltas[0]))
	a.Equal(basics.SetUintAction, delta.LocalDeltas[0]["lkeyint"].Action)
	a.Equal(uint64(2), delta.LocalDeltas[0]["lkeyint"].Uint)
}
