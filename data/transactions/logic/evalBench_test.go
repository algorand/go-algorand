// Copyright (C) 2019-2024 Algorand, Inc.
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

package logic_test

import (
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

func BenchmarkCheckSignature(b *testing.B) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	txns := txntest.CreateTinyManTxGroup(b, true)
	ops, err := logic.AssembleString(txntest.TmLsig)
	require.NoError(b, err)
	stxns := []transactions.SignedTxn{{Txn: txns[3].Txn(), Lsig: transactions.LogicSig{Logic: ops.Program}}}
	ep := logic.NewSigEvalParams(stxns, &proto, &logic.NoHeaderLedger{})
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err = logic.CheckSignature(0, ep)
		require.NoError(b, err)
	}
}
