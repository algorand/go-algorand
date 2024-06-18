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

package verify

import (
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/protocol"

	"github.com/stretchr/testify/require"
)

// test/benchmark real programs found in the wild (testnet/mainnet).

// BenchmarkTinyMan tries to reproduce
// https://algoexplorer.io/tx/group/d1bUcqFbNZDMIdcreM9Vw2jzOIZIa2UzDgTTlr2Sl4o%3D
// which is an algo to USDC swap.  The source code below is extracted from
// algoexplorer, which adds some unusual stuff as comments
func BenchmarkTinyMan(b *testing.B) {
	txns := txntest.CreateTinyManTxGroup(b, false)
	b.Run("eval-lsig-signature", func(b *testing.B) {
		stxns, _ := txntest.CreateTinyManSignedTxGroup(b, txns)
		require.NotEmpty(b, stxns[0].Sig)
		require.NotEmpty(b, stxns[1].Lsig.Logic)
		require.NotEmpty(b, stxns[2].Sig)
		require.NotEmpty(b, stxns[3].Lsig.Logic)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			proto := config.Consensus[protocol.ConsensusCurrentVersion]
			ep := logic.NewSigEvalParams(stxns, &proto, &logic.NoHeaderLedger{})
			pass, err := logic.EvalSignature(1, ep)
			require.NoError(b, err)
			require.True(b, pass)
			pass, err = logic.EvalSignature(3, ep)
			require.NoError(b, err)
			require.True(b, pass)
		}
	})

	hdr := bookkeeping.BlockHeader{
		UpgradeState: bookkeeping.UpgradeState{
			CurrentProtocol: protocol.ConsensusCurrentVersion,
		},
	}

	b.Run("group-check-actual", func(b *testing.B) {
		stxnss := make([][]transactions.SignedTxn, b.N)
		for i := 0; i < b.N; i++ {
			txns := txntest.CreateTinyManTxGroup(b, true)
			stxnss[i], _ = txntest.CreateTinyManSignedTxGroup(b, txns)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := TxnGroup(stxnss[i], &hdr, nil, &logic.NoHeaderLedger{})
			require.NoError(b, err)
		}
	})

	b.Run("group-check-all-crypto", func(b *testing.B) {
		stxns, secrets := txntest.CreateTinyManSignedTxGroup(b, txns)
		stxns[1] = stxns[1].Txn.Sign(secrets[0])
		stxns[3] = stxns[3].Txn.Sign(secrets[0])
		require.Empty(b, stxns[0].Lsig.Logic)
		require.Empty(b, stxns[1].Lsig.Logic)
		require.Empty(b, stxns[2].Lsig.Logic)
		require.Empty(b, stxns[3].Lsig.Logic)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := TxnGroup(stxns, &hdr, nil, &logic.NoHeaderLedger{})
			require.NoError(b, err)
		}
	})
}
