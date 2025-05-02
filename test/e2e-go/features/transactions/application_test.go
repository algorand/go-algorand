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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestApplication(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	proto, ok := config.Consensus[protocol.ConsensusFuture]
	a.True(ok)
	proto.AgreementFilterTimeoutPeriod0 = 400 * time.Millisecond
	proto.AgreementFilterTimeout = 400 * time.Millisecond
	fixture.SetConsensus(config.ConsensusProtocols{protocol.ConsensusFuture: proto})

	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer fixture.Shutdown()

	client := fixture.LibGoalClient
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)

	creator := accountList[0].Address
	_, err = client.GetUnencryptedWalletHandle()
	a.NoError(err)

	fee := uint64(1000)

	counter := `#pragma version 5
int 1
loop: byte "a"
log
int 1
+
dup
int 30
<=
bnz loop
byte "b"
log
byte "c"
log
`

	approvalOps, err := logic.AssembleString(counter)
	a.NoError(err)
	clearstateOps, err := logic.AssembleString("#pragma version 5\nint 1")
	a.NoError(err)
	schema := basics.StateSchema{
		NumUint: 1,
	}

	// create the app
	tx, err := client.MakeUnsignedAppCreateTx(
		transactions.OptInOC, approvalOps.Program, clearstateOps.Program, schema, schema, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(creator, 0, 0, fee, tx)
	a.NoError(err)
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)
	signedTxn, err := client.SignTransactionWithWallet(wh, nil, tx)
	a.NoError(err)
	round, err := client.CurrentRound()
	a.NoError(err)
	txid, err := client.BroadcastTransaction(signedTxn)
	a.NoError(err)
	confirmed := fixture.WaitForAllTxnsToConfirm(round+2, map[string]string{txid: signedTxn.Txn.Sender.String()})
	a.True(confirmed)
	round, err = client.CurrentRound()
	a.NoError(err)

	logs := make([]string, 32)
	for i := range logs {
		logs[i] = "a"
	}
	logs[30] = "b"
	logs[31] = "c"

	b, err := client.BookkeepingBlock(round)
	a.NoError(err)
	for _, ps := range b.Payset {
		a.Equal(logs, ps.ApplyData.EvalDelta.Logs)
	}

}
