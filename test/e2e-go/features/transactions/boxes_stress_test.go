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
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func checkEqual2(expected []string, actual []string) bool {
	if len(expected) != len(actual) {
		return false
	}
	for i, e := range expected {
		if e != actual[i] {
			return false
		}
	}
	return true
}

const genericBoxProgram string = `#pragma version 8
txn ApplicationID
bz end

txn ApplicationArgs 0 		// box op instruction
byte "create"
==
bnz create

txn ApplicationArgs 0 		// box op instruction
byte "extract"
==
bnz extract

txn ApplicationArgs 0 		// box op instruction
byte "replace"
==
bnz replace

txn ApplicationArgs 0 		// box op instruction
byte "del"
==
bnz del

txn ApplicationArgs 0 		// box op instruction
byte "len"
==
bnz len

txn ApplicationArgs 0 		// box op instruction
byte "get"
==
bnz get

txn ApplicationArgs 0 		// box op instruction
byte "put"
==
bnz put

bad:
	err

// Box opcode handlers
create:
	b end
extract:
	b end
replace:
	b end
del:
	b end
len:
	b end
get:
	b end
put:
	b end

end:
	int 1
`

const clearProgram string = `#pragma version 8
int 1`

func TestBoxesStress(t *testing.T) {
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

	approvalOps, err := logic.AssembleString(genericBoxProgram)
	a.NoError(err)
	clearstateOps, err := logic.AssembleString(clearProgram)
	a.NoError(err)
	schema := basics.StateSchema{
		NumUint: 1,
	}

	// create the app
	tx, err := client.MakeUnsignedAppCreateTx(
		transactions.OptInOC, approvalOps.Program, clearstateOps.Program, schema, schema, nil, nil, nil, nil, nil, 0)
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
		ed := ps.ApplyData.EvalDelta
		ok = checkEqual2(logs, ed.Logs)
		a.True(ok)
	}

}
