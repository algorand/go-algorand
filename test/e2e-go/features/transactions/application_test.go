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
)

func checkEqual(expected []string, actual []string) bool {
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

func TestApplication(t *testing.T) {
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
	wh, err := client.GetUnencryptedWalletHandle()
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
<
bnz loop
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
		transactions.OptInOC, approvalOps.Program, clearstateOps.Program, schema, schema, nil, nil, nil, nil, 0)
	a.NoError(err)
	tx, err = client.FillUnsignedTxTemplate(creator, 0, 0, fee, tx)
	a.NoError(err)
	wh, err = client.GetUnencryptedWalletHandle()
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

	logs := make([]string, 29)
	for i := range logs {
		logs[i] = "a"
	}

	b, err := client.BookkeepingBlock(round)
	for _, ps := range b.Payset {
		ed := ps.ApplyData.EvalDelta
		ok := checkEqual(logs, ed.Logs)
		a.True(ok)
	}

}
