package simulation

import (
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	simulationtesting "github.com/algorand/go-algorand/ledger/simulation/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// > Simulate With Debugger

type simpleDebugger struct {
	beforeTxnCalls int
	afterTxnCalls  int
}

func (d *simpleDebugger) BeforeTxn(ep *logic.EvalParams, groupIndex int) error {
	d.beforeTxnCalls++
	return nil
}
func (d *simpleDebugger) AfterTxn(ep *logic.EvalParams, groupIndex int) error {
	d.afterTxnCalls++
	return nil
}

// TestSimulateWithDebugger is a simple test to ensure that the debugger hooks are called. More
// complicated tests are in the logic/debugger_test.go file.
func TestSimulateWithDebugger(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	l, accounts, makeTxnHeader := simulationtesting.PrepareSimulatorTest(t)
	defer l.Close()
	s := MakeSimulator(l)
	sender := accounts[0].Addr
	senderBalance := accounts[0].AcctData.MicroAlgos
	amount := senderBalance.Raw - 10000

	txgroup := []transactions.SignedTxn{
		{
			Txn: transactions.Transaction{
				Type:   protocol.PaymentTx,
				Header: makeTxnHeader(sender),
				PaymentTxnFields: transactions.PaymentTxnFields{
					Receiver: sender,
					Amount:   basics.MicroAlgos{Raw: amount},
				},
			},
		},
	}

	// ALSO GENERAL TODO: satisfy review dog: https://github.com/algorand/go-algorand/runs/8006484689?check_suite_focus=true

	debugger := simpleDebugger{}
	_, _, err := s.simulateWithDebugger(txgroup, &debugger)
	require.NoError(t, err)
	require.Equal(t, 1, debugger.beforeTxnCalls)
	require.Equal(t, 1, debugger.afterTxnCalls)
}
