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

package simulate

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"

	helper "github.com/algorand/go-algorand/test/e2e-go/restAPI"
)

func TestSimulateTxnTracerDevMode(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "DevModeTxnTracerNetwork.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	_, err := testClient.Status()
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	senderBalance, senderAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	if senderAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	toAddress := helper.GetDestAddr(t, testClient, nil, senderAddress, wh)
	closeToAddress := helper.GetDestAddr(t, testClient, nil, senderAddress, wh)

	// Ensure these accounts don't exist
	receiverBalance, err := testClient.GetBalance(toAddress)
	a.NoError(err)
	a.Zero(receiverBalance)
	closeToBalance, err := testClient.GetBalance(closeToAddress)
	a.NoError(err)
	a.Zero(closeToBalance)

	txn, err := testClient.ConstructPayment(senderAddress, toAddress, 0, senderBalance/2, nil, closeToAddress, [32]byte{}, 0, 0)
	a.NoError(err)
	stxn, err := testClient.SignTransactionWithWallet(wh, nil, txn)
	a.NoError(err)

	currentRoundBeforeSimulate, err := testClient.CurrentRound()
	a.NoError(err)

	simulateRequest := v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{
				Txns: []transactions.SignedTxn{stxn},
			},
		},
	}
	result, err := testClient.SimulateTransactions(simulateRequest)
	a.NoError(err)

	currentAfterAfterSimulate, err := testClient.CurrentRound()
	a.NoError(err)

	// We can assert equality here since DevMode rounds are controlled by txn sends.
	a.Equal(result.LastRound, currentRoundBeforeSimulate)
	a.Equal(result.LastRound, currentAfterAfterSimulate)

	closingAmount := senderBalance - txn.Fee.Raw - txn.Amount.Raw
	expectedResult := v2.PreEncodedSimulateResponse{
		Version:   2,
		LastRound: result.LastRound, // checked above
		TxnGroups: []v2.PreEncodedSimulateTxnGroupResult{
			{
				Txns: []v2.PreEncodedSimulateTxnResult{
					{
						Txn: v2.PreEncodedTxInfo{
							Txn:           stxn,
							ClosingAmount: &closingAmount,
						},
					},
				},
			},
		},
	}
	a.Equal(expectedResult, result)

	// Ensure the transaction did not actually get applied to the ledger
	receiverBalance, err = testClient.GetBalance(toAddress)
	a.NoError(err)
	a.Zero(receiverBalance)
	closeToBalance, err = testClient.GetBalance(closeToAddress)
	a.NoError(err)
	a.Zero(closeToBalance)
}

func TestSimulateTransaction(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	_, err := testClient.WaitForRound(1)
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	senderBalance, senderAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	if senderAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	toAddress := helper.GetDestAddr(t, testClient, nil, senderAddress, wh)
	closeToAddress := helper.GetDestAddr(t, testClient, nil, senderAddress, wh)

	// Ensure these accounts don't exist
	receiverBalance, err := testClient.GetBalance(toAddress)
	a.NoError(err)
	a.Zero(receiverBalance)
	closeToBalance, err := testClient.GetBalance(closeToAddress)
	a.NoError(err)
	a.Zero(closeToBalance)

	txn, err := testClient.ConstructPayment(senderAddress, toAddress, 0, senderBalance/2, nil, closeToAddress, [32]byte{}, 0, 0)
	a.NoError(err)
	stxn, err := testClient.SignTransactionWithWallet(wh, nil, txn)
	a.NoError(err)

	currentRoundBeforeSimulate, err := testClient.CurrentRound()
	a.NoError(err)

	simulateRequest := v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{
				Txns: []transactions.SignedTxn{stxn},
			},
		},
	}
	result, err := testClient.SimulateTransactions(simulateRequest)
	a.NoError(err)

	currentAfterAfterSimulate, err := testClient.CurrentRound()
	a.NoError(err)

	// To reduce flakiness, only check the round from simulate is within a range.
	a.GreaterOrEqual(result.LastRound, currentRoundBeforeSimulate)
	a.LessOrEqual(result.LastRound, currentAfterAfterSimulate)

	closingAmount := senderBalance - txn.Fee.Raw - txn.Amount.Raw
	expectedResult := v2.PreEncodedSimulateResponse{
		Version:   2,
		LastRound: result.LastRound, // checked above
		TxnGroups: []v2.PreEncodedSimulateTxnGroupResult{
			{
				Txns: []v2.PreEncodedSimulateTxnResult{
					{
						Txn: v2.PreEncodedTxInfo{
							Txn:           stxn,
							ClosingAmount: &closingAmount,
						},
					},
				},
			},
		},
	}
	a.Equal(expectedResult, result)

	// Ensure the transaction did not actually get applied to the ledger
	receiverBalance, err = testClient.GetBalance(toAddress)
	a.NoError(err)
	a.Zero(receiverBalance)
	closeToBalance, err = testClient.GetBalance(closeToAddress)
	a.NoError(err)
	a.Zero(closeToBalance)
}

func TestSimulateStartRound(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesFollower100Second.json"))
	defer fixture.Shutdown()

	// Get controller for Primary node
	nc, err := fixture.GetNodeController("Primary")
	a.NoError(err)

	testClient := fixture.LibGoalClient

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, senderAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	if senderAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	approvalSrc := `#pragma version 8
global Round
itob
log
int 1`
	clearStateSrc := `#pragma version 8
int 1`
	ops, err := logic.AssembleString(approvalSrc)
	a.NoError(err)
	approval := ops.Program
	ops, err = logic.AssembleString(clearStateSrc)
	a.NoError(err)
	clearState := ops.Program

	txn, err := testClient.MakeUnsignedApplicationCallTx(
		0, nil, libgoal.RefBundle{}, transactions.NoOpOC,
		approval, clearState, basics.StateSchema{}, basics.StateSchema{}, 0, 0,
	)
	a.NoError(err)
	txn, err = testClient.FillUnsignedTxTemplate(senderAddress, 1, 1001, 0, txn)
	a.NoError(err)
	stxn, err := testClient.SignTransactionWithWallet(wh, nil, txn)
	a.NoError(err)

	// Get controller for follower node
	followControl, err := fixture.GetNodeController("Follower")
	a.NoError(err)
	followClient := fixture.GetAlgodClientForController(followControl)

	// Set sync round on follower
	const followerSyncRound basics.Round = 4
	err = followClient.SetSyncRound(followerSyncRound)
	a.NoError(err)

	cfg, err := config.LoadConfigFromDisk(followControl.GetDataDir())
	a.NoError(err)

	// Let the primary node make some progress
	primaryClient := fixture.GetAlgodClientForController(nc)
	err = primaryClient.WaitForRoundWithTimeout(followerSyncRound + basics.Round(cfg.MaxAcctLookback))
	a.NoError(err)

	// Let follower node progress as far as it can
	err = followClient.WaitForRoundWithTimeout(followerSyncRound + basics.Round(cfg.MaxAcctLookback) - 1)
	a.NoError(err)

	simulateRequest := v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{
				Txns: []transactions.SignedTxn{stxn},
			},
		},
	}

	// Simulate transactions against the follower node
	simulateTransactions := func(request v2.PreEncodedSimulateRequest) (result v2.PreEncodedSimulateResponse, err error) {
		encodedRequest := protocol.EncodeReflect(&request)
		var resp []byte
		resp, err = followClient.RawSimulateRawTransaction(encodedRequest)
		if err != nil {
			return
		}
		err = protocol.DecodeReflect(resp, &result)
		return
	}

	// Test default behavior (should use latest round available)
	result, err := simulateTransactions(simulateRequest)
	a.NoError(err)
	a.Len(result.TxnGroups, 1)
	a.Empty(result.TxnGroups[0].FailureMessage)
	a.Len(result.TxnGroups[0].Txns, 1)
	a.NotNil(result.TxnGroups[0].Txns[0].Txn.Logs)
	a.Len(*result.TxnGroups[0].Txns[0].Txn.Logs, 1)
	a.EqualValues(followerSyncRound+basics.Round(cfg.MaxAcctLookback), binary.BigEndian.Uint64((*result.TxnGroups[0].Txns[0].Txn.Logs)[0]))

	// Test with previous rounds
	for i := range basics.Round(cfg.MaxAcctLookback) {
		simulateRequest.Round = followerSyncRound + i
		result, err = simulateTransactions(simulateRequest)
		a.NoError(err)
		a.Len(result.TxnGroups, 1)
		a.Empty(result.TxnGroups[0].FailureMessage)
		a.Len(result.TxnGroups[0].Txns, 1)
		a.NotNil(result.TxnGroups[0].Txns[0].Txn.Logs)
		a.Len(*result.TxnGroups[0].Txns[0].Txn.Logs, 1)
		a.LessOrEqual(followerSyncRound+i+1, binary.BigEndian.Uint64((*result.TxnGroups[0].Txns[0].Txn.Logs)[0]))
	}

	// If the round is too far back, we should get an error saying so.
	simulateRequest.Round = followerSyncRound - 3
	endTime := time.Now().Add(6 * time.Second)
	for {
		result, err = simulateTransactions(simulateRequest)
		if err != nil || endTime.After(time.Now()) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err == nil {
		// NOTE: The ledger can have variability in when it commits rounds to the database. It's
		// possible that older rounds are still available because of this. If so, let's bail on the
		// test.
		t.Logf("Still producing a result for round %d", simulateRequest.Round)
		return
	}
	var httpErr client.HTTPError
	a.ErrorAs(err, &httpErr)
	a.Equal(http.StatusInternalServerError, httpErr.StatusCode)
	a.Contains(httpErr.ErrorString, fmt.Sprintf("round %d before dbRound", simulateRequest.Round))
}

func TestSimulateWithOptionalSignatures(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	_, err := testClient.WaitForRound(1)
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, senderAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	if senderAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	txn, err := testClient.ConstructPayment(senderAddress, senderAddress, 0, 1, nil, "", [32]byte{}, 0, 0)
	a.NoError(err)

	simulateRequest := v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{
				Txns: []transactions.SignedTxn{{Txn: txn}}, // no signature
			},
		},
		AllowEmptySignatures: true,
	}
	result, err := testClient.SimulateTransactions(simulateRequest)
	a.NoError(err)

	allowEmptySignatures := true
	expectedResult := v2.PreEncodedSimulateResponse{
		Version:   2,
		LastRound: result.LastRound,
		TxnGroups: []v2.PreEncodedSimulateTxnGroupResult{
			{
				Txns: []v2.PreEncodedSimulateTxnResult{
					{
						Txn: v2.PreEncodedTxInfo{
							Txn: transactions.SignedTxn{Txn: txn},
						},
					},
				},
			},
		},
		EvalOverrides: &model.SimulationEvalOverrides{
			AllowEmptySignatures: &allowEmptySignatures,
		},
	}
	a.Equal(expectedResult, result)
}

func TestSimulateWithUnlimitedLog(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	_, err := testClient.WaitForRound(1)
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, senderAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	if senderAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	// construct program that uses a lot of log
	prog := `#pragma version 8
txn NumAppArgs
int 0
==
bnz final
`
	for i := 0; i < 17; i++ {
		prog += `byte "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
log
`
	}
	prog += `final:
int 1`
	ops, err := logic.AssembleString(prog)
	a.NoError(err)
	approval := ops.Program
	ops, err = logic.AssembleString("#pragma version 8\nint 1")
	a.NoError(err)
	clearState := ops.Program

	gl := basics.StateSchema{}
	lc := basics.StateSchema{}

	// create app
	appCreateTxn, err := testClient.MakeUnsignedApplicationCallTx(
		0, nil, libgoal.RefBundle{}, transactions.NoOpOC,
		approval, clearState, gl, lc, 0, 0,
	)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)
	// sign and broadcast
	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	submittedAppCreateTxn, err := helper.WaitForTransaction(t, testClient, appCreateTxID, 30*time.Second)
	a.NoError(err)

	// get app ID
	a.NotNil(submittedAppCreateTxn.ApplicationIndex)
	createdAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)
	a.NotZero(createdAppID)

	// fund app account
	appFundTxn, err := testClient.SendPaymentFromWallet(
		wh, nil, senderAddress, createdAppID.Address().String(),
		0, 10_000_000, nil, "", 0, 0,
	)
	a.NoError(err)
	appFundTxID := appFundTxn.ID()
	_, err = helper.WaitForTransaction(t, testClient, appFundTxID.String(), 30*time.Second)
	a.NoError(err)

	// construct app call
	appCallTxn, err := testClient.MakeUnsignedAppNoOpTx(
		createdAppID, [][]byte{[]byte("first-arg")}, libgoal.RefBundle{}, 0,
	)
	a.NoError(err)
	appCallTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, appCallTxn)
	a.NoError(err)
	appCallTxnSigned, err := testClient.SignTransactionWithWallet(wh, nil, appCallTxn)
	a.NoError(err)

	resp, err := testClient.SimulateTransactions(v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{
				Txns: []transactions.SignedTxn{appCallTxnSigned},
			},
		},
		AllowMoreLogging: true,
	})
	a.NoError(err)

	var logs [][]byte
	for i := 0; i < 17; i++ {
		logs = append(logs, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	}

	budgetAdded, budgetUsed := 700, 40
	maxLogSize, maxLogCalls := 65536, 2048

	expectedResult := v2.PreEncodedSimulateResponse{
		Version:   2,
		LastRound: resp.LastRound,
		EvalOverrides: &model.SimulationEvalOverrides{
			MaxLogSize:  &maxLogSize,
			MaxLogCalls: &maxLogCalls,
		},
		TxnGroups: []v2.PreEncodedSimulateTxnGroupResult{
			{
				Txns: []v2.PreEncodedSimulateTxnResult{
					{
						Txn: v2.PreEncodedTxInfo{
							Txn:  appCallTxnSigned,
							Logs: &logs,
						},
						AppBudgetConsumed: &budgetUsed,
					},
				},
				AppBudgetAdded:    &budgetAdded,
				AppBudgetConsumed: &budgetUsed,
			},
		},
	}
	a.Equal(expectedResult, resp)
}

func TestSimulateWithExtraBudget(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	_, err := testClient.WaitForRound(1)
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, senderAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	if senderAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	// construct program that uses a lot of budget
	prog := `#pragma version 8
txn ApplicationID
bz end
`
	prog += strings.Repeat(`int 1; pop; `, 700)
	prog += `end:
int 1`

	ops, err := logic.AssembleString(prog)
	a.NoError(err)
	approval := ops.Program
	ops, err = logic.AssembleString("#pragma version 8\nint 1")
	a.NoError(err)
	clearState := ops.Program

	gl := basics.StateSchema{}
	lc := basics.StateSchema{}

	// create app
	appCreateTxn, err := testClient.MakeUnsignedApplicationCallTx(
		0, nil, libgoal.RefBundle{}, transactions.NoOpOC,
		approval, clearState, gl, lc, 0, 0,
	)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)
	// sign and broadcast
	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	submittedAppCreateTxn, err := helper.WaitForTransaction(t, testClient, appCreateTxID, 30*time.Second)
	a.NoError(err)

	// get app ID
	a.NotNil(submittedAppCreateTxn.ApplicationIndex)
	createdAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)
	a.NotZero(createdAppID)

	// fund app account
	appFundTxn, err := testClient.SendPaymentFromWallet(
		wh, nil, senderAddress, createdAppID.Address().String(),
		0, 10_000_000, nil, "", 0, 0,
	)
	a.NoError(err)
	appFundTxID := appFundTxn.ID()
	_, err = helper.WaitForTransaction(t, testClient, appFundTxID.String(), 30*time.Second)
	a.NoError(err)

	// construct app call
	appCallTxn, err := testClient.MakeUnsignedAppNoOpTx(
		createdAppID, nil, libgoal.RefBundle{}, 0,
	)
	a.NoError(err)
	appCallTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, appCallTxn)
	a.NoError(err)
	appCallTxnSigned, err := testClient.SignTransactionWithWallet(wh, nil, appCallTxn)
	a.NoError(err)

	extraBudget := 704
	resp, err := testClient.SimulateTransactions(v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{
				Txns: []transactions.SignedTxn{appCallTxnSigned},
			},
		},
		ExtraOpcodeBudget: extraBudget,
	})
	a.NoError(err)

	budgetAdded, budgetUsed := 1404, 1404

	expectedResult := v2.PreEncodedSimulateResponse{
		Version:       2,
		LastRound:     resp.LastRound,
		EvalOverrides: &model.SimulationEvalOverrides{ExtraOpcodeBudget: &extraBudget},
		TxnGroups: []v2.PreEncodedSimulateTxnGroupResult{
			{
				Txns: []v2.PreEncodedSimulateTxnResult{
					{
						Txn:               v2.PreEncodedTxInfo{Txn: appCallTxnSigned},
						AppBudgetConsumed: &budgetUsed,
					},
				},
				AppBudgetAdded:    &budgetAdded,
				AppBudgetConsumed: &budgetUsed,
			},
		},
	}
	a.Equal(expectedResult, resp)
}

func toPtr[T any](constVar T) *T { return &constVar }

func valToNil[T comparable](v *T) *T {
	var defaultV T
	if v == nil || *v == defaultV {
		return nil
	}
	return v
}

// The program is copied from pyteal source for c2c test over betanet:
// source: https://github.com/ahangsu/c2c-testscript/blob/master/c2c_test/max_depth/app.py
const maxDepthTealApproval = `#pragma version 8
txn ApplicationID
int 0
==
bnz main_l6
txn NumAppArgs
int 1
==
bnz main_l3
err
main_l3:
global CurrentApplicationID
app_params_get AppApprovalProgram
store 1
store 0
global CurrentApplicationID
app_params_get AppClearStateProgram
store 3
store 2
global CurrentApplicationAddress
acct_params_get AcctBalance
store 5
store 4
load 1
assert
load 3
assert
load 5
assert
int 2
txna ApplicationArgs 0
btoi
exp
itob
log
txna ApplicationArgs 0
btoi
int 0
>
bnz main_l5
main_l4:
int 1
return
main_l5:
itxn_begin
  int appl
  itxn_field TypeEnum
  int 0
  itxn_field Fee
  load 0
  itxn_field ApprovalProgram
  load 2
  itxn_field ClearStateProgram
itxn_submit
itxn_begin
  int pay
  itxn_field TypeEnum
  int 0
  itxn_field Fee
  load 4
  int 100000
  -
  itxn_field Amount
  byte "appID"
  gitxn 0 CreatedApplicationID
  itob
  concat
  sha512_256
  itxn_field Receiver
itxn_next
  int appl
  itxn_field TypeEnum
  txna ApplicationArgs 0
  btoi
  int 1
  -
  itob
  itxn_field ApplicationArgs
  itxn CreatedApplicationID
  itxn_field ApplicationID
  int 0
  itxn_field Fee
  int DeleteApplication
  itxn_field OnCompletion
itxn_submit
b main_l4
main_l6:
int 1
return`

func goValuesToAvmValues(goValues ...interface{}) *[]model.AvmValue {
	if len(goValues) == 0 {
		return nil
	}

	boolToUint64 := func(b bool) uint64 {
		if b {
			return 1
		}
		return 0
	}

	modelValues := make([]model.AvmValue, len(goValues))
	for i, goValue := range goValues {
		switch converted := goValue.(type) {
		case []byte:
			modelValues[i] = model.AvmValue{
				Type:  uint64(basics.TealBytesType),
				Bytes: &converted,
			}
		case bool:
			convertedUint := boolToUint64(converted)
			modelValues[i] = model.AvmValue{
				Type: uint64(basics.TealUintType),
				Uint: valToNil(&convertedUint),
			}
		case int:
			convertedUint := uint64(converted)
			modelValues[i] = model.AvmValue{
				Type: uint64(basics.TealUintType),
				Uint: valToNil(&convertedUint),
			}
		case basics.AppIndex:
			convertedUint := uint64(converted)
			modelValues[i] = model.AvmValue{
				Type: uint64(basics.TealUintType),
				Uint: valToNil(&convertedUint),
			}
		case uint64:
			modelValues[i] = model.AvmValue{
				Type: uint64(basics.TealUintType),
				Uint: valToNil(&converted),
			}
		default:
			panic("unexpected type inferred from interface{}")
		}
	}
	return &modelValues
}

func TestMaxDepthAppWithPCandStackTrace(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.SetupNoStart(t, filepath.Join("nettemplates", "OneNodeFuture.json"))

	primaryNode, err := localFixture.GetNodeController("Primary")
	a.NoError(err)

	localFixture.Start()
	defer primaryNode.FullStop()

	// get lib goal client
	testClient := localFixture.LibGoalFixture.GetLibGoalClientFromNodeController(primaryNode)

	_, err = testClient.WaitForRound(1)
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, senderAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	a.NotEmpty(senderAddress, "no addr with funds")
	a.NoError(err)

	ops, err := logic.AssembleString(maxDepthTealApproval)
	a.NoError(err)
	approval := ops.Program
	approvalHash := crypto.Hash(approval)
	ops, err = logic.AssembleString("#pragma version 8\nint 1")
	a.NoError(err)
	clearState := ops.Program

	gl := basics.StateSchema{}
	lc := basics.StateSchema{}

	MaxDepth := 2
	MinFee := config.Consensus[protocol.ConsensusFuture].MinTxnFee
	MinBalance := config.Consensus[protocol.ConsensusFuture].MinBalance

	// create app and get the application ID
	appCreateTxn, err := testClient.MakeUnsignedAppCreateTx(
		transactions.NoOpOC, approval, clearState, gl,
		lc, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)

	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	submittedAppCreateTxn, err := helper.WaitForTransaction(t, testClient, appCreateTxID, 30*time.Second)
	a.NoError(err)
	futureAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)

	// fund app account
	appFundTxn, err := testClient.ConstructPayment(
		senderAddress, futureAppID.Address().String(),
		0, MinBalance*uint64(MaxDepth+1), nil, "", [32]byte{}, 0, 0,
	)
	a.NoError(err)

	uint64ToBytes := func(v uint64) []byte {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		return b
	}

	// construct app calls
	appCallTxn, err := testClient.MakeUnsignedAppNoOpTx(
		futureAppID, [][]byte{uint64ToBytes(uint64(MaxDepth))}, libgoal.RefBundle{}, 0,
	)
	a.NoError(err)
	appCallTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, MinFee*uint64(3*MaxDepth+2), appCallTxn)
	a.NoError(err)

	// Group the transactions, and start the simulation
	gid, err := testClient.GroupID([]transactions.Transaction{appFundTxn, appCallTxn})
	a.NoError(err)
	appFundTxn.Group = gid
	appCallTxn.Group = gid

	appFundTxnSigned, err := testClient.SignTransactionWithWallet(wh, nil, appFundTxn)
	a.NoError(err)
	appCallTxnSigned, err := testClient.SignTransactionWithWallet(wh, nil, appCallTxn)
	a.NoError(err)

	// The first simulation should not pass, for simulation return PC in config has not been activated
	execTraceConfig := simulation.ExecTraceConfig{
		Enable: true,
		Stack:  true,
	}
	simulateRequest := v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{Txns: []transactions.SignedTxn{appFundTxnSigned, appCallTxnSigned}},
		},
		ExecTraceConfig: execTraceConfig,
	}

	_, err = testClient.SimulateTransactions(simulateRequest)
	var httpError client.HTTPError
	a.ErrorAs(err, &httpError)
	a.Equal(http.StatusBadRequest, httpError.StatusCode)
	a.Contains(httpError.ErrorString, "the local configuration of the node has `EnableDeveloperAPI` turned off, while requesting for execution trace")

	// update the configuration file to enable EnableDeveloperAPI
	err = primaryNode.FullStop()
	a.NoError(err)
	cfg, err := config.LoadConfigFromDisk(primaryNode.GetDataDir())
	a.NoError(err)
	cfg.EnableDeveloperAPI = true
	err = cfg.SaveToDisk(primaryNode.GetDataDir())
	require.NoError(t, err)
	localFixture.Start()

	resp, err := testClient.SimulateTransactions(simulateRequest)
	a.NoError(err)

	// Check expected == actual
	creationOpcodeTrace := []model.SimulationOpcodeTraceUnit{
		{
			Pc: 1,
		},
		// txn ApplicationID
		{
			Pc:             6,
			StackAdditions: goValuesToAvmValues(0),
		},
		// int 0
		{
			Pc:             8,
			StackAdditions: goValuesToAvmValues(0),
		},
		// ==
		{
			Pc:             9,
			StackPopCount:  toPtr(2),
			StackAdditions: goValuesToAvmValues(1),
		},
		// bnz main_l6
		{
			Pc:            10,
			StackPopCount: toPtr(1),
		},
		// int 1
		{
			Pc:             149,
			StackAdditions: goValuesToAvmValues(1),
		},
		// return
		{
			Pc:             150,
			StackAdditions: goValuesToAvmValues(1),
			StackPopCount:  toPtr(1),
		},
	}

	const NumArgs = 1

	recursiveLongOpcodeTrace := func(appID basics.AppIndex, layer int) *[]model.SimulationOpcodeTraceUnit {
		return &[]model.SimulationOpcodeTraceUnit{
			{
				Pc: 1,
			},
			// txn ApplicationID
			{
				Pc:             6,
				StackAdditions: goValuesToAvmValues(appID),
			},
			// int 0
			{
				Pc:             8,
				StackAdditions: goValuesToAvmValues(0),
			},
			// ==
			{
				Pc:             9,
				StackAdditions: goValuesToAvmValues(false),
				StackPopCount:  toPtr(2),
			},
			// bnz main_l6
			{
				Pc:            10,
				StackPopCount: toPtr(1),
			},
			// txn NumAppArgs
			{
				Pc:             13,
				StackAdditions: goValuesToAvmValues(NumArgs),
			},
			// int 1
			{
				Pc:             15,
				StackAdditions: goValuesToAvmValues(1),
			},
			// ==
			{
				Pc:             16,
				StackPopCount:  toPtr(2),
				StackAdditions: goValuesToAvmValues(true),
			},
			// bnz main_l3
			{
				Pc:            17,
				StackPopCount: toPtr(1),
			},
			// global CurrentApplicationID
			{
				Pc:             21,
				StackAdditions: goValuesToAvmValues(appID),
			},
			// app_params_get AppApprovalProgram
			{
				Pc:             23,
				StackAdditions: goValuesToAvmValues(approval, 1),
				StackPopCount:  toPtr(1),
			},
			// store 1
			{
				Pc:            25,
				StackPopCount: toPtr(1),
			},
			// store 0
			{
				Pc:            27,
				StackPopCount: toPtr(1),
			},
			// global CurrentApplicationID
			{
				Pc:             29,
				StackAdditions: goValuesToAvmValues(appID),
			},
			// app_params_get AppClearStateProgram
			{
				Pc:             31,
				StackAdditions: goValuesToAvmValues(clearState, 1),
				StackPopCount:  toPtr(1),
			},
			// store 3
			{
				Pc:            33,
				StackPopCount: toPtr(1),
			},
			// store 2
			{
				Pc:            35,
				StackPopCount: toPtr(1),
			},
			// global CurrentApplicationAddress
			{
				Pc:             37,
				StackAdditions: goValuesToAvmValues(crypto.Digest(appID.Address()).ToSlice()),
			},
			// acct_params_get AcctBalance
			{
				Pc:             39,
				StackAdditions: goValuesToAvmValues(uint64(3-layer)*MinBalance, 1),
				StackPopCount:  toPtr(1),
			},
			// store 5
			{
				Pc:            41,
				StackPopCount: toPtr(1),
			},
			// store 4
			{
				Pc:            43,
				StackPopCount: toPtr(1),
			},
			// load 1
			{
				Pc:             45,
				StackAdditions: goValuesToAvmValues(1),
			},
			// assert
			{
				Pc:            47,
				StackPopCount: toPtr(1),
			},
			// load 3
			{
				Pc:             48,
				StackAdditions: goValuesToAvmValues(1),
			},
			// assert
			{
				Pc:            50,
				StackPopCount: toPtr(1),
			},
			// load 5
			{
				Pc:             51,
				StackAdditions: goValuesToAvmValues(1),
			},
			// assert
			{
				Pc:            53,
				StackPopCount: toPtr(1),
			},
			// int 2
			{
				Pc:             54,
				StackAdditions: goValuesToAvmValues(2),
			},
			// txna ApplicationArgs 0
			{
				Pc:             56,
				StackAdditions: goValuesToAvmValues(uint64ToBytes(uint64(MaxDepth - layer))),
			},
			// btoi
			{
				Pc:             59,
				StackAdditions: goValuesToAvmValues(uint64(MaxDepth - layer)),
				StackPopCount:  toPtr(1),
			},
			// exp
			{
				Pc:             60,
				StackAdditions: goValuesToAvmValues(1 << (MaxDepth - layer)),
				StackPopCount:  toPtr(2),
			},
			// itob
			{
				Pc:             61,
				StackAdditions: goValuesToAvmValues(uint64ToBytes(1 << uint64(MaxDepth-layer))),
				StackPopCount:  toPtr(1),
			},
			// log
			{
				Pc:            62,
				StackPopCount: toPtr(1),
			},
			// txna ApplicationArgs 0
			{
				Pc:             63,
				StackAdditions: goValuesToAvmValues(uint64ToBytes(uint64(MaxDepth - layer))),
			},
			// btoi
			{
				Pc:             66,
				StackAdditions: goValuesToAvmValues(MaxDepth - layer),
				StackPopCount:  toPtr(1),
			},
			// int 0
			{
				Pc:             67,
				StackAdditions: goValuesToAvmValues(0),
			},
			// >
			{
				Pc:             68,
				StackAdditions: goValuesToAvmValues(MaxDepth-layer > 0),
				StackPopCount:  toPtr(2),
			},
			// bnz main_l5
			{
				Pc:            69,
				StackPopCount: toPtr(1),
			},
			// itxn_begin
			{
				Pc: 74,
			},
			// int appl
			{
				Pc:             75,
				StackAdditions: goValuesToAvmValues(6),
			},
			// itxn_field TypeEnum
			{
				Pc:            76,
				StackPopCount: toPtr(1),
			},
			// int 0
			{
				Pc:             78,
				StackAdditions: goValuesToAvmValues(0),
			},
			// itxn_field Fee
			{
				Pc:            79,
				StackPopCount: toPtr(1),
			},
			// load 0
			{
				Pc:             81,
				StackAdditions: goValuesToAvmValues(approval),
			},
			// itxn_field ApprovalProgram
			{
				Pc:            83,
				StackPopCount: toPtr(1),
			},
			// load 2
			{
				Pc:             85,
				StackAdditions: goValuesToAvmValues(clearState),
			},
			// itxn_field ClearStateProgram
			{
				Pc:            87,
				StackPopCount: toPtr(1),
			},
			// itxn_submit
			{
				Pc:            89,
				SpawnedInners: &[]int{0},
			},
			// itxn_begin
			{
				Pc: 90,
			},
			// int pay
			{
				Pc:             91,
				StackAdditions: goValuesToAvmValues(1),
			},
			// itxn_field TypeEnum
			{
				Pc:            92,
				StackPopCount: toPtr(1),
			},
			// int 0
			{
				Pc:             94,
				StackAdditions: goValuesToAvmValues(0),
			},
			// itxn_field Fee
			{
				Pc:            95,
				StackPopCount: toPtr(1),
			},
			// load 4
			{
				Pc:             97,
				StackAdditions: goValuesToAvmValues(uint64(3-layer) * MinBalance),
			},
			// int 100000
			{
				Pc:             99,
				StackAdditions: goValuesToAvmValues(MinBalance),
			},
			// -
			{
				Pc:             103,
				StackPopCount:  toPtr(2),
				StackAdditions: goValuesToAvmValues(uint64(2-layer) * MinBalance),
			},
			// itxn_field Amount
			{
				Pc:            104,
				StackPopCount: toPtr(1),
			},
			// byte "appID"
			{
				Pc:             106,
				StackAdditions: goValuesToAvmValues([]byte("appID")),
			},
			// gitxn 0 CreatedApplicationID
			{
				Pc:             113,
				StackAdditions: goValuesToAvmValues(appID + 3),
			},
			// itob
			{
				Pc:             116,
				StackAdditions: goValuesToAvmValues(uint64ToBytes(uint64(appID) + 3)),
				StackPopCount:  toPtr(1),
			},
			// concat
			{
				Pc:             117,
				StackAdditions: goValuesToAvmValues([]byte("appID" + string(uint64ToBytes(uint64(appID)+3)))),
				StackPopCount:  toPtr(2),
			},
			// sha512_256
			{
				Pc:             118,
				StackAdditions: goValuesToAvmValues(crypto.Digest((appID + 3).Address()).ToSlice()),
				StackPopCount:  toPtr(1),
			},
			// itxn_field Receiver
			{
				Pc:            119,
				StackPopCount: toPtr(1),
			},
			{
				Pc: 121,
			},
			// int appl
			{
				Pc:             122,
				StackAdditions: goValuesToAvmValues(6),
			},
			// itxn_field TypeEnum
			{
				Pc:            123,
				StackPopCount: toPtr(1),
			},
			// txna ApplicationArgs 0
			{
				Pc:             125,
				StackAdditions: goValuesToAvmValues(uint64ToBytes(uint64(MaxDepth - layer))),
			},
			// btoi
			{
				Pc:             128,
				StackAdditions: goValuesToAvmValues(MaxDepth - layer),
				StackPopCount:  toPtr(1),
			},
			// int 1
			{
				Pc:             129,
				StackAdditions: goValuesToAvmValues(1),
			},
			// -
			{
				Pc:             130,
				StackAdditions: goValuesToAvmValues(MaxDepth - layer - 1),
				StackPopCount:  toPtr(2),
			},
			// itob
			{
				Pc:             131,
				StackAdditions: goValuesToAvmValues(uint64ToBytes(uint64(MaxDepth - layer - 1))),
				StackPopCount:  toPtr(1),
			},
			// itxn_field ApplicationArgs
			{
				Pc:            132,
				StackPopCount: toPtr(1),
			},
			// itxn CreatedApplicationID
			{
				Pc:             134,
				StackAdditions: goValuesToAvmValues(appID + 3),
			},
			// itxn_field ApplicationID
			{
				Pc:            136,
				StackPopCount: toPtr(1),
			},
			// int 0
			{
				Pc:             138,
				StackAdditions: goValuesToAvmValues(0),
			},
			// itxn_field Fee
			{
				Pc:            139,
				StackPopCount: toPtr(1),
			},
			// int DeleteApplication
			{
				Pc:             141,
				StackAdditions: goValuesToAvmValues(5),
			},
			// itxn_field OnCompletion
			{
				Pc:            143,
				StackPopCount: toPtr(1),
			},
			// itxn_submit
			{
				Pc:            145,
				SpawnedInners: &[]int{1, 2},
			},
			// b main_l4
			{
				Pc: 146,
			},
			// int 1
			{
				Pc:             72,
				StackAdditions: goValuesToAvmValues(1),
			},
			// return
			{
				Pc:             73,
				StackAdditions: goValuesToAvmValues(1),
				StackPopCount:  toPtr(1),
			},
		}
	}

	finalDepthTrace := func(appID basics.AppIndex, layer int) *[]model.SimulationOpcodeTraceUnit {
		return &[]model.SimulationOpcodeTraceUnit{
			{
				Pc: 1,
			},
			// txn ApplicationID
			{
				Pc:             6,
				StackAdditions: goValuesToAvmValues(appID),
			},
			// int 0
			{
				Pc:             8,
				StackAdditions: goValuesToAvmValues(0),
			},
			// ==
			{
				Pc:             9,
				StackAdditions: goValuesToAvmValues(false),
				StackPopCount:  toPtr(2),
			},
			// bnz main_l6
			{
				Pc:            10,
				StackPopCount: toPtr(1),
			},
			// txn NumAppArgs
			{
				Pc:             13,
				StackAdditions: goValuesToAvmValues(NumArgs),
			},
			// int 1
			{
				Pc:             15,
				StackAdditions: goValuesToAvmValues(1),
			},
			// ==
			{
				Pc:             16,
				StackPopCount:  toPtr(2),
				StackAdditions: goValuesToAvmValues(true),
			},
			// bnz main_l3
			{
				Pc:            17,
				StackPopCount: toPtr(1),
			},
			// global CurrentApplicationID
			{
				Pc:             21,
				StackAdditions: goValuesToAvmValues(appID),
			},
			// app_params_get AppApprovalProgram
			{
				Pc:             23,
				StackAdditions: goValuesToAvmValues(approval, 1),
				StackPopCount:  toPtr(1),
			},
			// store 1
			{
				Pc:            25,
				StackPopCount: toPtr(1),
			},
			// store 0
			{
				Pc:            27,
				StackPopCount: toPtr(1),
			},
			// global CurrentApplicationID
			{
				Pc:             29,
				StackAdditions: goValuesToAvmValues(appID),
			},
			// app_params_get AppClearStateProgram
			{
				Pc:             31,
				StackAdditions: goValuesToAvmValues(clearState, 1),
				StackPopCount:  toPtr(1),
			},
			// store 3
			{
				Pc:            33,
				StackPopCount: toPtr(1),
			},
			// store 2
			{
				Pc:            35,
				StackPopCount: toPtr(1),
			},
			// global CurrentApplicationAddress
			{
				Pc:             37,
				StackAdditions: goValuesToAvmValues(crypto.Digest(appID.Address()).ToSlice()),
			},
			// acct_params_get AcctBalance
			{
				Pc:             39,
				StackAdditions: goValuesToAvmValues(uint64(3-layer)*MinBalance, 1),
				StackPopCount:  toPtr(1),
			},
			// store 5
			{
				Pc:            41,
				StackPopCount: toPtr(1),
			},
			// store 4
			{
				Pc:            43,
				StackPopCount: toPtr(1),
			},
			// load 1
			{
				Pc:             45,
				StackAdditions: goValuesToAvmValues(1),
			},
			// assert
			{
				Pc:            47,
				StackPopCount: toPtr(1),
			},
			// load 3
			{
				Pc:             48,
				StackAdditions: goValuesToAvmValues(1),
			},
			// assert
			{
				Pc:            50,
				StackPopCount: toPtr(1),
			},
			// load 5
			{
				Pc:             51,
				StackAdditions: goValuesToAvmValues(1),
			},
			// assert
			{
				Pc:            53,
				StackPopCount: toPtr(1),
			},
			// int 2
			{
				Pc:             54,
				StackAdditions: goValuesToAvmValues(2),
			},
			// txna ApplicationArgs 0
			{
				Pc:             56,
				StackAdditions: goValuesToAvmValues(uint64ToBytes(uint64(MaxDepth - layer))),
			},
			// btoi
			{
				Pc:             59,
				StackAdditions: goValuesToAvmValues(uint64(MaxDepth - layer)),
				StackPopCount:  toPtr(1),
			},
			// exp
			{
				Pc:             60,
				StackAdditions: goValuesToAvmValues(1 << (MaxDepth - layer)),
				StackPopCount:  toPtr(2),
			},
			// itob
			{
				Pc:             61,
				StackAdditions: goValuesToAvmValues(uint64ToBytes(1 << uint64(MaxDepth-layer))),
				StackPopCount:  toPtr(1),
			},
			// log
			{
				Pc:            62,
				StackPopCount: toPtr(1),
			},
			// txna ApplicationArgs 0
			{
				Pc:             63,
				StackAdditions: goValuesToAvmValues(uint64ToBytes(uint64(MaxDepth - layer))),
			},
			// btoi
			{
				Pc:             66,
				StackAdditions: goValuesToAvmValues(MaxDepth - layer),
				StackPopCount:  toPtr(1),
			},
			// int 0
			{
				Pc:             67,
				StackAdditions: goValuesToAvmValues(0),
			},
			// >
			{
				Pc:             68,
				StackAdditions: goValuesToAvmValues(MaxDepth-layer > 0),
				StackPopCount:  toPtr(2),
			},
			// bnz main_l5
			{
				Pc:            69,
				StackPopCount: toPtr(1),
			},
			// int 1
			{
				Pc:             72,
				StackAdditions: goValuesToAvmValues(1),
			},
			// return
			{
				Pc:             73,
				StackAdditions: goValuesToAvmValues(1),
				StackPopCount:  toPtr(1),
			},
		}
	}

	a.Len(resp.TxnGroups[0].Txns, 2)
	a.Nil(resp.TxnGroups[0].FailureMessage)
	a.Nil(resp.TxnGroups[0].FailedAt)

	a.Nil(resp.TxnGroups[0].Txns[0].TransactionTrace)

	expectedTraceSecondTxn := &model.SimulationTransactionExecTrace{
		ApprovalProgramTrace: recursiveLongOpcodeTrace(futureAppID, 0),
		ApprovalProgramHash:  toPtr(approvalHash.ToSlice()),
		InnerTrace: &[]model.SimulationTransactionExecTrace{
			{
				ApprovalProgramTrace: &creationOpcodeTrace,
				ApprovalProgramHash:  toPtr(approvalHash.ToSlice()),
			},
			{},
			{
				ApprovalProgramTrace: recursiveLongOpcodeTrace(futureAppID+3, 1),
				ApprovalProgramHash:  toPtr(approvalHash.ToSlice()),
				InnerTrace: &[]model.SimulationTransactionExecTrace{
					{
						ApprovalProgramTrace: &creationOpcodeTrace,
						ApprovalProgramHash:  toPtr(approvalHash.ToSlice()),
					},
					{},
					{
						ApprovalProgramTrace: finalDepthTrace(futureAppID+6, 2),
						ApprovalProgramHash:  toPtr(approvalHash.ToSlice()),
					},
				},
			},
		},
	}
	a.Equal(expectedTraceSecondTxn, resp.TxnGroups[0].Txns[1].TransactionTrace)

	a.Equal(execTraceConfig, resp.ExecTraceConfig)
}

func TestSimulateScratchSlotChange(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.SetupNoStart(t, filepath.Join("nettemplates", "OneNodeFuture.json"))

	// Get primary node
	primaryNode, err := localFixture.GetNodeController("Primary")
	a.NoError(err)

	localFixture.Start()
	defer primaryNode.FullStop()

	// get lib goal client
	testClient := localFixture.LibGoalFixture.GetLibGoalClientFromNodeController(primaryNode)

	_, err = testClient.WaitForRound(1)
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, senderAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	a.NotEmpty(senderAddress, "no addr with funds")
	a.NoError(err)

	ops, err := logic.AssembleString(
		`#pragma version 8
		 global CurrentApplicationID
		 bz end
		 int 1
		 store 1
		 load 1
		 dup
		 stores
		end:
		 int 1`)
	a.NoError(err)
	approval := ops.Program
	approvalHash := crypto.Hash(approval)
	ops, err = logic.AssembleString("#pragma version 8\nint 1")
	a.NoError(err)
	clearState := ops.Program

	gl := basics.StateSchema{}
	lc := basics.StateSchema{}

	MinFee := config.Consensus[protocol.ConsensusFuture].MinTxnFee
	MinBalance := config.Consensus[protocol.ConsensusFuture].MinBalance

	// create app and get the application ID
	appCreateTxn, err := testClient.MakeUnsignedAppCreateTx(
		transactions.NoOpOC, approval, clearState, gl,
		lc, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)

	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	submittedAppCreateTxn, err := helper.WaitForTransaction(t, testClient, appCreateTxID, 30*time.Second)
	a.NoError(err)
	futureAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)

	// fund app account
	_, err = testClient.SendPaymentFromWallet(
		wh, nil, senderAddress, futureAppID.Address().String(),
		0, MinBalance, nil, "", 0, 0,
	)
	a.NoError(err)

	// construct app calls
	appCallTxn, err := testClient.MakeUnsignedAppNoOpTx(
		futureAppID, [][]byte{}, libgoal.RefBundle{}, 0,
	)
	a.NoError(err)
	appCallTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, MinFee, appCallTxn)
	a.NoError(err)

	appCallTxnSigned, err := testClient.SignTransactionWithWallet(wh, nil, appCallTxn)
	a.NoError(err)

	// construct simulation request, with scratch slot change enabled
	execTraceConfig := simulation.ExecTraceConfig{
		Enable:  true,
		Scratch: true,
	}
	simulateRequest := v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{Txns: []transactions.SignedTxn{appCallTxnSigned}},
		},
		ExecTraceConfig: execTraceConfig,
	}

	// update the configuration file to enable EnableDeveloperAPI
	err = primaryNode.FullStop()
	a.NoError(err)
	cfg, err := config.LoadConfigFromDisk(primaryNode.GetDataDir())
	a.NoError(err)
	cfg.EnableDeveloperAPI = true
	err = cfg.SaveToDisk(primaryNode.GetDataDir())
	require.NoError(t, err)
	localFixture.Start()

	// simulate with wrong config (not enabled trace), see expected error
	_, err = testClient.SimulateTransactions(v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{Txns: []transactions.SignedTxn{appCallTxnSigned}},
		},
		ExecTraceConfig: simulation.ExecTraceConfig{Scratch: true},
	})
	a.ErrorContains(err, "basic trace must be enabled when enabling scratch slot change tracing")

	// start real simulating
	resp, err := testClient.SimulateTransactions(simulateRequest)
	a.NoError(err)

	// check if resp match expected result
	a.Equal(execTraceConfig, resp.ExecTraceConfig)
	a.Len(resp.TxnGroups[0].Txns, 1)
	a.NotNil(resp.TxnGroups[0].Txns[0].TransactionTrace)

	expectedTraceSecondTxn := &model.SimulationTransactionExecTrace{
		ApprovalProgramTrace: &[]model.SimulationOpcodeTraceUnit{
			{Pc: 1},
			{Pc: 4},
			{Pc: 6},
			{Pc: 9},
			{
				Pc: 10,
				ScratchChanges: &[]model.ScratchChange{
					{
						Slot: 1,
						NewValue: model.AvmValue{
							Type: 2,
							Uint: toPtr[uint64](1),
						},
					},
				},
			},
			{Pc: 12},
			{Pc: 14},
			{
				Pc: 15,
				ScratchChanges: &[]model.ScratchChange{
					{
						Slot: 1,
						NewValue: model.AvmValue{
							Type: 2,
							Uint: toPtr[uint64](1),
						},
					},
				},
			},
			{Pc: 16},
		},
		ApprovalProgramHash: toPtr(approvalHash.ToSlice()),
	}
	a.Equal(expectedTraceSecondTxn, resp.TxnGroups[0].Txns[0].TransactionTrace)
}

func TestSimulateExecTraceStateChange(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.SetupNoStart(t, filepath.Join("nettemplates", "OneNodeFuture.json"))

	// Get primary node
	primaryNode, err := localFixture.GetNodeController("Primary")
	a.NoError(err)

	localFixture.Start()
	defer primaryNode.FullStop()

	// get lib goal client
	testClient := localFixture.LibGoalFixture.GetLibGoalClientFromNodeController(primaryNode)

	_, err = testClient.WaitForRound(1)
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, senderAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	a.NotEmpty(senderAddress, "no addr with funds")

	addressDigest, err := basics.UnmarshalChecksumAddress(senderAddress)
	a.NoError(err)

	ops, err := logic.AssembleString(
		`#pragma version 8
txn ApplicationID
bz end // Do nothing during create

txn OnCompletion
int OptIn
==
bnz end // Always allow optin

byte "local"
byte "global"
txn ApplicationArgs 0
match local global
err // Unknown command

local:
  txn Sender
  byte "local-int-key"
  int 0xcafeb0ba
  app_local_put
  int 0
  byte "local-bytes-key"
  byte "xqcL"
  app_local_put
  b end

global:
  byte "global-int-key"
  int 0xdeadbeef
  app_global_put
  byte "global-bytes-key"
  byte "welt am draht"
  app_global_put
  b end

end:
  int 1`)
	a.NoError(err)
	approval := ops.Program
	approvalHash := crypto.Hash(approval)

	ops, err = logic.AssembleString("#pragma version 8\nint 1")
	a.NoError(err)
	clearState := ops.Program

	gl := basics.StateSchema{NumByteSlice: 1, NumUint: 1}
	lc := basics.StateSchema{NumByteSlice: 1, NumUint: 1}

	MinFee := config.Consensus[protocol.ConsensusFuture].MinTxnFee
	MinBalance := config.Consensus[protocol.ConsensusFuture].MinBalance

	// create app and get the application ID
	appCreateTxn, err := testClient.MakeUnsignedAppCreateTx(
		transactions.NoOpOC, approval, clearState, gl,
		lc, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)

	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	submittedAppCreateTxn, err := helper.WaitForTransaction(t, testClient, appCreateTxID, 30*time.Second)
	a.NoError(err)
	futureAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)

	// fund app account
	_, err = testClient.ConstructPayment(
		senderAddress, futureAppID.Address().String(),
		0, MinBalance*2, nil, "", [32]byte{}, 0, 0,
	)
	a.NoError(err)

	// construct app call "global"
	appCallGlobalTxn, err := testClient.MakeUnsignedAppNoOpTx(
		futureAppID, [][]byte{[]byte("global")}, libgoal.RefBundle{}, 0,
	)
	a.NoError(err)
	appCallGlobalTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, MinFee, appCallGlobalTxn)
	a.NoError(err)
	// construct app optin
	appOptInTxn, err := testClient.MakeUnsignedAppOptInTx(futureAppID, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	appOptInTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, MinFee, appOptInTxn)
	// construct app call "global"
	appCallLocalTxn, err := testClient.MakeUnsignedAppNoOpTx(
		futureAppID, [][]byte{[]byte("local")}, libgoal.RefBundle{}, 0,
	)
	a.NoError(err)
	appCallLocalTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, MinFee, appCallLocalTxn)
	a.NoError(err)

	gid, err := testClient.GroupID([]transactions.Transaction{appCallGlobalTxn, appOptInTxn, appCallLocalTxn})
	a.NoError(err)
	appCallGlobalTxn.Group = gid
	appOptInTxn.Group = gid
	appCallLocalTxn.Group = gid

	appCallTxnGlobalSigned, err := testClient.SignTransactionWithWallet(wh, nil, appCallGlobalTxn)
	a.NoError(err)
	appOptInSigned, err := testClient.SignTransactionWithWallet(wh, nil, appOptInTxn)
	a.NoError(err)
	appCallTxnLocalSigned, err := testClient.SignTransactionWithWallet(wh, nil, appCallLocalTxn)
	a.NoError(err)

	// construct simulation request, with state change enabled
	execTraceConfig := simulation.ExecTraceConfig{
		Enable: true,
		State:  true,
	}
	simulateRequest := v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{Txns: []transactions.SignedTxn{appCallTxnGlobalSigned, appOptInSigned, appCallTxnLocalSigned}},
		},
		ExecTraceConfig: execTraceConfig,
	}

	// update the configuration file to enable EnableDeveloperAPI
	err = primaryNode.FullStop()
	a.NoError(err)
	cfg, err := config.LoadConfigFromDisk(primaryNode.GetDataDir())
	a.NoError(err)
	cfg.EnableDeveloperAPI = true
	err = cfg.SaveToDisk(primaryNode.GetDataDir())
	require.NoError(t, err)
	localFixture.Start()

	// start real simulating
	resp, err := testClient.SimulateTransactions(simulateRequest)
	a.NoError(err)

	// assertions
	a.Len(resp.TxnGroups, 1)
	a.Nil(resp.TxnGroups[0].FailureMessage)
	a.Len(resp.TxnGroups[0].Txns, 3)

	for i := 0; i < 3; i++ {
		a.NotNil(resp.TxnGroups[0].Txns[i].TransactionTrace.ApprovalProgramHash)
		a.Equal(approvalHash.ToSlice(), *resp.TxnGroups[0].Txns[i].TransactionTrace.ApprovalProgramHash)
	}

	a.Equal([]model.SimulationOpcodeTraceUnit{
		{Pc: 1},
		{Pc: 4},
		{Pc: 6},
		{Pc: 9},
		{Pc: 11},
		{Pc: 12},
		{Pc: 13},
		{Pc: 16},
		{Pc: 23},
		{Pc: 31},
		{Pc: 34},
		{Pc: 94},
		{Pc: 110},
		{
			Pc: 116,
			StateChanges: &[]model.ApplicationStateOperation{
				{
					Operation:    "w",
					AppStateType: "g",
					Key:          []byte("global-int-key"),
					NewValue: &model.AvmValue{
						Type: uint64(basics.TealUintType),
						Uint: toPtr[uint64](0xdeadbeef),
					},
				},
			},
		},
		{Pc: 117},
		{Pc: 135},
		{
			Pc: 150,
			StateChanges: &[]model.ApplicationStateOperation{
				{
					Operation:    "w",
					AppStateType: "g",
					Key:          []byte("global-bytes-key"),
					NewValue: &model.AvmValue{
						Type:  uint64(basics.TealBytesType),
						Bytes: toPtr([]byte("welt am draht")),
					},
				},
			},
		},
		{Pc: 151},
		{Pc: 154},
	}, *resp.TxnGroups[0].Txns[0].TransactionTrace.ApprovalProgramTrace)
	a.NotNil(resp.TxnGroups[0].Txns[1].TransactionTrace.ApprovalProgramHash)
	a.Equal([]model.SimulationOpcodeTraceUnit{
		{Pc: 1},
		{Pc: 4},
		{Pc: 6},
		{Pc: 9},
		{Pc: 11},
		{Pc: 12},
		{Pc: 13},
		{Pc: 154},
	}, *resp.TxnGroups[0].Txns[1].TransactionTrace.ApprovalProgramTrace)
	a.Equal([]model.SimulationOpcodeTraceUnit{
		{Pc: 1},
		{Pc: 4},
		{Pc: 6},
		{Pc: 9},
		{Pc: 11},
		{Pc: 12},
		{Pc: 13},
		{Pc: 16},
		{Pc: 23},
		{Pc: 31},
		{Pc: 34},
		{Pc: 41},
		{Pc: 43},
		{Pc: 58},
		{
			Pc: 64,
			StateChanges: &[]model.ApplicationStateOperation{
				{
					Operation:    "w",
					AppStateType: "l",
					Key:          []byte("local-int-key"),
					NewValue: &model.AvmValue{
						Type: uint64(basics.TealUintType),
						Uint: toPtr[uint64](0xcafeb0ba),
					},
					Account: toPtr(addressDigest.String()),
				},
			},
		},
		{Pc: 65},
		{Pc: 67},
		{Pc: 84},
		{
			Pc: 90,
			StateChanges: &[]model.ApplicationStateOperation{
				{
					Operation:    "w",
					AppStateType: "l",
					Key:          []byte("local-bytes-key"),
					NewValue: &model.AvmValue{
						Type:  uint64(basics.TealBytesType),
						Bytes: toPtr([]byte("xqcL")),
					},
					Account: toPtr(addressDigest.String()),
				},
			},
		},
		{Pc: 91},
		{Pc: 154},
	}, *resp.TxnGroups[0].Txns[2].TransactionTrace.ApprovalProgramTrace)
}

func TestSimulateExecTraceAppInitialState(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.SetupNoStart(t, filepath.Join("nettemplates", "OneNodeFuture.json"))

	// Get primary node
	primaryNode, err := localFixture.GetNodeController("Primary")
	a.NoError(err)

	localFixture.Start()
	defer primaryNode.FullStop()

	// get lib goal client
	testClient := localFixture.LibGoalFixture.GetLibGoalClientFromNodeController(primaryNode)

	_, err = testClient.WaitForRound(1)
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, senderAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	a.NotEmpty(senderAddress, "no addr with funds")

	addressDigest, err := basics.UnmarshalChecksumAddress(senderAddress)
	a.NoError(err)

	ops, err := logic.AssembleString(
		`#pragma version 8
txn ApplicationID
bz end // Do nothing during create

txn OnCompletion
int OptIn
==
bnz end // Always allow optin

byte "local"
byte "global"
txn ApplicationArgs 0
match local global
err // Unknown command

local:
  txn Sender
  byte "local-int-key"
  int 0xcafeb0ba
  app_local_put
  int 0
  byte "local-bytes-key"
  byte "xqcL"
  app_local_put
  b end

global:
  byte "global-int-key"
  int 0xdeadbeef
  app_global_put
  byte "global-bytes-key"
  byte "welt am draht"
  app_global_put
  b end

end:
  int 1`)
	a.NoError(err)
	approval := ops.Program

	ops, err = logic.AssembleString("#pragma version 8\nint 1")
	a.NoError(err)
	clearState := ops.Program

	gl := basics.StateSchema{NumByteSlice: 1, NumUint: 1}
	lc := basics.StateSchema{NumByteSlice: 1, NumUint: 1}

	MinFee := config.Consensus[protocol.ConsensusFuture].MinTxnFee
	MinBalance := config.Consensus[protocol.ConsensusFuture].MinBalance

	// create app and get the application ID
	appCreateTxn, err := testClient.MakeUnsignedAppCreateTx(
		transactions.NoOpOC, approval, clearState, gl,
		lc, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)

	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	submittedAppCreateTxn, err := helper.WaitForTransaction(t, testClient, appCreateTxID, 30*time.Second)
	a.NoError(err)
	futureAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)

	// fund app account
	_, err = testClient.ConstructPayment(
		senderAddress, futureAppID.Address().String(),
		0, MinBalance*2, nil, "", [32]byte{}, 0, 0,
	)
	a.NoError(err)

	// construct app call "global"
	appCallGlobalTxn, err := testClient.MakeUnsignedAppNoOpTx(
		futureAppID, [][]byte{[]byte("global")}, libgoal.RefBundle{}, 0,
	)
	a.NoError(err)
	appCallGlobalTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, MinFee, appCallGlobalTxn)
	a.NoError(err)
	// construct app optin
	appOptInTxn, err := testClient.MakeUnsignedAppOptInTx(futureAppID, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	appOptInTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, MinFee, appOptInTxn)
	// construct app call "local"
	appCallLocalTxn, err := testClient.MakeUnsignedAppNoOpTx(
		futureAppID, [][]byte{[]byte("local")}, libgoal.RefBundle{}, 0,
	)
	a.NoError(err)
	appCallLocalTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, MinFee, appCallLocalTxn)
	a.NoError(err)

	gid, err := testClient.GroupID([]transactions.Transaction{appCallGlobalTxn, appOptInTxn, appCallLocalTxn})
	a.NoError(err)
	appCallGlobalTxn.Group = gid
	appOptInTxn.Group = gid
	appCallLocalTxn.Group = gid

	appCallTxnGlobalSigned, err := testClient.SignTransactionWithWallet(wh, nil, appCallGlobalTxn)
	a.NoError(err)
	appOptInSigned, err := testClient.SignTransactionWithWallet(wh, nil, appOptInTxn)
	a.NoError(err)
	appCallTxnLocalSigned, err := testClient.SignTransactionWithWallet(wh, nil, appCallLocalTxn)
	a.NoError(err)

	a.NoError(testClient.BroadcastTransactionGroup([]transactions.SignedTxn{
		appCallTxnGlobalSigned,
		appOptInSigned,
		appCallTxnLocalSigned,
	}))
	_, err = helper.WaitForTransaction(t, testClient, appCallTxnGlobalSigned.Txn.ID().String(), 30*time.Second)
	a.NoError(err)

	// construct simulation request, with state change enabled
	execTraceConfig := simulation.ExecTraceConfig{
		Enable: true,
		State:  true,
	}

	appCallGlobalTxn.Note = []byte("note for global")
	appCallGlobalTxn.Group = crypto.Digest{}
	appCallLocalTxn.Note = []byte("note for local")
	appCallLocalTxn.Group = crypto.Digest{}

	gid, err = testClient.GroupID([]transactions.Transaction{appCallGlobalTxn, appCallLocalTxn})
	a.NoError(err)
	appCallGlobalTxn.Group = gid
	appCallLocalTxn.Group = gid

	appCallTxnGlobalSigned, err = testClient.SignTransactionWithWallet(wh, nil, appCallGlobalTxn)
	a.NoError(err)
	appCallTxnLocalSigned, err = testClient.SignTransactionWithWallet(wh, nil, appCallLocalTxn)
	a.NoError(err)

	simulateRequest := v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{Txns: []transactions.SignedTxn{appCallTxnGlobalSigned, appCallTxnLocalSigned}},
		},
		ExecTraceConfig: execTraceConfig,
	}

	// update the configuration file to enable EnableDeveloperAPI
	err = primaryNode.FullStop()
	a.NoError(err)
	cfg, err := config.LoadConfigFromDisk(primaryNode.GetDataDir())
	a.NoError(err)
	cfg.EnableDeveloperAPI = true
	err = cfg.SaveToDisk(primaryNode.GetDataDir())
	require.NoError(t, err)
	localFixture.Start()

	// start real simulating
	resp, err := testClient.SimulateTransactions(simulateRequest)
	a.NoError(err)

	// assertions
	a.Len(resp.TxnGroups, 1)
	a.Nil(resp.TxnGroups[0].FailureMessage)
	a.Len(resp.TxnGroups[0].Txns, 2)

	a.Equal([]model.SimulationOpcodeTraceUnit{
		{Pc: 1},
		{Pc: 4},
		{Pc: 6},
		{Pc: 9},
		{Pc: 11},
		{Pc: 12},
		{Pc: 13},
		{Pc: 16},
		{Pc: 23},
		{Pc: 31},
		{Pc: 34},
		{Pc: 94},
		{Pc: 110},
		{
			Pc: 116,
			StateChanges: &[]model.ApplicationStateOperation{
				{
					Operation:    "w",
					AppStateType: "g",
					Key:          []byte("global-int-key"),
					NewValue: &model.AvmValue{
						Type: uint64(basics.TealUintType),
						Uint: toPtr[uint64](0xdeadbeef),
					},
				},
			},
		},
		{Pc: 117},
		{Pc: 135},
		{
			Pc: 150,
			StateChanges: &[]model.ApplicationStateOperation{
				{
					Operation:    "w",
					AppStateType: "g",
					Key:          []byte("global-bytes-key"),
					NewValue: &model.AvmValue{
						Type:  uint64(basics.TealBytesType),
						Bytes: toPtr([]byte("welt am draht")),
					},
				},
			},
		},
		{Pc: 151},
		{Pc: 154},
	}, *resp.TxnGroups[0].Txns[0].TransactionTrace.ApprovalProgramTrace)
	a.Equal([]model.SimulationOpcodeTraceUnit{
		{Pc: 1},
		{Pc: 4},
		{Pc: 6},
		{Pc: 9},
		{Pc: 11},
		{Pc: 12},
		{Pc: 13},
		{Pc: 16},
		{Pc: 23},
		{Pc: 31},
		{Pc: 34},
		{Pc: 41},
		{Pc: 43},
		{Pc: 58},
		{
			Pc: 64,
			StateChanges: &[]model.ApplicationStateOperation{
				{
					Operation:    "w",
					AppStateType: "l",
					Key:          []byte("local-int-key"),
					NewValue: &model.AvmValue{
						Type: uint64(basics.TealUintType),
						Uint: toPtr[uint64](0xcafeb0ba),
					},
					Account: toPtr(addressDigest.String()),
				},
			},
		},
		{Pc: 65},
		{Pc: 67},
		{Pc: 84},
		{
			Pc: 90,
			StateChanges: &[]model.ApplicationStateOperation{
				{
					Operation:    "w",
					AppStateType: "l",
					Key:          []byte("local-bytes-key"),
					NewValue: &model.AvmValue{
						Type:  uint64(basics.TealBytesType),
						Bytes: toPtr([]byte("xqcL")),
					},
					Account: toPtr(addressDigest.String()),
				},
			},
		},
		{Pc: 91},
		{Pc: 154},
	}, *resp.TxnGroups[0].Txns[1].TransactionTrace.ApprovalProgramTrace)

	a.NotNil(resp.InitialStates)
	a.Len(*resp.InitialStates.AppInitialStates, 1)

	a.Len((*resp.InitialStates.AppInitialStates)[0].AppGlobals.Kvs, 2)

	globalKVs := (*resp.InitialStates.AppInitialStates)[0].AppGlobals.Kvs
	globalKVMap := make(map[string]model.AvmValue)
	for _, kv := range globalKVs {
		globalKVMap[string(kv.Key)] = kv.Value
	}
	expectedGlobalKVMap := map[string]model.AvmValue{
		"global-int-key": {
			Type: 2,
			Uint: toPtr[uint64](0xdeadbeef),
		},
		"global-bytes-key": {
			Type:  1,
			Bytes: toPtr([]byte("welt am draht")),
		},
	}
	a.Equal(expectedGlobalKVMap, globalKVMap)

	a.Len(*(*resp.InitialStates.AppInitialStates)[0].AppLocals, 1)

	localKVs := (*(*resp.InitialStates.AppInitialStates)[0].AppLocals)[0]
	a.NotNil(localKVs.Account)
	a.Equal(senderAddress, *localKVs.Account)

	localKVMap := make(map[string]model.AvmValue)
	for _, kv := range localKVs.Kvs {
		localKVMap[string(kv.Key)] = kv.Value
	}
	expectedLocalKVMap := map[string]model.AvmValue{
		"local-int-key": {
			Type: 2,
			Uint: toPtr[uint64](0xcafeb0ba),
		},
		"local-bytes-key": {
			Type:  1,
			Bytes: toPtr([]byte("xqcL")),
		},
	}
	a.Equal(expectedLocalKVMap, localKVMap)
}

func TestSimulateWithUnnamedResources(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	_, err := testClient.WaitForRound(1)
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, senderAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	a.NotEmpty(senderAddress, "no addr with funds")
	a.NoError(err)

	otherAddress := helper.GetDestAddr(t, testClient, nil, senderAddress, wh)

	// fund otherAddress
	txn, err := testClient.SendPaymentFromWallet(
		wh, nil, senderAddress, otherAddress,
		0, 1_000_000, nil, "", 0, 0,
	)
	a.NoError(err)
	txID := txn.ID().String()
	_, err = helper.WaitForTransaction(t, testClient, txID, 30*time.Second)
	a.NoError(err)

	// create asset
	txn, err = testClient.MakeUnsignedAssetCreateTx(100, false, "", "", "", "", "", "", "", nil, 0)
	a.NoError(err)
	txn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, txn)
	a.NoError(err)
	// sign and broadcast
	txID, err = testClient.SignAndBroadcastTransaction(wh, nil, txn)
	a.NoError(err)
	confirmedTxn, err := helper.WaitForTransaction(t, testClient, txID, 30*time.Second)
	a.NoError(err)
	// get asset ID
	a.NotNil(confirmedTxn.AssetIndex)
	assetID := *confirmedTxn.AssetIndex
	a.NotZero(assetID)

	// opt-in to asset
	txn, err = testClient.MakeUnsignedAssetSendTx(assetID, 0, otherAddress, "", "")
	a.NoError(err)
	txn, err = testClient.FillUnsignedTxTemplate(otherAddress, 0, 0, 0, txn)
	a.NoError(err)
	// sign and broadcast
	txID, err = testClient.SignAndBroadcastTransaction(wh, nil, txn)
	a.NoError(err)
	_, err = helper.WaitForTransaction(t, testClient, txID, 30*time.Second)
	a.NoError(err)

	// transfer asset
	txn, err = testClient.MakeUnsignedAssetSendTx(assetID, 1, otherAddress, "", "")
	a.NoError(err)
	txn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, txn)
	a.NoError(err)
	// sign and broadcast
	txID, err = testClient.SignAndBroadcastTransaction(wh, nil, txn)
	a.NoError(err)
	_, err = helper.WaitForTransaction(t, testClient, txID, 30*time.Second)
	a.NoError(err)

	ops, err := logic.AssembleString("#pragma version 9\n int 1")
	a.NoError(err)
	alwaysApprove := ops.Program

	gl := basics.StateSchema{}
	lc := basics.StateSchema{}

	// create app
	txn, err = testClient.MakeUnsignedAppCreateTx(transactions.OptInOC, alwaysApprove, alwaysApprove, gl, lc, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	txn, err = testClient.FillUnsignedTxTemplate(otherAddress, 0, 0, 0, txn)
	a.NoError(err)
	// sign and broadcast
	txID, err = testClient.SignAndBroadcastTransaction(wh, nil, txn)
	a.NoError(err)
	confirmedTxn, err = helper.WaitForTransaction(t, testClient, txID, 30*time.Second)
	a.NoError(err)
	// get app ID
	a.NotNil(confirmedTxn.ApplicationIndex)
	otherAppID := basics.AppIndex(*confirmedTxn.ApplicationIndex)
	a.NotZero(otherAppID)

	prog := fmt.Sprintf(`#pragma version 9
txn ApplicationID
bz end

addr %s // otherAddress
store 0

int %d // assetID
store 1

int %d // otherAppID
store 2

// Account access
load 0 // otherAddress
balance
assert

// Asset params access
load 1 // assetID
asset_params_get AssetTotal
assert
int 100
==
assert

// Asset holding access
load 0 // otherAddress
load 1 // assetID
asset_holding_get AssetBalance
assert
int 1
==
assert

// App params access
load 2 // otherAppID
app_params_get AppCreator
assert
load 0 // otherAddress
==
assert

// App local access
load 0 // otherAddress
load 2 // otherAppID
app_opted_in
assert

// Box access
byte "A"
int 2049						// need three refs with old quota, two after the bump (we only test latest)
box_create
assert

end:
int 1
`, otherAddress, assetID, otherAppID)

	ops, err = logic.AssembleString(prog)
	a.NoError(err)
	approval := ops.Program

	// create app
	txn, err = testClient.MakeUnsignedAppCreateTx(transactions.NoOpOC, approval, alwaysApprove, gl, lc, nil, libgoal.RefBundle{}, 0)
	a.NoError(err)
	txn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, txn)
	a.NoError(err)
	// sign and broadcast
	txID, err = testClient.SignAndBroadcastTransaction(wh, nil, txn)
	a.NoError(err)
	confirmedTxn, err = helper.WaitForTransaction(t, testClient, txID, 30*time.Second)
	a.NoError(err)
	// get app ID
	a.NotNil(confirmedTxn.ApplicationIndex)
	testAppID := basics.AppIndex(*confirmedTxn.ApplicationIndex)
	a.NotZero(testAppID)

	// fund app account
	txn, err = testClient.SendPaymentFromWallet(
		wh, nil, senderAddress, testAppID.Address().String(),
		0, 1_000_000, nil, "", 0, 0,
	)
	a.NoError(err)
	txID = txn.ID().String()
	_, err = helper.WaitForTransaction(t, testClient, txID, 30*time.Second)
	a.NoError(err)

	// construct app call
	txn, err = testClient.MakeUnsignedAppNoOpTx(
		testAppID, nil, libgoal.RefBundle{}, 0,
	)
	a.NoError(err)
	txn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, txn)
	a.NoError(err)
	stxn, err := testClient.SignTransactionWithWallet(wh, nil, txn)
	a.NoError(err)

	// Cannot access these resources by default
	resp, err := testClient.SimulateTransactions(v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{
				Txns: []transactions.SignedTxn{stxn},
			},
		},
		AllowUnnamedResources: false,
	})
	a.NoError(err)
	a.Contains(*resp.TxnGroups[0].FailureMessage, "logic eval error: unavailable Account "+otherAddress)
	a.Equal([]int{0}, *resp.TxnGroups[0].FailedAt)

	// It should work with AllowUnnamedResources=true
	resp, err = testClient.SimulateTransactions(v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{
				Txns: []transactions.SignedTxn{stxn},
			},
		},
		AllowUnnamedResources: true,
	})
	a.NoError(err)

	expectedUnnamedGroupResources := model.SimulateUnnamedResourcesAccessed{
		Accounts:     &[]string{otherAddress},
		Assets:       &[]basics.AssetIndex{assetID},
		Apps:         &[]basics.AppIndex{otherAppID},
		Boxes:        &[]model.BoxReference{{App: testAppID, Name: []byte("A")}},
		ExtraBoxRefs: toPtr(1),
		AssetHoldings: &[]model.AssetHoldingReference{
			{Account: otherAddress, Asset: assetID},
		},
		AppLocals: &[]model.ApplicationLocalReference{
			{Account: otherAddress, App: otherAppID},
		},
	}

	budgetAdded, budgetUsed := 700, 40
	allowUnnamedResources := true

	expectedResult := v2.PreEncodedSimulateResponse{
		Version:   2,
		LastRound: resp.LastRound,
		EvalOverrides: &model.SimulationEvalOverrides{
			AllowUnnamedResources: &allowUnnamedResources,
		},
		TxnGroups: []v2.PreEncodedSimulateTxnGroupResult{
			{
				Txns: []v2.PreEncodedSimulateTxnResult{
					{
						Txn:               v2.PreEncodedTxInfo{Txn: stxn},
						AppBudgetConsumed: &budgetUsed,
					},
				},
				AppBudgetAdded:           &budgetAdded,
				AppBudgetConsumed:        &budgetUsed,
				UnnamedResourcesAccessed: &expectedUnnamedGroupResources,
			},
		},
	}
	a.Equal(expectedResult, resp)
}

func TestSimulateWithFixSigners(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	_, err := testClient.WaitForRound(1)
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, senderAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	if senderAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	rekeyTxn, err := testClient.ConstructPayment(senderAddress, senderAddress, 0, 1, nil, "", [32]byte{}, 0, 0)
	a.NoError(err)

	var authAddr basics.Address
	crypto.RandBytes(authAddr[:])
	rekeyTxn.RekeyTo = authAddr

	txn, err := testClient.ConstructPayment(senderAddress, senderAddress, 0, 1, nil, "", [32]byte{}, 0, 0)
	a.NoError(err)

	gid, err := testClient.GroupID([]transactions.Transaction{rekeyTxn, txn})
	a.NoError(err)

	rekeyTxn.Group = gid
	txn.Group = gid

	simulateRequest := v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{
				Txns: []transactions.SignedTxn{{Txn: rekeyTxn}, {Txn: txn}},
			},
		},
		AllowEmptySignatures: true,
		FixSigners:           true,
	}
	result, err := testClient.SimulateTransactions(simulateRequest)
	a.NoError(err)

	allowEmptySignatures := true
	fixSigners := true
	authAddrStr := authAddr.String()
	expectedResult := v2.PreEncodedSimulateResponse{
		Version:   2,
		LastRound: result.LastRound,
		TxnGroups: []v2.PreEncodedSimulateTxnGroupResult{
			{
				Txns: []v2.PreEncodedSimulateTxnResult{
					{
						Txn: v2.PreEncodedTxInfo{
							Txn: transactions.SignedTxn{Txn: rekeyTxn},
						},
					},
					{
						Txn: v2.PreEncodedTxInfo{
							Txn: transactions.SignedTxn{Txn: txn},
						},
						FixedSigner: &authAddrStr,
					},
				},
			},
		},
		EvalOverrides: &model.SimulationEvalOverrides{
			AllowEmptySignatures: &allowEmptySignatures,
			FixSigners:           &fixSigners,
		},
	}
	a.Equal(expectedResult, result)
}
