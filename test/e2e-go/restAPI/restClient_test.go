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

package restapi

import (
	"flag"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

// NOTE: Tests in this file use a shared a network.
// TestMain runs all tests in this package using that shared network.

var fixture fixtures.RestClientFixture

func TestMain(m *testing.M) {
	listMode := false
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "test.list" {
			listMode = true
		}
	})
	if !listMode {
		fixture.SetupShared("RestClientTests", filepath.Join("nettemplates", "TwoNodes50Each.json"))
		fixture.RunAndExit(m)
	} else {
		os.Exit(m.Run())
	}
}

func TestClientCanGetStatus(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	statusResponse, err := testClient.Status()
	a.NoError(err)
	a.NotEmpty(statusResponse)
	statusResponse2, err := testClient.Status()
	a.NoError(err)
	a.NotEmpty(statusResponse2)
	a.True(statusResponse2.LastRound >= statusResponse.LastRound)
}

func TestClientCanGetStatusAfterBlock(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	statusResponse, err := testClient.WaitForRound(1)
	a.NoError(err)
	a.NotEmpty(statusResponse)
	statusResponse, err = testClient.WaitForRound(statusResponse.LastRound + 1)
	a.NoError(err)
	a.NotEmpty(statusResponse)
}

func TestClientCanGetVersion(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	versionResponse, err := testClient.AlgodVersions()
	a.NoError(err)
	a.NotEmpty(versionResponse)
}

func TestClientCanGetSuggestedFee(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	suggestedFeeResponse, err := testClient.SuggestedFee()
	a.NoError(err)
	_ = suggestedFeeResponse // per-byte-fee is allowed to be zero
}

func TestClientCanGetMinTxnFee(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	suggestedParamsRes, err := testClient.SuggestedParams()
	a.NoError(err)
	a.Truef(suggestedParamsRes.MinFee > 0, "min txn fee not supplied")
}

func TestClientCanGetBlockInfo(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	WaitForRoundOne(t, testClient)
	blockResponse, err := testClient.Block(1)
	a.NoError(err)
	a.NotEmpty(blockResponse)
}

func TestClientRejectsBadFromAddressWhenSending(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	params, err := testClient.SuggestedParams()
	a.NoError(err)
	badAccountAddress := "This is absolutely not a valid account address."
	goodAccountAddress := addresses[0]
	_, err = testClient.SendPaymentFromWallet(wh, nil, badAccountAddress, goodAccountAddress, params.MinFee, 100000, nil, "", 0, 0)
	a.Error(err)
}

func TestClientRejectsBadToAddressWhenSending(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	params, err := testClient.SuggestedParams()
	a.NoError(err)
	badAccountAddress := "This is absolutely not a valid account address."
	goodAccountAddress := addresses[0]
	_, err = testClient.SendPaymentFromWallet(wh, nil, goodAccountAddress, badAccountAddress, params.MinFee, 100000, nil, "", 0, 0)
	a.Error(err)
}

func TestClientRejectsMutatedFromAddressWhenSending(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	params, err := testClient.SuggestedParams()
	a.NoError(err)
	goodAccountAddress := addresses[0]
	var unmutatedAccountAddress string
	if len(addresses) > 1 {
		unmutatedAccountAddress = addresses[1]
	} else {
		unmutatedAccountAddress, err = testClient.GenerateAddress(wh)
		a.NoError(err)
	}
	mutatedAccountAddress := mutateStringAtIndex(unmutatedAccountAddress, 0)
	_, err = testClient.SendPaymentFromWallet(wh, nil, mutatedAccountAddress, goodAccountAddress, params.MinFee, 100000, nil, "", 0, 0)
	a.Error(err)
}

func TestClientRejectsMutatedToAddressWhenSending(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	params, err := testClient.SuggestedParams()
	a.NoError(err)
	goodAccountAddress := addresses[0]
	var unmutatedAccountAddress string
	if len(addresses) > 1 {
		unmutatedAccountAddress = addresses[1]
	} else {
		unmutatedAccountAddress, err = testClient.GenerateAddress(wh)
		a.NoError(err)
	}
	mutatedAccountAddress := mutateStringAtIndex(unmutatedAccountAddress, 0)
	_, err = testClient.SendPaymentFromWallet(wh, nil, goodAccountAddress, mutatedAccountAddress, params.MinFee, 100000, nil, "", 0, 0)
	a.Error(err)
}

func TestClientRejectsSendingMoneyFromAccountForWhichItHasNoKey(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	params, err := testClient.SuggestedParams()
	a.NoError(err)
	goodAccountAddress := addresses[0]
	nodeDoesNotHaveKeyForThisAddress := "NJY27OQ2ZXK6OWBN44LE4K43TA2AV3DPILPYTHAJAMKIVZDWTEJKZJKO4A"
	_, err = testClient.SendPaymentFromWallet(wh, nil, nodeDoesNotHaveKeyForThisAddress, goodAccountAddress, params.MinFee, 100000, nil, "", 0, 0)
	a.Error(err)
}

func TestClientOversizedNote(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	WaitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	params, err := testClient.SuggestedParams()
	a.NoError(err)
	fromAddress := addresses[0]
	var toAddress string
	if len(addresses) > 1 {
		toAddress = addresses[1]
	} else {
		toAddress, err = testClient.GenerateAddress(wh)
		a.NoError(err)
	}
	maxTxnNoteBytes := config.Consensus[protocol.ConsensusCurrentVersion].MaxTxnNoteBytes
	note := make([]byte, maxTxnNoteBytes+1)
	_, err = testClient.SendPaymentFromWallet(wh, nil, fromAddress, toAddress, params.MinFee, 100000, note, "", 0, 0)
	a.Error(err)
}

func TestClientCanSendAndGetNote(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	WaitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	params, err := testClient.SuggestedParams()
	a.NoError(err)
	_, someAddress := GetMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	toAddress := GetDestAddr(t, testClient, addresses, someAddress, wh)
	maxTxnNoteBytes := config.Consensus[protocol.ConsensusCurrentVersion].MaxTxnNoteBytes
	note := make([]byte, maxTxnNoteBytes)
	tx, err := testClient.SendPaymentFromWallet(wh, nil, someAddress, toAddress, params.MinFee, 100000, note, "", 0, 0)
	a.NoError(err)
	txStatus, err := WaitForTransaction(t, testClient, tx.ID().String(), 30*time.Second)
	a.NoError(err)
	a.Equal(note, txStatus.Txn.Txn.Note)
}

func TestClientCanGetTransactionStatus(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	WaitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	params, err := testClient.SuggestedParams()
	a.NoError(err)
	_, someAddress := GetMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	toAddress := GetDestAddr(t, testClient, addresses, someAddress, wh)
	tx, err := testClient.SendPaymentFromWallet(wh, nil, someAddress, toAddress, params.MinFee, 100000, nil, "", 0, 0)
	t.Log(string(protocol.EncodeJSON(tx)))
	a.NoError(err)
	t.Log(tx.ID().String())
	_, err = WaitForTransaction(t, testClient, tx.ID().String(), 30*time.Second)
	a.NoError(err)
}

func TestAccountBalance(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	WaitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	params, err := testClient.SuggestedParams()
	a.NoError(err)
	_, someAddress := GetMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}

	toAddress, err := testClient.GenerateAddress(wh)
	a.NoError(err)
	tx, err := testClient.SendPaymentFromWallet(wh, nil, someAddress, toAddress, params.MinFee, 100000, nil, "", 0, 0)
	a.NoError(err)
	_, err = WaitForTransaction(t, testClient, tx.ID().String(), 30*time.Second)
	a.NoError(err)

	account, err := testClient.AccountInformation(toAddress, false)
	a.NoError(err)
	a.Equal(account.AmountWithoutPendingRewards, uint64(100000))
	a.Truef(account.Amount >= 100000, "account must have received money, and account information endpoint must print it")
}

func TestAccountParticipationInfo(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	WaitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := GetMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)
	addr, err := basics.UnmarshalChecksumAddress(someAddress)
	a.NoError(err)

	params, err := testClient.SuggestedParams()
	a.NoError(err)

	firstRound := basics.Round(params.LastRound + 1)
	lastRound := basics.Round(params.LastRound + 1000)
	dilution := uint64(100)
	var stateproof merklesignature.Verifier
	stateproof.KeyLifetime = merklesignature.KeyLifetimeDefault
	stateproof.Commitment[0] = 1 // change some byte so the stateproof is not considered empty (required since consensus v31)

	randomVotePKStr := RandomString(32)
	var votePK crypto.OneTimeSignatureVerifier
	copy(votePK[:], []byte(randomVotePKStr))
	randomSelPKStr := RandomString(32)
	var selPK crypto.VRFVerifier
	copy(selPK[:], []byte(randomSelPKStr))
	var gh crypto.Digest
	copy(gh[:], params.GenesisHash)
	tx := transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:      addr,
			Fee:         basics.MicroAlgos{Raw: params.MinFee},
			FirstValid:  firstRound,
			LastValid:   lastRound,
			GenesisHash: gh,
		},
		KeyregTxnFields: transactions.KeyregTxnFields{
			VotePK:          votePK,
			SelectionPK:     selPK,
			VoteKeyDilution: dilution,
			VoteFirst:       firstRound,
			VoteLast:        lastRound,
			StateProofPK:    stateproof.Commitment,
		},
	}
	txID, err := testClient.SignAndBroadcastTransaction(wh, nil, tx)
	a.NoError(err)
	_, err = WaitForTransaction(t, testClient, txID, 30*time.Second)
	a.NoError(err)

	account, err := testClient.AccountInformation(someAddress, false)
	a.NoError(err)
	a.Equal(randomVotePKStr, string(account.Participation.VoteParticipationKey), "API must print correct root voting key")
	a.Equal(randomSelPKStr, string(account.Participation.SelectionParticipationKey), "API must print correct vrf key")
	a.Equal(firstRound, account.Participation.VoteFirstValid, "API must print correct first participation round")
	a.Equal(lastRound, account.Participation.VoteLastValid, "API must print correct last participation round")
	a.Equal(dilution, account.Participation.VoteKeyDilution, "API must print correct key dilution")
	// TODO: should we update the v1 API to support state proof? Currently it does not return this field.
}

func TestSupply(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	supply, err := testClient.LedgerSupply()
	a.NoError(err)
	a.True(supply.TotalMoney > 1e6)
	a.True(supply.OnlineMoney > 1e6)
	a.True(supply.TotalMoney >= supply.OnlineMoney)
}

func TestClientCanGetGoRoutines(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.AlgodClient
	ctx := t.Context()
	goRoutines, err := testClient.GetGoRoutines(ctx)
	a.NoError(err)
	a.NotEmpty(goRoutines)
	a.True(strings.Contains(goRoutines, "goroutine profile:"))
}

func TestSendingTooMuchErrs(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	fromAddress := addresses[0]
	var toAddress string
	if len(addresses) > 1 {
		toAddress = addresses[1]
	} else {
		toAddress, err = testClient.GenerateAddress(wh)
		a.NoError(err)
	}
	fromBalance, err := testClient.GetBalance(fromAddress)
	a.NoError(err)
	params, err := testClient.SuggestedParams()
	a.NoError(err)
	// too much amount
	_, err = testClient.SendPaymentFromWallet(wh, nil, fromAddress, toAddress, params.MinFee, fromBalance+100, nil, "", 0, 0)
	t.Log(err)
	a.Error(err)

	// waaaay too much amount
	_, err = testClient.SendPaymentFromWallet(wh, nil, fromAddress, toAddress, params.MinFee, math.MaxUint64, nil, "", 0, 0)
	t.Log(err)
	a.Error(err)

	// too much fee
	_, err = testClient.SendPaymentFromWallet(wh, nil, fromAddress, toAddress, fromBalance+100, params.MinFee, nil, "", 0, 0)
	t.Log(err)
	a.Error(err)

	// waaaay too much fee
	_, err = testClient.SendPaymentFromWallet(wh, nil, fromAddress, toAddress, math.MaxUint64, params.MinFee, nil, "", 0, 0)
	t.Log(err)
	a.Error(err)
}

func TestSendingFromEmptyAccountErrs(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	WaitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	var fromAddress string
	for _, addr := range addresses {
		bal, err := testClient.GetBalance(addr)
		a.NoError(err)
		if bal == 0 {
			fromAddress = addr
			break
		}
	}
	if fromAddress == "" {
		fromAddress, err = testClient.GenerateAddress(wh)
		a.NoError(err)
	}
	var toAddress string
	for _, addr := range addresses {
		if addr != fromAddress {
			toAddress = addr
			break
		}
	}
	if toAddress == "" {
		toAddress, err = testClient.GenerateAddress(wh)
		a.NoError(err)
	}
	params, err := testClient.SuggestedParams()
	a.NoError(err)
	_, err = testClient.SendPaymentFromWallet(wh, nil, fromAddress, toAddress, params.MinFee, 100000, nil, "", 0, 0)
	a.Error(err)
}

func TestSendingTooLittleToEmptyAccountErrs(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	WaitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	var emptyAddress string
	for _, addr := range addresses {
		bal, err := testClient.GetBalance(addr)
		a.NoError(err)
		if bal == 0 {
			emptyAddress = addr
			break
		}
	}
	if emptyAddress == "" {
		emptyAddress, err = testClient.GenerateAddress(wh)
		a.NoError(err)
	}
	_, someAddress := GetMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	params, err := testClient.SuggestedParams()
	a.NoError(err)
	_, err = testClient.SendPaymentFromWallet(wh, nil, someAddress, emptyAddress, params.MinFee, 1, nil, "", 0, 0)
	a.Error(err)
}

func TestSendingLowFeeErrs(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	const sendAmount = 100000
	someBal, someAddress := GetMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	if someBal < sendAmount {
		t.Errorf("balance too low %d < %d", someBal, sendAmount)
	}
	toAddress := GetDestAddr(t, testClient, addresses, someAddress, wh)
	utx, err := testClient.ConstructPayment(someAddress, toAddress, 1, sendAmount, nil, "", [32]byte{}, 0, 0)
	a.NoError(err)
	utx.Fee.Raw = 1
	stx, err := testClient.SignTransactionWithWallet(wh, nil, utx)
	a.NoError(err)
	_, err = testClient.BroadcastTransaction(stx)
	t.Log(err)
	a.Error(err)
	utx.Fee.Raw = 0
	stx, err = testClient.SignTransactionWithWallet(wh, nil, utx)
	a.NoError(err)
	_, err = testClient.BroadcastTransaction(stx)
	t.Log(err)
	a.Error(err)
}
