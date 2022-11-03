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

package restapi

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

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

// helper generates a random Uppercase Alphabetic ASCII char
func randomUpperAlphaAsByte() byte {
	return byte(65 + rand.Intn(25))
}

// helper generates a random string
// snippet credit to many places, one such place is https://medium.com/@kpbird/golang-generate-fixed-size-random-string-dd6dbd5e63c0
func randomString(len int) string {
	// re-seed the RNG to mitigate randomString collisions across tests
	rand.Seed(time.Now().UnixNano())
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		bytes[i] = randomUpperAlphaAsByte()
	}
	return string(bytes)
}

// helper replaces a string's character at index
func replaceAtIndex(in string, r rune, i int) string {
	out := []rune(in)
	out[i] = r
	return string(out)
}

// helper replaces a string's character at index with a random, different uppercase alphabetic ascii char
func mutateStringAtIndex(in string, i int) (out string) {
	out = in
	for out == in {
		out = replaceAtIndex(in, rune(randomUpperAlphaAsByte()), i)
	}
	return out
}

func getMaxBalAddr(t *testing.T, testClient libgoal.Client, addresses []string) (someBal uint64, someAddress string) {
	a := require.New(fixtures.SynchronizedTest(t))
	someBal = 0
	for _, addr := range addresses {
		bal, err := testClient.GetBalance(addr)
		a.NoError(err)
		if bal > someBal {
			someAddress = addr
			someBal = bal
		}
	}
	return
}

func getDestAddr(t *testing.T, testClient libgoal.Client, addresses []string, someAddress string, wh []byte) (toAddress string) {
	a := require.New(fixtures.SynchronizedTest(t))
	if len(addresses) > 1 {
		for _, addr := range addresses {
			if addr != someAddress {
				toAddress = addr
				return
			}
		}
	}
	var err error
	toAddress, err = testClient.GenerateAddress(wh)
	a.NoError(err)
	return
}

func waitForRoundOne(t *testing.T, testClient libgoal.Client) {
	a := require.New(fixtures.SynchronizedTest(t))
	errchan := make(chan error)
	quit := make(chan struct{})
	go func() {
		_, xe := testClient.WaitForRound(1)
		select {
		case errchan <- xe:
		case <-quit:
		}
	}()
	select {
	case err := <-errchan:
		a.NoError(err)
	case <-time.After(1 * time.Minute): // Wait 1 minute (same as WaitForRound)
		close(quit)
		t.Fatalf("%s: timeout waiting for round 1", t.Name())
	}
}

var errWaitForTransactionTimeout = errors.New("wait for transaction timed out")

func waitForTransaction(t *testing.T, testClient libgoal.Client, fromAddress, txID string, timeout time.Duration) (tx v2.PreEncodedTxInfo, err error) {
	a := require.New(fixtures.SynchronizedTest(t))
	rnd, err := testClient.Status()
	a.NoError(err)
	if rnd.LastRound == 0 {
		t.Fatal("it is currently round 0 but we need to wait for a transaction that might happen this round but we'll never know if that happens because ConfirmedRound==0 is indestinguishable from not having happened")
	}
	timeoutTime := time.Now().Add(timeout)
	for {
		tx, err = testClient.ParsedPendingTransaction(txID)
		if err == nil {
			a.NotEmpty(tx)
			a.Empty(tx.PoolError)
			if tx.ConfirmedRound != nil && *tx.ConfirmedRound > 0 {
				return
			}
		}
		if time.Now().After(timeoutTime) {
			err = errWaitForTransactionTimeout
			return
		}
		time.Sleep(time.Second)
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

// Deprecated: This test uses a v1 API feature that is no longer supported by v2.
func TestTransactionsByAddr(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient
	waitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := getMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	toAddress := getDestAddr(t, testClient, addresses, someAddress, wh)
	tx, err := testClient.SendPaymentFromWallet(wh, nil, someAddress, toAddress, 10000, 100000, nil, "", 0, 0)
	a.NoError(err)
	txID := tx.ID()
	rnd, err := testClient.Status()
	a.NoError(err)
	t.Logf("rnd[%d] created txn %s", rnd.LastRound, txID)
	_, err = waitForTransaction(t, testClient, someAddress, txID.String(), 30*time.Second)
	a.NoError(err)

	// what is my round?
	rnd, err = testClient.Status()
	a.NoError(err)
	t.Logf("rnd %d", rnd.LastRound)

	// Now let's get the transaction

	restClient, err := localFixture.NC.AlgodClient()
	a.NoError(err)
	res, err := restClient.TransactionsByAddr(toAddress, 0, rnd.LastRound, 100)
	a.NoError(err)
	a.Equal(1, len(res.Transactions))

	for _, tx := range res.Transactions {
		a.Equal(tx.From, someAddress)
		a.Equal(tx.Payment.Amount, uint64(100000))
		a.Equal(tx.Fee, uint64(10000))
	}
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
	waitForRoundOne(t, testClient)
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
	badAccountAddress := "This is absolutely not a valid account address."
	goodAccountAddress := addresses[0]
	_, err = testClient.SendPaymentFromWallet(wh, nil, badAccountAddress, goodAccountAddress, 10000, 100000, nil, "", 0, 0)
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
	badAccountAddress := "This is absolutely not a valid account address."
	goodAccountAddress := addresses[0]
	_, err = testClient.SendPaymentFromWallet(wh, nil, goodAccountAddress, badAccountAddress, 10000, 100000, nil, "", 0, 0)
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
	goodAccountAddress := addresses[0]
	var unmutatedAccountAddress string
	if len(addresses) > 1 {
		unmutatedAccountAddress = addresses[1]
	} else {
		unmutatedAccountAddress, err = testClient.GenerateAddress(wh)
		a.NoError(err)
	}
	mutatedAccountAddress := mutateStringAtIndex(unmutatedAccountAddress, 0)
	_, err = testClient.SendPaymentFromWallet(wh, nil, mutatedAccountAddress, goodAccountAddress, 10000, 100000, nil, "", 0, 0)
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
	goodAccountAddress := addresses[0]
	var unmutatedAccountAddress string
	if len(addresses) > 1 {
		unmutatedAccountAddress = addresses[1]
	} else {
		unmutatedAccountAddress, err = testClient.GenerateAddress(wh)
		a.NoError(err)
	}
	mutatedAccountAddress := mutateStringAtIndex(unmutatedAccountAddress, 0)
	_, err = testClient.SendPaymentFromWallet(wh, nil, goodAccountAddress, mutatedAccountAddress, 10000, 100000, nil, "", 0, 0)
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
	goodAccountAddress := addresses[0]
	nodeDoesNotHaveKeyForThisAddress := "NJY27OQ2ZXK6OWBN44LE4K43TA2AV3DPILPYTHAJAMKIVZDWTEJKZJKO4A"
	_, err = testClient.SendPaymentFromWallet(wh, nil, nodeDoesNotHaveKeyForThisAddress, goodAccountAddress, 10000, 100000, nil, "", 0, 0)
	a.Error(err)
}

func TestClientOversizedNote(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	waitForRoundOne(t, testClient)
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
	maxTxnNoteBytes := config.Consensus[protocol.ConsensusCurrentVersion].MaxTxnNoteBytes
	note := make([]byte, maxTxnNoteBytes+1)
	_, err = testClient.SendPaymentFromWallet(wh, nil, fromAddress, toAddress, 10000, 100000, note, "", 0, 0)
	a.Error(err)
}

func TestClientCanSendAndGetNote(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	waitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := getMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	toAddress := getDestAddr(t, testClient, addresses, someAddress, wh)
	maxTxnNoteBytes := config.Consensus[protocol.ConsensusCurrentVersion].MaxTxnNoteBytes
	note := make([]byte, maxTxnNoteBytes)
	tx, err := testClient.SendPaymentFromWallet(wh, nil, someAddress, toAddress, 10000, 100000, note, "", 0, 0)
	a.NoError(err)
	txStatus, err := waitForTransaction(t, testClient, someAddress, tx.ID().String(), 30*time.Second)
	a.NoError(err)
	a.Equal(note, txStatus.Txn.Txn.Note)
}

func TestClientCanGetTransactionStatus(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	waitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := getMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	toAddress := getDestAddr(t, testClient, addresses, someAddress, wh)
	tx, err := testClient.SendPaymentFromWallet(wh, nil, someAddress, toAddress, 10000, 100000, nil, "", 0, 0)
	t.Log(string(protocol.EncodeJSON(tx)))
	a.NoError(err)
	t.Log(tx.ID().String())
	_, err = waitForTransaction(t, testClient, someAddress, tx.ID().String(), 30*time.Second)
	a.NoError(err)
}

func TestAccountBalance(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	waitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := getMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}

	toAddress, err := testClient.GenerateAddress(wh)
	a.NoError(err)
	tx, err := testClient.SendPaymentFromWallet(wh, nil, someAddress, toAddress, 10000, 100000, nil, "", 0, 0)
	a.NoError(err)
	_, err = waitForTransaction(t, testClient, someAddress, tx.ID().String(), 30*time.Second)
	a.NoError(err)

	account, err := testClient.AccountInformationV2(toAddress, false)
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
	waitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := getMaxBalAddr(t, testClient, addresses)
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

	randomVotePKStr := randomString(32)
	var votePK crypto.OneTimeSignatureVerifier
	copy(votePK[:], []byte(randomVotePKStr))
	randomSelPKStr := randomString(32)
	var selPK crypto.VRFVerifier
	copy(selPK[:], []byte(randomSelPKStr))
	var gh crypto.Digest
	copy(gh[:], params.GenesisHash)
	tx := transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:      addr,
			Fee:         basics.MicroAlgos{Raw: 10000},
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
	_, err = waitForTransaction(t, testClient, someAddress, txID, 30*time.Second)
	a.NoError(err)

	account, err := testClient.AccountInformationV2(someAddress, false)
	a.NoError(err)
	a.Equal(randomVotePKStr, string(account.Participation.VoteParticipationKey), "API must print correct root voting key")
	a.Equal(randomSelPKStr, string(account.Participation.SelectionParticipationKey), "API must print correct vrf key")
	a.Equal(uint64(firstRound), account.Participation.VoteFirstValid, "API must print correct first participation round")
	a.Equal(uint64(lastRound), account.Participation.VoteLastValid, "API must print correct last participation round")
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
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	goRoutines, err := testClient.GetGoRoutines(ctx)
	a.NoError(err)
	a.NotEmpty(goRoutines)
	a.True(strings.Contains(goRoutines, "goroutine profile:"))
}

func TestSendingTooMuchFails(t *testing.T) {
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
	// too much amount
	_, err = testClient.SendPaymentFromWallet(wh, nil, fromAddress, toAddress, 10000, fromBalance+100, nil, "", 0, 0)
	t.Log(err)
	a.Error(err)

	// waaaay too much amount
	_, err = testClient.SendPaymentFromWallet(wh, nil, fromAddress, toAddress, 10000, math.MaxUint64, nil, "", 0, 0)
	t.Log(err)
	a.Error(err)

	// too much fee
	_, err = testClient.SendPaymentFromWallet(wh, nil, fromAddress, toAddress, fromBalance+100, 10000, nil, "", 0, 0)
	t.Log(err)
	a.Error(err)

	// waaaay too much fee
	_, err = testClient.SendPaymentFromWallet(wh, nil, fromAddress, toAddress, math.MaxUint64, 10000, nil, "", 0, 0)
	t.Log(err)
	a.Error(err)
}

func TestSendingFromEmptyAccountFails(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	waitForRoundOne(t, testClient)
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
	_, err = testClient.SendPaymentFromWallet(wh, nil, fromAddress, toAddress, 10000, 100000, nil, "", 0, 0)
	a.Error(err)
}

func TestSendingTooLittleToEmptyAccountFails(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	waitForRoundOne(t, testClient)
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
	_, someAddress := getMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	_, err = testClient.SendPaymentFromWallet(wh, nil, someAddress, emptyAddress, 10000, 1, nil, "", 0, 0)
	a.Error(err)
}

func TestSendingLowFeeFails(t *testing.T) {
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
	someBal, someAddress := getMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	if someBal < sendAmount {
		t.Errorf("balance too low %d < %d", someBal, sendAmount)
	}
	toAddress := getDestAddr(t, testClient, addresses, someAddress, wh)
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

func TestSendingNotClosingAccountFails(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	// use a local fixture because we might really mess with the balances
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer localFixture.Shutdown()
	testClient := localFixture.LibGoalClient
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
	var someAddress string
	someBal := uint64(0)
	for _, addr := range addresses {
		if addr != emptyAddress {
			bal, err := testClient.GetBalance(addr)
			a.NoError(err)
			if bal > someBal {
				someAddress = addr
				someBal = bal
			}
		}
	}
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	amt := someBal - 10000 - 1
	_, err = testClient.SendPaymentFromWallet(wh, nil, someAddress, emptyAddress, 10000, amt, nil, "", 0, 0)
	a.Error(err)
}

func TestClientCanGetPendingTransactions(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient
	wh, _ := testClient.GetUnencryptedWalletHandle()
	addresses, _ := testClient.ListAddresses(wh)
	fromAddress := addresses[0]
	toAddress, _ := testClient.GenerateAddress(wh)
	// We may not need to kill the other node, but do it anyways to ensure the txn never gets committed
	nc, _ := localFixture.GetNodeController("Node")
	err := nc.FullStop()
	a.NoError(err)

	minTxnFee, minAcctBalance, err := localFixture.CurrentMinFeeAndBalance()
	a.NoError(err)

	// Check that a single pending txn is corectly displayed
	tx, err := testClient.SendPaymentFromUnencryptedWallet(fromAddress, toAddress, minTxnFee, minAcctBalance, nil)
	a.NoError(err)
	statusResponse, err := testClient.GetParsedPendingTransactions(0)
	a.NoError(err)
	a.NotEmpty(statusResponse)
	a.True(statusResponse.TotalTransactions == 1)
	a.True(len(statusResponse.TopTransactions) == 1)

	// Parse response into SignedTxn
	pendingTxn := statusResponse.TopTransactions[0]
	a.True(pendingTxn.Txn.ID().String() == tx.ID().String())
}

func TestClientTruncatesPendingTransactions(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient
	wh, _ := testClient.GetUnencryptedWalletHandle()
	nc, _ := localFixture.GetNodeController("Node")
	err := nc.FullStop()
	a.NoError(err)

	minTxnFee, minAcctBalance, err := localFixture.CurrentMinFeeAndBalance()
	a.NoError(err)

	NumTxns := 10
	MaxTxns := 7
	addresses, _ := testClient.ListAddresses(wh)
	fromAddress := addresses[0]
	txIDsSeen := make(map[string]bool)
	for i := 0; i < NumTxns; i++ {
		toAddress, _ := testClient.GenerateAddress(wh)
		tx2, err := testClient.SendPaymentFromUnencryptedWallet(fromAddress, toAddress, minTxnFee, minAcctBalance, nil)
		a.NoError(err)
		txIDsSeen[tx2.ID().String()] = true
	}
	statusResponse, err := testClient.GetParsedPendingTransactions(uint64(MaxTxns))
	a.NoError(err)
	a.True(int(statusResponse.TotalTransactions) == NumTxns)
	a.True(len(statusResponse.TopTransactions) == MaxTxns)
	for _, tx := range statusResponse.TopTransactions {
		a.True(txIDsSeen[tx.Txn.ID().String()])
		delete(txIDsSeen, tx.Txn.ID().String())
	}
	a.True(len(txIDsSeen) == NumTxns-MaxTxns)
}

func TestClientPrioritizesPendingTransactions(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Skip("new FIFO pool does not have prioritization")
	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient
	wh, _ := testClient.GetUnencryptedWalletHandle()
	addresses, _ := testClient.ListAddresses(wh)
	fromAddress := addresses[0]
	toAddress, _ := testClient.GenerateAddress(wh)
	nc, _ := localFixture.GetNodeController("Node")
	err := nc.FullStop()
	a.NoError(err)

	minTxnFee, minAcctBalance, err := localFixture.CurrentMinFeeAndBalance()
	a.NoError(err)

	NumTxns := 5
	MaxTxns := 3
	for i := 0; i < NumTxns; i++ {
		toAddress2, _ := testClient.GenerateAddress(wh)
		_, err := testClient.SendPaymentFromUnencryptedWallet(fromAddress, toAddress2, minTxnFee, minAcctBalance, nil)
		a.NoError(err)
	}

	// Add a very high fee transaction. This should have first priority
	// (even if we don't know the encoding length of the underlying signed txn)
	txHigh, err := testClient.SendPaymentFromUnencryptedWallet(fromAddress, toAddress, minTxnFee*10, minAcctBalance, nil)
	a.NoError(err)

	statusResponse, err := testClient.GetParsedPendingTransactions(uint64(MaxTxns))
	a.NoError(err)
	a.NotEmpty(statusResponse)
	a.True(int(statusResponse.TotalTransactions) == NumTxns+1)
	a.True(len(statusResponse.TopTransactions) == MaxTxns)

	pendingTxn := statusResponse.TopTransactions[0]
	a.True(pendingTxn.Txn.ID().String() == txHigh.ID().String())
}

func TestPendingTransactionInfoInnerTxnAssetCreate(t *testing.T) {
	partitiontest.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	testClient.WaitForRound(1)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := getMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	prog := `#pragma version 5
txn ApplicationID
bz end
itxn_begin
int acfg
itxn_field TypeEnum
int 1000000
itxn_field ConfigAssetTotal
int 3
itxn_field ConfigAssetDecimals
byte "oz"
itxn_field ConfigAssetUnitName
byte "Gold"
itxn_field ConfigAssetName
byte "https://gold.rush/"
itxn_field ConfigAssetURL
byte 0x67f0cd61653bd34316160bc3f5cd3763c85b114d50d38e1f4e72c3b994411e7b
itxn_field ConfigAssetMetadataHash
itxn_submit
end:
int 1
return
`
	ops, err := logic.AssembleString(prog)
	a.NoError(err)
	approv := ops.Program
	ops, err = logic.AssembleString("#pragma version 5 \nint 1")
	clst := ops.Program
	a.NoError(err)

	gl := basics.StateSchema{}
	lc := basics.StateSchema{}

	// create app
	appCreateTxn, err := testClient.MakeUnsignedApplicationCallTx(0, nil, nil, nil, nil, nil, transactions.NoOpOC, approv, clst, gl, lc, 0)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(someAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)
	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	_, err = waitForTransaction(t, testClient, someAddress, appCreateTxID, 30*time.Second)
	a.NoError(err)

	// get app ID
	submittedAppCreateTxn, err := testClient.PendingTransactionInformationV2(appCreateTxID)
	a.NoError(err)
	a.NotNil(submittedAppCreateTxn.ApplicationIndex)
	createdAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)
	a.Greater(uint64(createdAppID), uint64(0))

	// fund app account
	appFundTxn, err := testClient.SendPaymentFromWallet(wh, nil, someAddress, createdAppID.Address().String(), 0, 1_000_000, nil, "", 0, 0)
	a.NoError(err)
	appFundTxID := appFundTxn.ID()
	_, err = waitForTransaction(t, testClient, someAddress, appFundTxID.String(), 30*time.Second)
	a.NoError(err)

	// call app, which will issue an ASA create inner txn
	appCallTxn, err := testClient.MakeUnsignedAppNoOpTx(uint64(createdAppID), nil, nil, nil, nil, nil)
	a.NoError(err)
	appCallTxn, err = testClient.FillUnsignedTxTemplate(someAddress, 0, 0, 0, appCallTxn)
	a.NoError(err)
	appCallTxnTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCallTxn)
	a.NoError(err)
	_, err = waitForTransaction(t, testClient, someAddress, appCallTxnTxID, 30*time.Second)
	a.NoError(err)

	// verify pending txn info of outer txn
	submittedAppCallTxn, err := testClient.PendingTransactionInformationV2(appCallTxnTxID)
	a.NoError(err)
	a.Nil(submittedAppCallTxn.ApplicationIndex)
	a.Nil(submittedAppCallTxn.AssetIndex)
	a.NotNil(submittedAppCallTxn.InnerTxns)
	a.Len(*submittedAppCallTxn.InnerTxns, 1)

	// verify pending txn info of inner txn
	innerTxn := (*submittedAppCallTxn.InnerTxns)[0]
	a.Nil(innerTxn.ApplicationIndex)
	a.NotNil(innerTxn.AssetIndex)
	createdAssetID := *innerTxn.AssetIndex
	a.Greater(createdAssetID, uint64(0))

	createdAssetInfo, err := testClient.AssetInformationV2(createdAssetID)
	a.NoError(err)
	a.Equal(createdAssetID, createdAssetInfo.Index)
	a.Equal(createdAppID.Address().String(), createdAssetInfo.Params.Creator)
	a.Equal(uint64(1000000), createdAssetInfo.Params.Total)
	a.Equal(uint64(3), createdAssetInfo.Params.Decimals)
	a.Equal("oz", *createdAssetInfo.Params.UnitName)
	a.Equal("Gold", *createdAssetInfo.Params.Name)
	a.Equal("https://gold.rush/", *createdAssetInfo.Params.Url)
	expectedMetadata, err := hex.DecodeString("67f0cd61653bd34316160bc3f5cd3763c85b114d50d38e1f4e72c3b994411e7b")
	a.NoError(err)
	a.Equal(expectedMetadata, *createdAssetInfo.Params.MetadataHash)
}

func TestStateProofInParticipationInfo(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	localFixture.SetConsensus(config.ConsensusProtocols{protocol.ConsensusCurrentVersion: proto})

	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient
	waitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := getMaxBalAddr(t, testClient, addresses)
	a.NotEmpty(someAddress, "no addr with funds")

	addr, err := basics.UnmarshalChecksumAddress(someAddress)
	a.NoError(err)

	params, err := testClient.SuggestedParams()
	a.NoError(err)

	firstRound := basics.Round(params.LastRound + 1)
	lastRound := basics.Round(params.LastRound + 1000)
	dilution := uint64(100)
	randomVotePKStr := randomString(32)
	var votePK crypto.OneTimeSignatureVerifier
	copy(votePK[:], randomVotePKStr)
	randomSelPKStr := randomString(32)
	var selPK crypto.VRFVerifier
	copy(selPK[:], randomSelPKStr)
	var mssRoot [merklesignature.MerkleSignatureSchemeRootSize]byte
	randomRootStr := randomString(merklesignature.MerkleSignatureSchemeRootSize)
	copy(mssRoot[:], randomRootStr)
	var gh crypto.Digest
	copy(gh[:], params.GenesisHash)

	tx := transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:      addr,
			Fee:         basics.MicroAlgos{Raw: 10000},
			FirstValid:  firstRound,
			LastValid:   lastRound,
			GenesisHash: gh,
		},
		KeyregTxnFields: transactions.KeyregTxnFields{
			VotePK:           votePK,
			SelectionPK:      selPK,
			VoteFirst:        firstRound,
			StateProofPK:     mssRoot,
			VoteLast:         lastRound,
			VoteKeyDilution:  dilution,
			Nonparticipation: false,
		},
	}
	txID, err := testClient.SignAndBroadcastTransaction(wh, nil, tx)
	a.NoError(err)
	_, err = waitForTransaction(t, testClient, someAddress, txID, 120*time.Second)
	a.NoError(err)

	account, err := testClient.AccountInformationV2(someAddress, false)
	a.NoError(err)
	a.NotNil(account.Participation.StateProofKey)

	actual := [merklesignature.MerkleSignatureSchemeRootSize]byte{}
	copy(actual[:], *account.Participation.StateProofKey)
	a.Equal(mssRoot, actual)
}

func TestStateProofParticipationKeysAPI(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture

	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient
	waitForRoundOne(t, testClient)

	partdb, err := db.MakeErasableAccessor(filepath.Join(testClient.DataDir(), "/..", "/Wallet1.0.3000.partkey"))
	a.NoError(err)

	partkey, err := account.RestoreParticipation(partdb)
	a.NoError(err)

	pRoot, err := testClient.GetParticipationKeys()
	a.NoError(err)

	actual := [merklesignature.MerkleSignatureSchemeRootSize]byte{}
	a.NotNil(pRoot[0].Key.StateProofKey)
	copy(actual[:], *pRoot[0].Key.StateProofKey)
	a.Equal(partkey.StateProofSecrets.GetVerifier().Commitment[:], actual[:])
}

func TestNilStateProofInParticipationInfo(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture

	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachV30.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient
	waitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := getMaxBalAddr(t, testClient, addresses)
	a.NotEmpty(someAddress, "no addr with funds")

	addr, err := basics.UnmarshalChecksumAddress(someAddress)
	a.NoError(err)

	params, err := testClient.SuggestedParams()
	a.NoError(err)

	firstRound := basics.Round(1)
	lastRound := basics.Round(20)
	dilution := uint64(100)
	randomVotePKStr := randomString(32)
	var votePK crypto.OneTimeSignatureVerifier
	copy(votePK[:], []byte(randomVotePKStr))
	randomSelPKStr := randomString(32)
	var selPK crypto.VRFVerifier
	copy(selPK[:], []byte(randomSelPKStr))
	var gh crypto.Digest
	copy(gh[:], params.GenesisHash)

	tx := transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:      addr,
			Fee:         basics.MicroAlgos{Raw: 10000},
			FirstValid:  firstRound,
			LastValid:   lastRound,
			GenesisHash: gh,
		},
		KeyregTxnFields: transactions.KeyregTxnFields{
			VotePK:           votePK,
			SelectionPK:      selPK,
			VoteFirst:        firstRound,
			VoteLast:         lastRound,
			VoteKeyDilution:  dilution,
			Nonparticipation: false,
		},
	}
	txID, err := testClient.SignAndBroadcastTransaction(wh, nil, tx)
	a.NoError(err)
	_, err = waitForTransaction(t, testClient, someAddress, txID, 30*time.Second)
	a.NoError(err)

	account, err := testClient.AccountInformationV2(someAddress, false)
	a.NoError(err)
	a.Nil(account.Participation.StateProofKey)
}

func TestBoxNamesByAppID(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	testClient.WaitForRound(1)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := getMaxBalAddr(t, testClient, addresses)
	if someAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	prog := `#pragma version 8
    txn ApplicationID
    bz end					// create the app
	txn NumAppArgs
	bz end					// approve when no app args
    txn ApplicationArgs 0   // [arg[0]] // fails if no args && app already exists
    byte "create"           // [arg[0], "create"] // create box named arg[1]
    ==                      // [arg[0]=?="create"]
    bz del                  // "create" ? continue : goto del
    int 5                   // [5]
    txn ApplicationArgs 1   // [5, arg[1]]
    swap
    box_create              // [] // boxes: arg[1] -> [5]byte
    assert
    b end
del:                        // delete box arg[1]
    txn ApplicationArgs 0   // [arg[0]]
    byte "delete"           // [arg[0], "delete"]
    ==                      // [arg[0]=?="delete"]
	bz set                  // "delete" ? continue : goto set
    txn ApplicationArgs 1   // [arg[1]]
    box_del                 // del boxes[arg[1]]
    assert
    b end
set:						// put arg[1] at start of box arg[0] ... so actually a _partial_ "set"
    txn ApplicationArgs 0   // [arg[0]]
    byte "set"              // [arg[0], "set"]
    ==                      // [arg[0]=?="set"]
    bz bad                  // "delete" ? continue : goto bad
    txn ApplicationArgs 1   // [arg[1]]
    int 0                   // [arg[1], 0]
    txn ApplicationArgs 2   // [arg[1], 0, arg[2]]
    box_replace             // [] // boxes: arg[1] -> replace(boxes[arg[1]], 0, arg[2])
    b end
bad:
    err
end:
    int 1
`
	ops, err := logic.AssembleString(prog)
	approval := ops.Program
	ops, err = logic.AssembleString("#pragma version 8\nint 1")
	clearState := ops.Program

	gl := basics.StateSchema{}
	lc := basics.StateSchema{}

	// create app
	appCreateTxn, err := testClient.MakeUnsignedApplicationCallTx(
		0, nil, nil, nil,
		nil, nil, transactions.NoOpOC,
		approval, clearState, gl, lc, 0,
	)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(someAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)
	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	_, err = waitForTransaction(t, testClient, someAddress, appCreateTxID, 30*time.Second)
	a.NoError(err)

	// get app ID
	submittedAppCreateTxn, err := testClient.PendingTransactionInformationV2(appCreateTxID)
	a.NoError(err)
	a.NotNil(submittedAppCreateTxn.ApplicationIndex)
	createdAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)
	a.Greater(uint64(createdAppID), uint64(0))

	// fund app account
	appFundTxn, err := testClient.SendPaymentFromWallet(
		wh, nil, someAddress, createdAppID.Address().String(),
		0, 10_000_000, nil, "", 0, 0,
	)
	a.NoError(err)
	appFundTxID := appFundTxn.ID()
	_, err = waitForTransaction(t, testClient, someAddress, appFundTxID.String(), 30*time.Second)
	a.NoError(err)

	createdBoxName := map[string]bool{}
	var createdBoxCount uint64 = 0

	// define operate box helper
	operateBoxAndSendTxn := func(operation string, boxNames []string, boxValues []string, errPrefix ...string) {
		txns := make([]transactions.Transaction, len(boxNames))
		txIDs := make(map[string]string, len(boxNames))

		for i := 0; i < len(boxNames); i++ {
			appArgs := [][]byte{
				[]byte(operation),
				[]byte(boxNames[i]),
				[]byte(boxValues[i]),
			}
			boxRef := transactions.BoxRef{
				Name:  []byte(boxNames[i]),
				Index: 0,
			}

			txns[i], err = testClient.MakeUnsignedAppNoOpTx(
				uint64(createdAppID), appArgs,
				nil, nil, nil,
				[]transactions.BoxRef{boxRef},
			)
			a.NoError(err)
			txns[i], err = testClient.FillUnsignedTxTemplate(someAddress, 0, 0, 0, txns[i])
			a.NoError(err)
			txIDs[txns[i].ID().String()] = someAddress
		}

		var gid crypto.Digest
		gid, err = testClient.GroupID(txns)
		a.NoError(err)

		stxns := make([]transactions.SignedTxn, len(boxNames))
		for i := 0; i < len(boxNames); i++ {
			txns[i].Group = gid
			wh, err = testClient.GetUnencryptedWalletHandle()
			a.NoError(err)
			stxns[i], err = testClient.SignTransactionWithWallet(wh, nil, txns[i])
			a.NoError(err)
		}

		err = testClient.BroadcastTransactionGroup(stxns)
		if len(errPrefix) == 0 {
			a.NoError(err)
			_, err = waitForTransaction(t, testClient, someAddress, txns[0].ID().String(), 30*time.Second)
			a.NoError(err)
		} else {
			a.ErrorContains(err, errPrefix[0])
		}
	}

	// `assertErrorResponse` confirms the _Result limit exceeded_ error response provides expected fields and values.
	assertErrorResponse := func(err error, expectedCount, requestedMax uint64) {
		a.Error(err)
		e := err.(client.HTTPError)
		a.Equal(400, e.StatusCode)

		var er *generated.ErrorResponse
		err = protocol.DecodeJSON([]byte(e.ErrorString), &er)
		a.NoError(err)
		a.Equal("Result limit exceeded", er.Message)
		a.Equal(uint64(100000), ((*er.Data)["max-api-box-per-application"]).(uint64))
		a.Equal(requestedMax, ((*er.Data)["max"]).(uint64))
		a.Equal(expectedCount, ((*er.Data)["total-boxes"]).(uint64))

		a.Len(*er.Data, 3, fmt.Sprintf("error response (%v) contains unverified fields.  Extend test for new fields.", *er.Data))
	}

	// `assertBoxCount` sanity checks that the REST API respects `expectedCount` through different queries against app ID = `createdAppID`.
	assertBoxCount := func(expectedCount uint64) {
		// Query without client-side limit.
		resp, err := testClient.ApplicationBoxes(uint64(createdAppID), 0)
		a.NoError(err)
		a.Len(resp.Boxes, int(expectedCount))

		// Query with requested max < expected expectedCount.
		_, err = testClient.ApplicationBoxes(uint64(createdAppID), expectedCount-1)
		assertErrorResponse(err, expectedCount, expectedCount-1)

		// Query with requested max == expected expectedCount.
		resp, err = testClient.ApplicationBoxes(uint64(createdAppID), expectedCount)
		a.NoError(err)
		a.Len(resp.Boxes, int(expectedCount))

		// Query with requested max > expected expectedCount.
		resp, err = testClient.ApplicationBoxes(uint64(createdAppID), expectedCount+1)
		a.NoError(err)
		a.Len(resp.Boxes, int(expectedCount))
	}

	// helper function, take operation and a slice of box names
	// then submit transaction group containing all operations on box names
	// Then we check these boxes are appropriately created/deleted
	operateAndMatchRes := func(operation string, boxNames []string) {
		boxValues := make([]string, len(boxNames))
		if operation == "create" {
			for i, box := range boxNames {
				keyValid, ok := createdBoxName[box]
				a.False(ok && keyValid)
				boxValues[i] = ""
			}
		} else if operation == "delete" {
			for i, box := range boxNames {
				keyValid, ok := createdBoxName[box]
				a.True(keyValid == ok)
				boxValues[i] = ""
			}
		} else {
			a.Failf("Unknown operation %s", operation)
		}

		operateBoxAndSendTxn(operation, boxNames, boxValues)

		if operation == "create" {
			for _, box := range boxNames {
				createdBoxName[box] = true
			}
			createdBoxCount += uint64(len(boxNames))
		} else if operation == "delete" {
			for _, box := range boxNames {
				createdBoxName[box] = false
			}
			createdBoxCount -= uint64(len(boxNames))
		}

		var resp generated.BoxesResponse
		resp, err = testClient.ApplicationBoxes(uint64(createdAppID), 0)
		a.NoError(err)

		expectedCreatedBoxes := make([]string, 0, createdBoxCount)
		for name, isCreate := range createdBoxName {
			if isCreate {
				expectedCreatedBoxes = append(expectedCreatedBoxes, name)
			}
		}
		sort.Strings(expectedCreatedBoxes)

		actualBoxes := make([]string, len(resp.Boxes))
		for i, box := range resp.Boxes {
			actualBoxes[i] = string(box.Name)
		}
		sort.Strings(actualBoxes)

		a.Equal(expectedCreatedBoxes, actualBoxes)
	}

	testingBoxNames := []string{
		` `,
		`     	`,
		` ? = % ;`,
		`; DROP *;`,
		`OR 1 = 1;`,
		`"      ;  SELECT * FROM kvstore; DROP acctrounds; `,
		`背负青天而莫之夭阏者，而后乃今将图南。`,
		`於浩歌狂熱之際中寒﹔於天上看見深淵。`,
		`於一切眼中看見無所有﹔於無所希望中得救。`,
		`有一遊魂，化為長蛇，口有毒牙。`,
		`不以嚙人，自嚙其身，終以殞顛。`,
		`那些智力超常的人啊`,
		`认为已经，熟悉了云和闪电的脾气`,
		`就不再迷惑，就不必了解自己，世界和他人`,
		`每天只管，被微风吹拂，与猛虎谈情`,
		`他们从来，不需要楼梯，只有窗口`,
		`把一切交付于梦境，和优美的浪潮`,
		`在这颗行星所有的酒馆，青春自由似乎理所应得`,
		`面向涣散的未来，只唱情歌，看不到坦克`,
		`在科学和啤酒都不能安抚的夜晚`,
		`他们丢失了四季，惶惑之行开始`,
		`这颗行星所有的酒馆，无法听到远方的呼喊`,
		`野心勃勃的灯火，瞬间吞没黑暗的脸庞`,
		`b64:APj/AA==`,
		`str:123.3/aa\\0`,
		string([]byte{0, 255, 254, 254}),
		string([]byte{0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF}),
		`; SELECT key from kvstore WHERE key LIKE %;`,
		`?&%!=`,
		"SELECT * FROM kvstore " + string([]byte{0, 0}) + " WHERE key LIKE %; ",
		string([]byte{'%', 'a', 'b', 'c', 0, 0, '%', 'a', '!'}),
		`
`,
		`™£´´∂ƒ∂ƒßƒ©∑®ƒß∂†¬∆`,
		`∑´´˙©˚¬∆ßåƒ√¬`,
	}

	// Happy Vanilla paths:
	resp, err := testClient.ApplicationBoxes(uint64(createdAppID), 0)
	a.NoError(err)
	a.Empty(resp.Boxes)

	// Some Un-Happy / Non-Vanilla paths:

	// Even though the next box _does not exist_ as asserted by the error below,
	// querying it for boxes _DOES NOT ERROR_. There is no easy way to tell
	// the difference between non-existing boxes for an app that once existed
	// vs. an app the NEVER existed.
	nonexistantAppIndex := uint64(1337)
	_, err = testClient.ApplicationInformation(nonexistantAppIndex)
	a.ErrorContains(err, "application does not exist")
	resp, err = testClient.ApplicationBoxes(nonexistantAppIndex, 0)
	a.NoError(err)
	a.Len(resp.Boxes, 0)

	operateBoxAndSendTxn("create", []string{``}, []string{``}, "box names may not be zero length")

	for i := 0; i < len(testingBoxNames); i += 16 {
		var strSliceTest []string
		// grouping box names to operate, and create such boxes
		if i+16 >= len(testingBoxNames) {
			strSliceTest = testingBoxNames[i:]
		} else {
			strSliceTest = testingBoxNames[i : i+16]
		}
		operateAndMatchRes("create", strSliceTest)
	}

	assertBoxCount(uint64(len(testingBoxNames)))

	for i := 0; i < len(testingBoxNames); i += 16 {
		var strSliceTest []string
		// grouping box names to operate, and delete such boxes
		if i+16 >= len(testingBoxNames) {
			strSliceTest = testingBoxNames[i:]
		} else {
			strSliceTest = testingBoxNames[i : i+16]
		}
		operateAndMatchRes("delete", strSliceTest)
	}

	resp, err = testClient.ApplicationBoxes(uint64(createdAppID), 0)
	a.NoError(err)
	a.Empty(resp.Boxes)

	// Get Box value from box name
	encodeInt := func(n uint64) []byte {
		ibytes := make([]byte, 8)
		binary.BigEndian.PutUint64(ibytes, n)
		return ibytes
	}

	boxTests := []struct {
		name        []byte
		encodedName string
		value       []byte
	}{
		{[]byte("foo"), "str:foo", []byte("bar12")},
		{encodeInt(12321), "int:12321", []byte{0, 1, 254, 3, 2}},
		{[]byte{0, 248, 255, 32}, "b64:APj/IA==", []byte("lux56")},
	}
	for _, boxTest := range boxTests {
		// Box values are 5 bytes, as defined by the test TEAL program.
		operateBoxAndSendTxn("create", []string{string(boxTest.name)}, []string{""})
		operateBoxAndSendTxn("set", []string{string(boxTest.name)}, []string{string(boxTest.value)})

		boxResponse, err := testClient.GetApplicationBoxByName(uint64(createdAppID), boxTest.encodedName)
		a.NoError(err)
		a.Equal(boxTest.name, boxResponse.Name)
		a.Equal(boxTest.value, boxResponse.Value)
	}

	const numberOfBoxesRemaining = uint64(3)
	assertBoxCount(numberOfBoxesRemaining)

	// Non-vanilla. Wasteful but correct. Can delete an app without first cleaning up its boxes.
	appAccountData, err := testClient.AccountData(createdAppID.Address().String())
	a.NoError(err)
	a.Equal(numberOfBoxesRemaining, appAccountData.TotalBoxes)
	a.Equal(uint64(30), appAccountData.TotalBoxBytes)

	// delete the app
	appDeleteTxn, err := testClient.MakeUnsignedAppDeleteTx(uint64(createdAppID), nil, nil, nil, nil, nil)
	a.NoError(err)
	appDeleteTxn, err = testClient.FillUnsignedTxTemplate(someAddress, 0, 0, 0, appDeleteTxn)
	a.NoError(err)
	appDeleteTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appDeleteTxn)
	a.NoError(err)
	_, err = waitForTransaction(t, testClient, someAddress, appDeleteTxID, 30*time.Second)
	a.NoError(err)

	_, err = testClient.ApplicationInformation(uint64(createdAppID))
	a.ErrorContains(err, "application does not exist")

	assertBoxCount(numberOfBoxesRemaining)
}
