// Copyright (C) 2019-2023 Algorand, Inc.
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
	"math"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/daemon/algod/api/client"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/simulation"
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

	account, err := testClient.AccountInformation(someAddress, false)
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
	submittedAppCreateTxn, err := testClient.PendingTransactionInformation(appCreateTxID)
	a.NoError(err)
	a.NotNil(submittedAppCreateTxn.ApplicationIndex)
	createdAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)
	a.NotZero(createdAppID)

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
	submittedAppCallTxn, err := testClient.PendingTransactionInformation(appCallTxnTxID)
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
	a.NotZero(createdAssetID)

	createdAssetInfo, err := testClient.AssetInformation(createdAssetID)
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

	account, err := testClient.AccountInformation(someAddress, false)
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

	account, err := testClient.AccountInformation(someAddress, false)
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
	a.NoError(err)
	approval := ops.Program
	ops, err = logic.AssembleString("#pragma version 8\nint 1")
	a.NoError(err)
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
	submittedAppCreateTxn, err := testClient.PendingTransactionInformation(appCreateTxID)
	a.NoError(err)
	a.NotNil(submittedAppCreateTxn.ApplicationIndex)
	createdAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)
	a.NotZero(createdAppID)

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

		var er *model.ErrorResponse
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

		var resp model.BoxesResponse
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

		currentRoundBeforeBoxes, err := testClient.CurrentRound()
		a.NoError(err)
		boxResponse, err := testClient.GetApplicationBoxByName(uint64(createdAppID), boxTest.encodedName)
		a.NoError(err)
		currentRoundAfterBoxes, err := testClient.CurrentRound()
		a.NoError(err)
		a.Equal(boxTest.name, boxResponse.Name)
		a.Equal(boxTest.value, boxResponse.Value)
		// To reduce flakiness, only check the round from boxes is within a range.
		a.GreaterOrEqual(boxResponse.Round, currentRoundBeforeBoxes)
		a.LessOrEqual(boxResponse.Round, currentRoundAfterBoxes)
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

func TestSimulateTxnTracerDevMode(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture
	localFixture.Setup(t, filepath.Join("nettemplates", "DevModeTxnTracerNetwork.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient

	_, err := testClient.WaitForRound(1)
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	senderBalance, senderAddress := getMaxBalAddr(t, testClient, addresses)
	if senderAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	toAddress := getDestAddr(t, testClient, nil, senderAddress, wh)
	closeToAddress := getDestAddr(t, testClient, nil, senderAddress, wh)

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
	senderBalance, senderAddress := getMaxBalAddr(t, testClient, addresses)
	if senderAddress == "" {
		t.Error("no addr with funds")
	}
	a.NoError(err)

	toAddress := getDestAddr(t, testClient, nil, senderAddress, wh)
	closeToAddress := getDestAddr(t, testClient, nil, senderAddress, wh)

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
	_, senderAddress := getMaxBalAddr(t, testClient, addresses)
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
	_, senderAddress := getMaxBalAddr(t, testClient, addresses)
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
		0, nil, nil, nil,
		nil, nil, transactions.NoOpOC,
		approval, clearState, gl, lc, 0,
	)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)
	// sign and broadcast
	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	submittedAppCreateTxn, err := waitForTransaction(t, testClient, senderAddress, appCreateTxID, 30*time.Second)
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
	_, err = waitForTransaction(t, testClient, senderAddress, appFundTxID.String(), 30*time.Second)
	a.NoError(err)

	// construct app call
	appCallTxn, err := testClient.MakeUnsignedAppNoOpTx(
		uint64(createdAppID), [][]byte{[]byte("first-arg")},
		nil, nil, nil, nil,
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

	budgetAdded, budgetUsed := uint64(700), uint64(40)
	maxLogSize, maxLogCalls := uint64(65536), uint64(2048)

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
	_, senderAddress := getMaxBalAddr(t, testClient, addresses)
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
		0, nil, nil, nil,
		nil, nil, transactions.NoOpOC,
		approval, clearState, gl, lc, 0,
	)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)
	// sign and broadcast
	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	submittedAppCreateTxn, err := waitForTransaction(t, testClient, senderAddress, appCreateTxID, 30*time.Second)
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
	_, err = waitForTransaction(t, testClient, senderAddress, appFundTxID.String(), 30*time.Second)
	a.NoError(err)

	// construct app call
	appCallTxn, err := testClient.MakeUnsignedAppNoOpTx(
		uint64(createdAppID), nil, nil, nil, nil, nil,
	)
	a.NoError(err)
	appCallTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, appCallTxn)
	a.NoError(err)
	appCallTxnSigned, err := testClient.SignTransactionWithWallet(wh, nil, appCallTxn)
	a.NoError(err)

	extraBudget := uint64(704)
	resp, err := testClient.SimulateTransactions(v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{
				Txns: []transactions.SignedTxn{appCallTxnSigned},
			},
		},
		ExtraOpcodeBudget: extraBudget,
	})
	a.NoError(err)

	budgetAdded, budgetUsed := uint64(1404), uint64(1404)

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

	// Get primary node
	primaryNode, err := fixture.GetNodeController("Primary")
	a.NoError(err)

	fixture.Start()
	defer primaryNode.FullStop()

	// get lib goal client
	testClient := fixture.LibGoalFixture.GetLibGoalClientFromNodeController(primaryNode)

	_, err = testClient.WaitForRound(1)
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, senderAddress := getMaxBalAddr(t, testClient, addresses)
	a.NotEmpty(senderAddress, "no addr with funds")
	a.NoError(err)

	ops, err := logic.AssembleString(maxDepthTealApproval)
	a.NoError(err)
	approval := ops.Program
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
		lc, nil, nil, nil, nil, nil, 0)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)

	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	submittedAppCreateTxn, err := waitForTransaction(t, testClient, senderAddress, appCreateTxID, 30*time.Second)
	a.NoError(err)
	futureAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)

	// fund app account
	appFundTxn, err := testClient.SendPaymentFromWallet(
		wh, nil, senderAddress, futureAppID.Address().String(),
		0, MinBalance*uint64(MaxDepth+1), nil, "", 0, 0,
	)
	a.NoError(err)

	uint64ToBytes := func(v uint64) []byte {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		return b
	}

	// construct app calls
	appCallTxn, err := testClient.MakeUnsignedAppNoOpTx(
		uint64(futureAppID), [][]byte{uint64ToBytes(uint64(MaxDepth))}, nil, nil, nil, nil,
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
	fixture.Start()

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
			StackPopCount:  toPtr[uint64](2),
			StackAdditions: goValuesToAvmValues(1),
		},
		// bnz main_l6
		{
			Pc:            10,
			StackPopCount: toPtr[uint64](1),
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
			StackPopCount:  toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](2),
			},
			// bnz main_l6
			{
				Pc:            10,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](2),
				StackAdditions: goValuesToAvmValues(true),
			},
			// bnz main_l3
			{
				Pc:            17,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](1),
			},
			// store 1
			{
				Pc:            25,
				StackPopCount: toPtr[uint64](1),
			},
			// store 0
			{
				Pc:            27,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](1),
			},
			// store 3
			{
				Pc:            33,
				StackPopCount: toPtr[uint64](1),
			},
			// store 2
			{
				Pc:            35,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](1),
			},
			// store 5
			{
				Pc:            41,
				StackPopCount: toPtr[uint64](1),
			},
			// store 4
			{
				Pc:            43,
				StackPopCount: toPtr[uint64](1),
			},
			// load 1
			{
				Pc:             45,
				StackAdditions: goValuesToAvmValues(1),
			},
			// assert
			{
				Pc:            47,
				StackPopCount: toPtr[uint64](1),
			},
			// load 3
			{
				Pc:             48,
				StackAdditions: goValuesToAvmValues(1),
			},
			// assert
			{
				Pc:            50,
				StackPopCount: toPtr[uint64](1),
			},
			// load 5
			{
				Pc:             51,
				StackAdditions: goValuesToAvmValues(1),
			},
			// assert
			{
				Pc:            53,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](1),
			},
			// exp
			{
				Pc:             60,
				StackAdditions: goValuesToAvmValues(1 << (MaxDepth - layer)),
				StackPopCount:  toPtr[uint64](2),
			},
			// itob
			{
				Pc:             61,
				StackAdditions: goValuesToAvmValues(uint64ToBytes(1 << uint64(MaxDepth-layer))),
				StackPopCount:  toPtr[uint64](1),
			},
			// log
			{
				Pc:            62,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](2),
			},
			// bnz main_l5
			{
				Pc:            69,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount: toPtr[uint64](1),
			},
			// int 0
			{
				Pc:             78,
				StackAdditions: goValuesToAvmValues(0),
			},
			// itxn_field Fee
			{
				Pc:            79,
				StackPopCount: toPtr[uint64](1),
			},
			// load 0
			{
				Pc:             81,
				StackAdditions: goValuesToAvmValues(approval),
			},
			// itxn_field ApprovalProgram
			{
				Pc:            83,
				StackPopCount: toPtr[uint64](1),
			},
			// load 2
			{
				Pc:             85,
				StackAdditions: goValuesToAvmValues(clearState),
			},
			// itxn_field ClearStateProgram
			{
				Pc:            87,
				StackPopCount: toPtr[uint64](1),
			},
			// itxn_submit
			{
				Pc:            89,
				SpawnedInners: &[]uint64{0},
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
				StackPopCount: toPtr[uint64](1),
			},
			// int 0
			{
				Pc:             94,
				StackAdditions: goValuesToAvmValues(0),
			},
			// itxn_field Fee
			{
				Pc:            95,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](2),
				StackAdditions: goValuesToAvmValues(uint64(2-layer) * MinBalance),
			},
			// itxn_field Amount
			{
				Pc:            104,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](1),
			},
			// concat
			{
				Pc:             117,
				StackAdditions: goValuesToAvmValues([]byte("appID" + string(uint64ToBytes(uint64(appID)+3)))),
				StackPopCount:  toPtr[uint64](2),
			},
			// sha512_256
			{
				Pc:             118,
				StackAdditions: goValuesToAvmValues(crypto.Digest(basics.AppIndex(uint64(appID) + 3).Address()).ToSlice()),
				StackPopCount:  toPtr[uint64](1),
			},
			// itxn_field Receiver
			{
				Pc:            119,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](2),
			},
			// itob
			{
				Pc:             131,
				StackAdditions: goValuesToAvmValues(uint64ToBytes(uint64(MaxDepth - layer - 1))),
				StackPopCount:  toPtr[uint64](1),
			},
			// itxn_field ApplicationArgs
			{
				Pc:            132,
				StackPopCount: toPtr[uint64](1),
			},
			// itxn CreatedApplicationID
			{
				Pc:             134,
				StackAdditions: goValuesToAvmValues(appID + 3),
			},
			// itxn_field ApplicationID
			{
				Pc:            136,
				StackPopCount: toPtr[uint64](1),
			},
			// int 0
			{
				Pc:             138,
				StackAdditions: goValuesToAvmValues(0),
			},
			// itxn_field Fee
			{
				Pc:            139,
				StackPopCount: toPtr[uint64](1),
			},
			// int DeleteApplication
			{
				Pc:             141,
				StackAdditions: goValuesToAvmValues(5),
			},
			// itxn_field OnCompletion
			{
				Pc:            143,
				StackPopCount: toPtr[uint64](1),
			},
			// itxn_submit
			{
				Pc:            145,
				SpawnedInners: &[]uint64{1, 2},
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
				StackPopCount:  toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](2),
			},
			// bnz main_l6
			{
				Pc:            10,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](2),
				StackAdditions: goValuesToAvmValues(true),
			},
			// bnz main_l3
			{
				Pc:            17,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](1),
			},
			// store 1
			{
				Pc:            25,
				StackPopCount: toPtr[uint64](1),
			},
			// store 0
			{
				Pc:            27,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](1),
			},
			// store 3
			{
				Pc:            33,
				StackPopCount: toPtr[uint64](1),
			},
			// store 2
			{
				Pc:            35,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](1),
			},
			// store 5
			{
				Pc:            41,
				StackPopCount: toPtr[uint64](1),
			},
			// store 4
			{
				Pc:            43,
				StackPopCount: toPtr[uint64](1),
			},
			// load 1
			{
				Pc:             45,
				StackAdditions: goValuesToAvmValues(1),
			},
			// assert
			{
				Pc:            47,
				StackPopCount: toPtr[uint64](1),
			},
			// load 3
			{
				Pc:             48,
				StackAdditions: goValuesToAvmValues(1),
			},
			// assert
			{
				Pc:            50,
				StackPopCount: toPtr[uint64](1),
			},
			// load 5
			{
				Pc:             51,
				StackAdditions: goValuesToAvmValues(1),
			},
			// assert
			{
				Pc:            53,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](1),
			},
			// exp
			{
				Pc:             60,
				StackAdditions: goValuesToAvmValues(1 << (MaxDepth - layer)),
				StackPopCount:  toPtr[uint64](2),
			},
			// itob
			{
				Pc:             61,
				StackAdditions: goValuesToAvmValues(uint64ToBytes(1 << uint64(MaxDepth-layer))),
				StackPopCount:  toPtr[uint64](1),
			},
			// log
			{
				Pc:            62,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](2),
			},
			// bnz main_l5
			{
				Pc:            69,
				StackPopCount: toPtr[uint64](1),
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
				StackPopCount:  toPtr[uint64](1),
			},
		}
	}

	a.Len(resp.TxnGroups[0].Txns, 2)
	a.Nil(resp.TxnGroups[0].FailureMessage)
	a.Nil(resp.TxnGroups[0].FailedAt)

	a.Nil(resp.TxnGroups[0].Txns[0].TransactionTrace)

	expectedTraceSecondTxn := &model.SimulationTransactionExecTrace{
		ApprovalProgramTrace: recursiveLongOpcodeTrace(futureAppID, 0),
		InnerTrace: &[]model.SimulationTransactionExecTrace{
			{ApprovalProgramTrace: &creationOpcodeTrace},
			{},
			{
				ApprovalProgramTrace: recursiveLongOpcodeTrace(futureAppID+3, 1),
				InnerTrace: &[]model.SimulationTransactionExecTrace{
					{ApprovalProgramTrace: &creationOpcodeTrace},
					{},
					{ApprovalProgramTrace: finalDepthTrace(futureAppID+6, 2)},
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
	primaryNode, err := fixture.GetNodeController("Primary")
	a.NoError(err)

	fixture.Start()
	defer primaryNode.FullStop()

	// get lib goal client
	testClient := fixture.LibGoalFixture.GetLibGoalClientFromNodeController(primaryNode)

	_, err = testClient.WaitForRound(1)
	a.NoError(err)

	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, senderAddress := getMaxBalAddr(t, testClient, addresses)
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
		lc, nil, nil, nil, nil, nil, 0)
	a.NoError(err)
	appCreateTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, appCreateTxn)
	a.NoError(err)

	appCreateTxID, err := testClient.SignAndBroadcastTransaction(wh, nil, appCreateTxn)
	a.NoError(err)
	submittedAppCreateTxn, err := waitForTransaction(t, testClient, senderAddress, appCreateTxID, 30*time.Second)
	a.NoError(err)
	futureAppID := basics.AppIndex(*submittedAppCreateTxn.ApplicationIndex)

	// fund app account
	appFundTxn, err := testClient.SendPaymentFromWallet(
		wh, nil, senderAddress, futureAppID.Address().String(),
		0, MinBalance, nil, "", 0, 0,
	)
	a.NoError(err)

	// construct app calls
	appCallTxn, err := testClient.MakeUnsignedAppNoOpTx(
		uint64(futureAppID), [][]byte{}, nil, nil, nil, nil,
	)
	a.NoError(err)
	appCallTxn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, MinFee, appCallTxn)
	a.NoError(err)

	// Group the transactions
	gid, err := testClient.GroupID([]transactions.Transaction{appFundTxn, appCallTxn})
	a.NoError(err)
	appFundTxn.Group = gid
	appCallTxn.Group = gid

	appFundTxnSigned, err := testClient.SignTransactionWithWallet(wh, nil, appFundTxn)
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
			{Txns: []transactions.SignedTxn{appFundTxnSigned, appCallTxnSigned}},
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
	fixture.Start()

	// simulate with wrong config (not enabled trace), see expected error
	_, err = testClient.SimulateTransactions(v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{
			{Txns: []transactions.SignedTxn{appFundTxnSigned, appCallTxnSigned}},
		},
		ExecTraceConfig: simulation.ExecTraceConfig{Scratch: true},
	})
	a.ErrorContains(err, "basic trace must be enabled when enabling scratch slot change tracing")

	// start real simulating
	resp, err := testClient.SimulateTransactions(simulateRequest)
	a.NoError(err)

	// check if resp match expected result
	a.Equal(execTraceConfig, resp.ExecTraceConfig)
	a.Len(resp.TxnGroups[0].Txns, 2)
	a.Nil(resp.TxnGroups[0].Txns[0].TransactionTrace)
	a.NotNil(resp.TxnGroups[0].Txns[1].TransactionTrace)

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
	}
	a.Equal(expectedTraceSecondTxn, resp.TxnGroups[0].Txns[1].TransactionTrace)
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
	_, senderAddress := getMaxBalAddr(t, testClient, addresses)
	a.NotEmpty(senderAddress, "no addr with funds")
	a.NoError(err)

	otherAddress := getDestAddr(t, testClient, nil, senderAddress, wh)

	// fund otherAddress
	txn, err := testClient.SendPaymentFromWallet(
		wh, nil, senderAddress, otherAddress,
		0, 1_000_000, nil, "", 0, 0,
	)
	a.NoError(err)
	txID := txn.ID().String()
	_, err = waitForTransaction(t, testClient, senderAddress, txID, 30*time.Second)
	a.NoError(err)

	// create asset
	txn, err = testClient.MakeUnsignedAssetCreateTx(100, false, "", "", "", "", "", "", "", nil, 0)
	a.NoError(err)
	txn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, txn)
	a.NoError(err)
	// sign and broadcast
	txID, err = testClient.SignAndBroadcastTransaction(wh, nil, txn)
	a.NoError(err)
	confirmedTxn, err := waitForTransaction(t, testClient, senderAddress, txID, 30*time.Second)
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
	_, err = waitForTransaction(t, testClient, otherAddress, txID, 30*time.Second)
	a.NoError(err)

	// transfer asset
	txn, err = testClient.MakeUnsignedAssetSendTx(assetID, 1, otherAddress, "", "")
	a.NoError(err)
	txn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, txn)
	a.NoError(err)
	// sign and broadcast
	txID, err = testClient.SignAndBroadcastTransaction(wh, nil, txn)
	a.NoError(err)
	_, err = waitForTransaction(t, testClient, senderAddress, txID, 30*time.Second)
	a.NoError(err)

	ops, err := logic.AssembleString("#pragma version 9\n int 1")
	a.NoError(err)
	alwaysApprove := ops.Program

	gl := basics.StateSchema{}
	lc := basics.StateSchema{}

	// create app
	txn, err = testClient.MakeUnsignedAppCreateTx(transactions.OptInOC, alwaysApprove, alwaysApprove, gl, lc, nil, nil, nil, nil, nil, 0)
	a.NoError(err)
	txn, err = testClient.FillUnsignedTxTemplate(otherAddress, 0, 0, 0, txn)
	a.NoError(err)
	// sign and broadcast
	txID, err = testClient.SignAndBroadcastTransaction(wh, nil, txn)
	a.NoError(err)
	confirmedTxn, err = waitForTransaction(t, testClient, otherAddress, txID, 30*time.Second)
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
int 1025
box_create
assert

end:
int 1
`, otherAddress, assetID, otherAppID)

	ops, err = logic.AssembleString(prog)
	a.NoError(err)
	approval := ops.Program

	// create app
	txn, err = testClient.MakeUnsignedAppCreateTx(transactions.NoOpOC, approval, alwaysApprove, gl, lc, nil, nil, nil, nil, nil, 0)
	a.NoError(err)
	txn, err = testClient.FillUnsignedTxTemplate(senderAddress, 0, 0, 0, txn)
	a.NoError(err)
	// sign and broadcast
	txID, err = testClient.SignAndBroadcastTransaction(wh, nil, txn)
	a.NoError(err)
	confirmedTxn, err = waitForTransaction(t, testClient, senderAddress, txID, 30*time.Second)
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
	_, err = waitForTransaction(t, testClient, senderAddress, txID, 30*time.Second)
	a.NoError(err)

	// construct app call
	txn, err = testClient.MakeUnsignedAppNoOpTx(
		uint64(testAppID), nil, nil, nil, nil, nil,
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
	a.Contains(*resp.TxnGroups[0].FailureMessage, "logic eval error: invalid Account reference "+otherAddress)
	a.Equal([]uint64{0}, *resp.TxnGroups[0].FailedAt)

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
		Assets:       &[]uint64{assetID},
		Apps:         &[]uint64{uint64(otherAppID)},
		Boxes:        &[]model.BoxReference{{App: uint64(testAppID), Name: []byte("A")}},
		ExtraBoxRefs: toPtr[uint64](1),
		AssetHoldings: &[]model.AssetHoldingReference{
			{Account: otherAddress, Asset: assetID},
		},
		AppLocals: &[]model.ApplicationLocalReference{
			{Account: otherAddress, App: uint64(otherAppID)},
		},
	}

	budgetAdded, budgetUsed := uint64(700), uint64(40)
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
