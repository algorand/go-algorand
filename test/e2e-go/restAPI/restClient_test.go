// Copyright (C) 2019-2021 Algorand, Inc.
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
	"errors"
	"flag"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/require"

	algodclient "github.com/algorand/go-algorand/daemon/algod/api/client"
	kmdclient "github.com/algorand/go-algorand/daemon/kmd/client"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/testPartitioning"
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

// checks whether a string is all letters-or-spaces
func isLetterOrSpace(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsSpace(r) {
			return false
		}
	}
	return true
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

func waitForTransaction(t *testing.T, testClient libgoal.Client, fromAddress, txID string, timeout time.Duration) (tx v1.Transaction, err error) {
	a := require.New(fixtures.SynchronizedTest(t))
	rnd, err := testClient.Status()
	a.NoError(err)
	if rnd.LastRound == 0 {
		t.Fatal("it is currently round 0 but we need to wait for a transaction that might happen this round but we'll never know if that happens because ConfirmedRound==0 is indestinguishable from not having happened")
	}
	timeoutTime := time.Now().Add(30 * time.Second)
	for {
		tx, err = testClient.TransactionInformation(fromAddress, txID)
		if err != nil && strings.HasPrefix(err.Error(), "HTTP 404") {
			tx, err = testClient.PendingTransactionInformation(txID)
		}
		if err == nil {
			a.NotEmpty(tx)
			a.Empty(tx.PoolError)
			if tx.ConfirmedRound > 0 {
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
	testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	statusResponse, err := testClient.Status()
	a.NoError(err)
	a.NotEmpty(statusResponse)
	testClient.SetAPIVersionAffinity(algodclient.APIVersionV2, kmdclient.APIVersionV1)
	statusResponse2, err := testClient.Status()
	a.NoError(err)
	a.NotEmpty(statusResponse2)
	a.True(statusResponse2.LastRound >= statusResponse.LastRound)
}

func TestClientCanGetStatusAfterBlock(t *testing.T) {
	testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	statusResponse, err := testClient.WaitForRound(1)
	a.NoError(err)
	a.NotEmpty(statusResponse)
	testClient.SetAPIVersionAffinity(algodclient.APIVersionV2, kmdclient.APIVersionV1)
	statusResponse, err = testClient.WaitForRound(statusResponse.LastRound + 1)
	a.NoError(err)
	a.NotEmpty(statusResponse)
}

func TestTransactionsByAddr(t *testing.T) {
	testPartitioning.PartitionTest(t)

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
	_, err = waitForTransaction(t, testClient, someAddress, txID.String(), 15*time.Second)
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
	testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	versionResponse, err := testClient.AlgodVersions()
	a.NoError(err)
	a.NotEmpty(versionResponse)
}

func TestClientCanGetSuggestedFee(t *testing.T) {
	testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	suggestedFeeResponse, err := testClient.SuggestedFee()
	a.NoError(err)
	_ = suggestedFeeResponse // per-byte-fee is allowed to be zero
}

func TestClientCanGetMinTxnFee(t *testing.T) {
	testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	suggestedParamsRes, err := testClient.SuggestedParams()
	a.NoError(err)
	a.Truef(suggestedParamsRes.MinTxnFee > 0, "min txn fee not supplied")
}

func TestClientCanGetBlockInfo(t *testing.T) {
	testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.LibGoalClient
	waitForRoundOne(t, testClient)
	blockResponse, err := testClient.Block(1)
	a.NoError(err)
	a.NotEmpty(blockResponse)
}

func TestClientRejectsBadFromAddressWhenSending(t *testing.T) {
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

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
	txStatus, err := waitForTransaction(t, testClient, someAddress, tx.ID().String(), 15*time.Second)
	a.NoError(err)
	a.Equal(note, txStatus.Note)
}

func TestClientCanGetTransactionStatus(t *testing.T) {
	testPartitioning.PartitionTest(t)

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
	_, err = waitForTransaction(t, testClient, someAddress, tx.ID().String(), 15*time.Second)
	a.NoError(err)
}

func TestAccountBalance(t *testing.T) {
	testPartitioning.PartitionTest(t)

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
	_, err = waitForTransaction(t, testClient, someAddress, tx.ID().String(), 15*time.Second)
	a.NoError(err)

	account, err := testClient.AccountInformation(toAddress)
	a.NoError(err)
	a.Equal(account.AmountWithoutPendingRewards, uint64(100000))
	a.Truef(account.Amount >= 100000, "account must have received money, and account information endpoint must print it")
}

func TestAccountParticipationInfo(t *testing.T) {
	testPartitioning.PartitionTest(t)

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

	params, err := testClient.SuggestedParams()
	a.NoError(err)

	firstRound := basics.Round(params.LastRound + 1)
	lastRound := basics.Round(params.LastRound + 1000)
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
			VotePK:          votePK,
			SelectionPK:     selPK,
			VoteKeyDilution: dilution,
			VoteFirst:       firstRound,
			VoteLast:        lastRound,
		},
	}
	txID, err := testClient.SignAndBroadcastTransaction(wh, nil, tx)
	a.NoError(err)
	_, err = waitForTransaction(t, testClient, someAddress, txID, 15*time.Second)
	a.NoError(err)

	account, err := testClient.AccountInformation(someAddress)
	a.NoError(err)
	a.Equal(randomVotePKStr, string(account.Participation.ParticipationPK), "API must print correct root voting key")
	a.Equal(randomSelPKStr, string(account.Participation.VRFPK), "API must print correct vrf key")
	a.Equal(uint64(firstRound), account.Participation.VoteFirst, "API must print correct first participation round")
	a.Equal(uint64(lastRound), account.Participation.VoteLast, "API must print correct last participation round")
	a.Equal(dilution, account.Participation.VoteKeyDilution, "API must print correct key dilution")
}

func TestSupply(t *testing.T) {
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	defer fixture.SetTestContext(t)()
	testClient := fixture.AlgodClient
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	goRoutines, err := testClient.GetGoRoutines(ctx)
	a.NoError(err)
	a.NotEmpty(goRoutines)
	a.True(strings.Index(goRoutines, "goroutine profile:") >= 0)
}

func TestSendingTooMuchFails(t *testing.T) {
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

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
	testPartitioning.PartitionTest(t)

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
	statusResponse, err := testClient.GetPendingTransactions(0)
	a.NoError(err)
	a.NotEmpty(statusResponse)
	a.True(statusResponse.TotalTxns == 1)
	a.True(len(statusResponse.TruncatedTxns.Transactions) == 1)
	a.True(statusResponse.TruncatedTxns.Transactions[0].TxID == tx.ID().String())

}

func TestClientTruncatesPendingTransactions(t *testing.T) {
	testPartitioning.PartitionTest(t)

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

	statusResponse, err := testClient.GetPendingTransactions(uint64(MaxTxns))
	a.NoError(err)
	a.NotEmpty(statusResponse)
	a.True(int(statusResponse.TotalTxns) == NumTxns)
	a.True(len(statusResponse.TruncatedTxns.Transactions) == MaxTxns)
	for _, tx := range statusResponse.TruncatedTxns.Transactions {
		a.True(txIDsSeen[tx.TxID])
		delete(txIDsSeen, tx.TxID)
	}
	a.True(len(txIDsSeen) == NumTxns-MaxTxns)
}

func TestClientPrioritizesPendingTransactions(t *testing.T) {
	testPartitioning.PartitionTest(t)

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

	statusResponse, err := testClient.GetPendingTransactions(uint64(MaxTxns))
	a.NoError(err)
	a.NotEmpty(statusResponse)
	a.True(int(statusResponse.TotalTxns) == NumTxns+1)
	a.True(len(statusResponse.TruncatedTxns.Transactions) == MaxTxns)
	a.True(statusResponse.TruncatedTxns.Transactions[0].TxID == txHigh.ID().String())
}
