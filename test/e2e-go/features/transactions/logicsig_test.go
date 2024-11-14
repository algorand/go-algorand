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

package transactions

import (
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestLogicSigSizeBeforePooling(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)
	a := require.New(fixtures.SynchronizedTest(t))

	// From consensus version 18, we have lsigs with a maximum size of 1000 bytes.
	// We need to use pragma 1 for teal in v18
	pragma := uint(1)
	tealOK, err := txntest.GenerateProgramOfSize(1000, pragma)
	a.NoError(err)
	tealTooLong, err := txntest.GenerateProgramOfSize(1001, pragma)
	a.NoError(err)

	testLogicSize(t, tealOK, tealTooLong, filepath.Join("nettemplates", "TwoNodes50EachV18.json"))
}

func TestLogicSigSizeAfterPooling(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)
	a := require.New(fixtures.SynchronizedTest(t))

	pragma := uint(1)
	tealOK, err := txntest.GenerateProgramOfSize(2000, pragma)
	a.NoError(err)
	tealTooLong, err := txntest.GenerateProgramOfSize(2001, pragma)
	a.NoError(err)

	// TODO: Update this when lsig pooling graduates from vFuture
	testLogicSize(t, tealOK, tealTooLong, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))
}

// testLogicSize takes two TEAL programs, one expected to be ok and one expected to be too long
// and thus to be rejected, and tests that's indeed the case.
func testLogicSize(t *testing.T, tealOK, tealTooLong []byte,
	networkTemplate string) {

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, networkTemplate)
	defer fixture.Shutdown()

	client := fixture.LibGoalClient
	accountList, err := fixture.GetWalletsSortedByBalance()
	a.NoError(err)
	baseAcct := accountList[0].Address

	walletHandler, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)

	signatureOK, err := client.SignProgramWithWallet(walletHandler, nil, baseAcct, tealOK)
	a.NoError(err)
	lsigOK := transactions.LogicSig{Logic: tealOK, Sig: signatureOK}

	signatureTooLong, err := client.SignProgramWithWallet(walletHandler, nil, baseAcct, tealTooLong)
	a.NoError(err)
	lsigTooLong := transactions.LogicSig{Logic: tealTooLong, Sig: signatureTooLong}

	// We build two transaction groups of two transactions each.
	// The first txn will be either signed by an ok lsig or a too long one.
	// The second is a vanilla payment transaction to complete the group.
	var txn1Success, txn2Success, txn1Fail, txn2Fail transactions.Transaction
	for i, txn := range []*transactions.Transaction{&txn1Success, &txn2Success, &txn1Fail, &txn2Fail} {
		*txn, err = client.ConstructPayment(baseAcct, baseAcct, 0, uint64(i), nil, "", [32]byte{}, 0, 0)
		a.NoError(err)
	}

	// success group
	gidSuccess, err := client.GroupID([]transactions.Transaction{txn1Success, txn2Success})
	a.NoError(err)

	txn1Success.Group = gidSuccess
	stxn1Success := transactions.SignedTxn{Txn: txn1Success, Lsig: lsigOK}

	txn2Success.Group = gidSuccess
	stxn2Success, err := client.SignTransactionWithWallet(walletHandler, nil, txn2Success)
	a.NoError(err)

	err = client.BroadcastTransactionGroup([]transactions.SignedTxn{stxn1Success, stxn2Success})
	a.NoError(err)

	// fail group
	gidFail, err := client.GroupID([]transactions.Transaction{txn1Fail, txn2Fail})
	a.NoError(err)

	txn1Fail.Group = gidFail
	stxn1Fail := transactions.SignedTxn{Txn: txn1Fail, Lsig: lsigTooLong}

	txn2Fail.Group = gidFail
	stxn2Fail, err := client.SignTransactionWithWallet(walletHandler, nil, txn2Fail)
	a.NoError(err)

	cp, err := client.ConsensusParams(0)
	a.NoError(err)

	err = client.BroadcastTransactionGroup([]transactions.SignedTxn{stxn1Fail, stxn2Fail})
	if cp.EnableLogicSigSizePooling {
		a.ErrorContains(err, "more than the available pool")
	} else {
		a.ErrorContains(err, "LogicSig too long")
	}

	// wait for the second transaction in the successful group to confirm
	txn2SuccessID := txn2Success.ID().String()
	_, curRound := fixture.GetBalanceAndRound(baseAcct)
	confirmed := fixture.WaitForTxnConfirmation(curRound+5, txn2SuccessID)
	a.True(confirmed)
}
