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

package multisig

import (
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/stretchr/testify/require"
)

// create a 2 out of 3 multisig address
// try to transact with 1 sig:  expect failure
// try to transact with 2 sigs: expect success
// try to transact with 3 sigs: expect success
func TestBasicMultisig(t *testing.T) {
	t.Parallel()

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer fixture.Shutdown()

	r := require.New(t)

	// create three addrs
	client := fixture.LibGoalClient
	fundingAccount, err := fixture.GetRichestAccount()
	r.NoError(err, "fixture should be able to get richest account.")
	walletHandle, err := client.GetUnencryptedWalletHandle()
	r.NoError(err, "Getting default wallet handle should not return error")
	r.NotEmpty(walletHandle, "Wallet handle should not be empty")
	const numAccounts = uint8(3)
	var addrs []string
	for i := uint8(0); i < numAccounts; i++ {
		account, err := client.GenerateAddress(walletHandle)
		r.NoError(err, "Generating address should not return error")
		r.NotEmpty(account, "Address generation should not return empty string")
		addrs = append(addrs, account)
	}
	// use the new addrs to create a 2 of 3 multisig address
	const threshold = numAccounts - 1
	multisigAddr, err := client.CreateMultisigAccount(walletHandle, threshold, addrs)
	r.NoError(err, "Unexpected error during multisig address creation")
	r.NotEmpty(multisigAddr, "Created multisig address unexpectedly empty")

	minTxnFee, minAcctBalance, err := fixture.CurrentMinFeeAndBalance()
	r.NoError(err)

	// fund the new multisig address
	fundingAddr := fundingAccount.Address
	// fund account with enough Algos to allow for 3 transactions and still keep a minBalance in the account
	amountToFund := 4*minAcctBalance + 3*minTxnFee
	curStatus, err := client.Status()
	fixture.SendMoneyAndWait(curStatus.LastRound, amountToFund, minTxnFee, fundingAddr, multisigAddr)
	// try to transact with 1 of 3
	amountToSend := minAcctBalance
	unsignedTransaction, err := client.ConstructPayment(multisigAddr, addrs[0], minTxnFee, amountToSend, nil, "", [32]byte{}, 0, 0)
	r.NoError(err, "Unexpected error when constructing payment transaction")
	emptyPartial := crypto.MultisigSig{}
	emptySignature := crypto.Signature{}
	signatureWithOne, err := client.UnencryptedMultisigSignTransaction(unsignedTransaction, addrs[0], emptyPartial)
	r.NoError(err, "first signing returned error")
	signedTransactionWithOne, err := transactions.AssembleSignedTxn(unsignedTransaction, emptySignature, signatureWithOne)
	_, err = client.BroadcastTransaction(signedTransactionWithOne)
	r.Error(err, "Trying to broadcast 2-of-3 multisig with 1 sig should fail")
	// try to transact with 2 of 3
	signatureWithTwo, err := client.UnencryptedMultisigSignTransaction(unsignedTransaction, addrs[1], signatureWithOne)
	r.NoError(err, "second signing returned error")
	signedTransactionWithTwo, err := transactions.AssembleSignedTxn(unsignedTransaction, emptySignature, signatureWithTwo)
	txid, err := client.BroadcastTransaction(signedTransactionWithTwo)
	r.NoError(err, "Trying to broadcast 2-of-3 multisig with 2 sig should not cause error")
	curStatus, _ = client.Status()
	r.True(fixture.WaitForTxnConfirmation(curStatus.LastRound+uint64(5), multisigAddr, txid))

	// Need a new txid to avoid dup detection
	unsignedTransaction, err = client.ConstructPayment(multisigAddr, addrs[0], minTxnFee, amountToSend, []byte("foobar"), "", [32]byte{}, 0, 0)
	r.NoError(err, "Unexpected error when constructing payment transaction")
	signatureWithOne, err = client.UnencryptedMultisigSignTransaction(unsignedTransaction, addrs[0], emptyPartial)
	r.NoError(err, "first signing returned error")
	signatureWithTwo, err = client.UnencryptedMultisigSignTransaction(unsignedTransaction, addrs[1], signatureWithOne)
	r.NoError(err, "second signing returned error")
	// try to transact with 3 of 3
	signatureWithThree, err := client.UnencryptedMultisigSignTransaction(unsignedTransaction, addrs[2], signatureWithTwo)
	r.NoError(err, "third signing returned error")
	signedTransactionWithThree, err := transactions.AssembleSignedTxn(unsignedTransaction, emptySignature, signatureWithThree)
	_, err = client.BroadcastTransaction(signedTransactionWithThree)
	r.NoError(err, "Trying to broadcast 2-of-3 multisig with 3 sig should not cause error")
}

// create a 0-of-3 multisig address: expect failure
func TestZeroThreshold(t *testing.T) {
	t.Parallel()

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer fixture.Shutdown()

	r := require.New(t)
	client := fixture.LibGoalClient
	walletHandle, err := client.GetUnencryptedWalletHandle()
	r.NoError(err, "Getting default wallet handle should not return error")
	r.NotEmpty(walletHandle, "Wallet handle should not be empty")
	const numAccounts = uint8(3)
	var addrs []string
	for i := uint8(0); i < numAccounts; i++ {
		account, err := client.GenerateAddress(walletHandle)
		r.NoError(err, "Generating address should not return error")
		r.NotEmpty(account, "Address generation should not return empty string")
		addrs = append(addrs, account)
	}
	const threshold = 0 // this threshold of 0 is what should cause the error
	multisigAddr, err := client.CreateMultisigAccount(walletHandle, threshold, addrs)
	r.Error(err, "expected error when creating a multisig addr with threshold of 0")
	r.Empty(multisigAddr, "should not have received an addr when creating bad multisig addr")
}

// create a 3-of-0 multisig address: expect failure
func TestZeroSigners(t *testing.T) {
	t.Parallel()

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer fixture.Shutdown()

	r := require.New(t)
	client := fixture.LibGoalClient
	walletHandle, err := client.GetUnencryptedWalletHandle()
	r.NoError(err, "Getting default wallet handle should not return error")
	r.NotEmpty(walletHandle, "Wallet handle should not be empty")
	const threshold = 3
	var addrs []string // no addrs for this test, which should cause an error

	multisigAddr, err := client.CreateMultisigAccount(walletHandle, threshold, addrs)
	r.Error(err, "expected error when creating a multisig addr with no potential signers")
	r.Empty(multisigAddr, "should not have received an addr when creating bad multisig addr")
}

// create an n-of-n+1 multisig address
// where the valid keys are all the same
// then try to transact
func TestDuplicateKeys(t *testing.T) {
	t.Parallel()

	var fixture fixtures.RestClientFixture
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer fixture.Shutdown()

	r := require.New(t)

	// create one addr
	client := fixture.LibGoalClient
	fundingAccount, err := fixture.GetRichestAccount()
	r.NoError(err, "fixture should be able to get richest account.")
	walletHandle, err := client.GetUnencryptedWalletHandle()
	r.NoError(err, "Getting default wallet handle should not return error")
	r.NotEmpty(walletHandle, "Wallet handle should not be empty")
	const numAccounts = uint8(30)
	var addrs []string
	account, err := client.GenerateAddress(walletHandle)
	r.NoError(err, "Generating address should not return error")
	r.NotEmpty(account, "Address generation should not return empty string")
	for i := uint8(0); i < numAccounts; i++ {
		addrs = append(addrs, account)
	}
	const threshold = numAccounts - 1
	// use the addr to create a "many"-keyed multisig address (where in fact each key is the same, duplicated, key)
	multisigAddr, err := client.CreateMultisigAccount(walletHandle, threshold, addrs)
	r.NoError(err, "Unexpected error during multisig address creation")
	r.NotEmpty(multisigAddr, "Created multisig address unexpectedly empty")

	minTxnFee, minAcctBalance, err := fixture.CurrentMinFeeAndBalance()
	r.NoError(err)

	// fund the new multisig address
	fundingAddr := fundingAccount.Address
	amountToFund := 3 * minAcctBalance
	txnFee := minTxnFee
	curStatus, _ := client.Status()
	fixture.SendMoneyAndWait(curStatus.LastRound, amountToFund, txnFee, fundingAddr, multisigAddr)
	// try to transact with "1" signature (though, this is a signature from "every" member of the multisig)
	amountToSend := minAcctBalance
	unsignedTransaction, err := client.ConstructPayment(multisigAddr, addrs[0], txnFee, amountToSend, nil, "", [32]byte{}, 0, 0)
	r.NoError(err, "Unexpected error when constructing payment transaction")
	emptyPartial := crypto.MultisigSig{}
	emptySignature := crypto.Signature{}
	signatureWithOne, err := client.UnencryptedMultisigSignTransaction(unsignedTransaction, addrs[0], emptyPartial)
	r.NoError(err, "Signing returned error")
	signedTransactionWithOne, err := transactions.AssembleSignedTxn(unsignedTransaction, emptySignature, signatureWithOne)
	_, err = client.BroadcastTransaction(signedTransactionWithOne)
	r.NoError(err, "One signature should be sufficient since multisig members are duplicated")
}
