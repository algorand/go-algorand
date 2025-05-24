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

package apply

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

var feeSink = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}

const defaultParticipationFirstRound = 0
const defaultParticipationLastRound = 3000

// mock balances that support looking up particular balance records
type keyregTestBalances struct {
	addrs   map[basics.Address]basics.AccountData
	version protocol.ConsensusVersion
	mockCreatableBalances
}

func newKeyregTestBalances() *keyregTestBalances {
	b := &keyregTestBalances{
		addrs:   make(map[basics.Address]basics.AccountData),
		version: protocol.ConsensusCurrentVersion,
	}
	b.mockCreatableBalances = mockCreatableBalances{access: b}
	return b
}

func (balances keyregTestBalances) Get(addr basics.Address, withPendingRewards bool) (ledgercore.AccountData, error) {
	acct, err := balances.getAccount(addr, withPendingRewards)
	return ledgercore.ToAccountData(acct), err
}

func (balances keyregTestBalances) getAccount(addr basics.Address, withPendingRewards bool) (basics.AccountData, error) {
	return balances.addrs[addr], nil
}

func (balances keyregTestBalances) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return basics.Address{}, true, nil
}

func (balances keyregTestBalances) Put(addr basics.Address, ad ledgercore.AccountData) error {
	a, _ := balances.getAccount(addr, false) // ignoring not found error
	ledgercore.AssignAccountData(&a, ad)
	return balances.putAccount(addr, a)
}

func (balances keyregTestBalances) putAccount(addr basics.Address, ad basics.AccountData) error {
	balances.addrs[addr] = ad
	return nil
}

func (balances keyregTestBalances) CloseAccount(addr basics.Address) error {
	return balances.putAccount(addr, basics.AccountData{})
}

func (balances keyregTestBalances) Move(src, dst basics.Address, amount basics.MicroAlgos, srcRewards, dstRewards *basics.MicroAlgos) error {
	return nil
}

func (balances keyregTestBalances) ConsensusParams() config.ConsensusParams {
	return config.Consensus[balances.version]
}

func (balances keyregTestBalances) Round() basics.Round {
	return basics.Round(4294967296)
}

func (balances keyregTestBalances) AllocateApp(basics.Address, basics.AppIndex, bool, basics.StateSchema) error {
	return nil
}

func (balances keyregTestBalances) DeallocateApp(basics.Address, basics.AppIndex, bool) error {
	return nil
}

func (balances keyregTestBalances) AllocateAsset(addr basics.Address, index basics.AssetIndex, global bool) error {
	return nil
}

func (balances keyregTestBalances) DeallocateAsset(addr basics.Address, index basics.AssetIndex, global bool) error {
	return nil
}

func (balances keyregTestBalances) StatefulEval(int, *logic.EvalParams, basics.AppIndex, []byte) (bool, transactions.EvalDelta, error) {
	return false, transactions.EvalDelta{}, nil
}

func TestKeyregApply(t *testing.T) {
	partitiontest.PartitionTest(t)

	src := ledgertesting.RandomAddress()
	vrfSecrets := crypto.GenerateVRFSecrets()
	sigVerifier := crypto.SignatureVerifier{0x02, 0x03, 0x04}

	tx := createTestKeyreg(t, src, sigVerifier, vrfSecrets)
	err := Keyreg(tx.KeyregTxnFields, tx.Header, makeMockBalances(protocol.ConsensusCurrentVersion), spec, nil, basics.Round(0))
	require.NoError(t, err)

	mockBal := newKeyregTestBalances()

	// Going from offline to online should be okay
	mockBal.addrs[src] = basics.AccountData{Status: basics.Offline}
	err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(0))
	require.NoError(t, err)

	// Going from online to nonparticipatory should be okay, if the protocol supports that
	if mockBal.ConsensusParams().SupportBecomeNonParticipatingTransactions {
		tx.KeyregTxnFields = transactions.KeyregTxnFields{}
		tx.KeyregTxnFields.Nonparticipation = true
		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(0))
		require.NoError(t, err)

		// Nonparticipatory accounts should not be able to change status
		mockBal.addrs[src] = basics.AccountData{Status: basics.NotParticipating}
		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(0))
		require.ErrorContains(t, err, "cannot change online/offline status of non-participating account")
	}

	mockBal.version = "future"
	if mockBal.ConsensusParams().EnableKeyregCoherencyCheck {
		tx = transactions.Transaction{
			Type: protocol.KeyRegistrationTx,
			Header: transactions.Header{
				Sender:     src,
				Fee:        basics.MicroAlgos{Raw: 1},
				FirstValid: basics.Round(1000),
				LastValid:  basics.Round(1200),
			},
			KeyregTxnFields: transactions.KeyregTxnFields{
				VotePK:          crypto.OneTimeSignatureVerifier(sigVerifier),
				SelectionPK:     vrfSecrets.PK,
				VoteKeyDilution: 1000,
				VoteFirst:       500,
				VoteLast:        1000,
			},
		}
		mockBal.addrs[src] = basics.AccountData{Status: basics.Offline}
		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(999))
		require.NoError(t, err)

		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(1000))
		require.Equal(t, errKeyregGoingOnlineExpiredParticipationKey, err)

		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(1001))
		require.Equal(t, errKeyregGoingOnlineExpiredParticipationKey, err)

		tx.KeyregTxnFields.VoteFirst = basics.Round(1100)
		tx.KeyregTxnFields.VoteLast = basics.Round(1200)

		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(1098))
		require.Equal(t, errKeyregGoingOnlineFirstVotingInFuture, err)

		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(1099))
		require.NoError(t, err)

		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(1100))
		require.NoError(t, err)

		testStateProofPKBeingStored(t, tx, mockBal)
	}
}

func testStateProofPKBeingStored(t *testing.T, tx transactions.Transaction, mockBal *keyregTestBalances) {
	err := Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(1100))
	require.NoError(t, err) // expects no error with empty keyRegistration attempt

	rec, err := mockBal.Get(tx.Header.Sender, false)
	require.NoError(t, err) // expects no error with empty keyRegistration attempt
	require.Equal(t, tx.KeyregTxnFields.StateProofPK, rec.StateProofID)
}

func TestStateProofPKKeyReg(t *testing.T) {
	partitiontest.PartitionTest(t)

	src := ledgertesting.RandomAddress()
	vrfSecrets := crypto.GenerateVRFSecrets()
	sigVerifier := crypto.SignatureVerifier{0x01, 0x02}

	tx := createTestKeyreg(t, src, sigVerifier, vrfSecrets)
	mockBal := makeMockBalances(protocol.ConsensusV30)
	err := Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(0))
	require.NoError(t, err)

	acct, err := mockBal.Get(tx.Src(), false)
	require.NoError(t, err)
	require.True(t, acct.StateProofID.IsEmpty())

	mockBal = makeMockBalances(protocol.ConsensusCurrentVersion)
	err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(0))
	require.NoError(t, err)

	acct, err = mockBal.Get(tx.Src(), false)
	require.NoError(t, err)
	require.False(t, acct.StateProofID.IsEmpty())

	// go offline in current consensus version: StateProofID should be empty
	emptyKeyreg := transactions.KeyregTxnFields{}
	err = Keyreg(emptyKeyreg, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(0))
	require.NoError(t, err)

	acct, err = mockBal.Get(tx.Src(), false)
	require.NoError(t, err)
	require.True(t, acct.StateProofID.IsEmpty())

	// run same test using vFuture
	mockBal = makeMockBalances(protocol.ConsensusFuture)
	err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(0))
	require.NoError(t, err)

	acct, err = mockBal.Get(tx.Src(), false)
	require.NoError(t, err)
	require.False(t, acct.StateProofID.IsEmpty())

	// go offline in vFuture: StateProofID should be empty
	err = Keyreg(emptyKeyreg, tx.Header, mockBal, transactions.SpecialAddresses{}, nil, basics.Round(0))
	require.NoError(t, err)

	acct, err = mockBal.Get(tx.Src(), false)
	require.NoError(t, err)
	require.True(t, acct.StateProofID.IsEmpty())

}

func createTestKeyreg(t *testing.T, src basics.Address, sigVerifier crypto.SignatureVerifier, vrfSecrets *crypto.VRFSecrets) transactions.Transaction {
	return createTestKeyregWithPeriod(t, src, sigVerifier, vrfSecrets, defaultParticipationFirstRound, defaultParticipationLastRound)
}

func createTestKeyregWithPeriod(t *testing.T, src basics.Address, sigVerifier crypto.SignatureVerifier, vrfSecrets *crypto.VRFSecrets, firstRound basics.Round, lastRound basics.Round) transactions.Transaction {
	store, err := db.MakeAccessor("test-DB", false, true)
	require.NoError(t, err)
	defer store.Close()
	root, err := account.GenerateRoot(store)
	require.NoError(t, err)
	p, err := account.FillDBWithParticipationKeys(store, root.Address(), firstRound, lastRound, config.Consensus[protocol.ConsensusCurrentVersion].DefaultKeyDilution)
	signer := p.Participation.StateProofSecrets

	return transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:     src,
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: defaultParticipationFirstRound,
			LastValid:  defaultParticipationLastRound,
		},
		KeyregTxnFields: transactions.KeyregTxnFields{
			VotePK:       crypto.OneTimeSignatureVerifier(sigVerifier),
			SelectionPK:  vrfSecrets.PK,
			StateProofPK: signer.GetVerifier().Commitment,
			VoteFirst:    0,
			VoteLast:     100,
		},
	}
}
