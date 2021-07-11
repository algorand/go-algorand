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

package apply

import (
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

var feeSink = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}

// mock balances that support looking up particular balance records
type keyregTestBalances struct {
	addrs   map[basics.Address]basics.AccountData
	version protocol.ConsensusVersion
}

func (balances keyregTestBalances) Get(addr basics.Address, withPendingRewards bool) (basics.AccountData, error) {
	return balances.addrs[addr], nil
}

func (balances keyregTestBalances) GetCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return basics.Address{}, true, nil
}

func (balances keyregTestBalances) Put(addr basics.Address, ad basics.AccountData) error {
	balances.addrs[addr] = ad
	return nil
}

func (balances keyregTestBalances) PutWithCreatable(basics.Address, basics.AccountData, *basics.CreatableLocator, *basics.CreatableLocator) error {
	return nil
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

func (balances keyregTestBalances) Allocate(basics.Address, basics.AppIndex, bool, basics.StateSchema) error {
	return nil
}

func (balances keyregTestBalances) Deallocate(basics.Address, basics.AppIndex, bool) error {
	return nil
}

func (balances keyregTestBalances) StatefulEval(logic.EvalParams, basics.AppIndex, []byte) (bool, basics.EvalDelta, error) {
	return false, basics.EvalDelta{}, nil
}

func TestKeyregApply(t *testing.T) {
	secretSrc := keypair()
	src := basics.Address(secretSrc.SignatureVerifier)
	vrfSecrets := crypto.GenerateVRFSecrets()
	secretParticipation := keypair()

	tx := transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:     src,
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: basics.Round(100),
			LastValid:  basics.Round(1000),
		},
		KeyregTxnFields: transactions.KeyregTxnFields{
			VotePK:      crypto.OneTimeSignatureVerifier(secretParticipation.SignatureVerifier),
			SelectionPK: vrfSecrets.PK,
			VoteFirst:   0,
			VoteLast:    100,
		},
	}
	err := Keyreg(tx.KeyregTxnFields, tx.Header, makeMockBalances(protocol.ConsensusCurrentVersion), transactions.SpecialAddresses{FeeSink: feeSink}, nil, basics.Round(0))
	require.NoError(t, err)

	tx.Sender = feeSink
	err = Keyreg(tx.KeyregTxnFields, tx.Header, makeMockBalances(protocol.ConsensusCurrentVersion), transactions.SpecialAddresses{FeeSink: feeSink}, nil, basics.Round(0))
	require.Error(t, err)

	tx.Sender = src

	mockBal := keyregTestBalances{make(map[basics.Address]basics.AccountData), protocol.ConsensusCurrentVersion}

	// Going from offline to online should be okay
	mockBal.addrs[src] = basics.AccountData{Status: basics.Offline}
	err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{FeeSink: feeSink}, nil, basics.Round(0))
	require.NoError(t, err)

	// Going from online to nonparticipatory should be okay, if the protocol supports that
	if mockBal.ConsensusParams().SupportBecomeNonParticipatingTransactions {
		tx.KeyregTxnFields = transactions.KeyregTxnFields{}
		tx.KeyregTxnFields.Nonparticipation = true
		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{FeeSink: feeSink}, nil, basics.Round(0))
		require.NoError(t, err)

		// Nonparticipatory accounts should not be able to change status
		mockBal.addrs[src] = basics.AccountData{Status: basics.NotParticipating}
		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{FeeSink: feeSink}, nil, basics.Round(0))
		require.Error(t, err)
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
				VotePK:          crypto.OneTimeSignatureVerifier(secretParticipation.SignatureVerifier),
				SelectionPK:     vrfSecrets.PK,
				VoteKeyDilution: 1000,
				VoteFirst:       500,
				VoteLast:        1000,
			},
		}
		mockBal.addrs[src] = basics.AccountData{Status: basics.Offline}
		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{FeeSink: feeSink}, nil, basics.Round(999))
		require.NoError(t, err)

		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{FeeSink: feeSink}, nil, basics.Round(1000))
		require.Equal(t, errKeyregGoingOnlineExpiredParticipationKey, err)

		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{FeeSink: feeSink}, nil, basics.Round(1001))
		require.Equal(t, errKeyregGoingOnlineExpiredParticipationKey, err)

		tx.KeyregTxnFields.VoteFirst = basics.Round(1100)
		tx.KeyregTxnFields.VoteLast = basics.Round(1200)

		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{FeeSink: feeSink}, nil, basics.Round(1098))
		require.Equal(t, errKeyregGoingOnlineFirstVotingInFuture, err)

		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{FeeSink: feeSink}, nil, basics.Round(1099))
		require.NoError(t, err)

		err = Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{FeeSink: feeSink}, nil, basics.Round(1100))
		require.NoError(t, err)

		testBlockProofPKBeingStored(t, tx, mockBal)
	}
}

func testBlockProofPKBeingStored(t *testing.T, tx transactions.Transaction, mockBal keyregTestBalances) {
	tx.KeyregTxnFields.BlockProofPK = crypto.VerifyingKey{Type: crypto.PlaceHolderType}
	err := Keyreg(tx.KeyregTxnFields, tx.Header, mockBal, transactions.SpecialAddresses{FeeSink: feeSink}, nil, basics.Round(1100))
	require.NoError(t, err) // expects no error with empty keyRegistration attempt

	rec, err := mockBal.Get(tx.Header.Sender, false)
	require.NoError(t, err) // expects no error with empty keyRegistration attempt
	require.Equal(t, tx.KeyregTxnFields.BlockProofPK, rec.BlockProofID)
}
