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

package transactions

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

func TestTransaction_EstimateEncodedSize(t *testing.T) {
	addr, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	buf := make([]byte, 10)
	crypto.RandBytes(buf[:])

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	tx := Transaction{
		Type: protocol.PaymentTx,
		Header: Header{
			Sender:     addr,
			Fee:        basics.MicroAlgos{Raw: 100},
			FirstValid: basics.Round(1000),
			LastValid:  basics.Round(1000 + proto.MaxTxnLife),
			Note:       buf,
		},
		PaymentTxnFields: PaymentTxnFields{
			Receiver: addr,
			Amount:   basics.MicroAlgos{Raw: 100},
		},
	}

	require.Equal(t, 200, tx.EstimateEncodedSize())
}

func generateDummyGoNonparticpatingTransaction(addr basics.Address) (tx Transaction) {
	buf := make([]byte, 10)
	crypto.RandBytes(buf[:])

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	tx = Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: Header{
			Sender:     addr,
			Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee},
			FirstValid: 1,
			LastValid:  300,
		},
		KeyregTxnFields: KeyregTxnFields{Nonparticipation: true},
	}
	tx.KeyregTxnFields.VoteFirst = 1
	tx.KeyregTxnFields.VoteLast = 300
	tx.KeyregTxnFields.VoteKeyDilution = 1

	tx.KeyregTxnFields.Nonparticipation = true
	return tx
}

func TestGoOnlineGoNonparticipatingContradiction(t *testing.T) {
	// addr has no significance here other than being a normal valid address
	addr, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	tx := generateDummyGoNonparticpatingTransaction(addr)
	// Generate keys, they don't need to be good or secure, just present
	v := crypto.GenerateOneTimeSignatureSecrets(1, 1)
	// Also generate a new VRF key
	vrf := crypto.GenerateVRFSecrets()
	tx.KeyregTxnFields = KeyregTxnFields{
		VotePK:           v.OneTimeSignatureVerifier,
		SelectionPK:      vrf.PK,
		Nonparticipation: true,
	}
	// this tx tries to both register keys to go online, and mark an account as non-participating.
	// it is not well-formed.
	feeSink := basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
	err = tx.WellFormed(SpecialAddresses{FeeSink: feeSink}, config.Consensus[protocol.ConsensusCurrentVersion])
	require.Error(t, err)
}

func TestGoNonparticipatingWellFormed(t *testing.T) {
	// addr has no significance here other than being a normal valid address
	addr, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	tx := generateDummyGoNonparticpatingTransaction(addr)
	curProto := config.Consensus[protocol.ConsensusCurrentVersion]

	if !curProto.SupportBecomeNonParticipatingTransactions {
		t.Skipf("Skipping rest of test because current protocol version %v does not support become-nonparticipating transactions", protocol.ConsensusCurrentVersion)
	}

	// this tx is well-formed
	feeSink := basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
	err = tx.WellFormed(SpecialAddresses{FeeSink: feeSink}, curProto)
	require.NoError(t, err)
	// but it should stop being well-formed if the protocol does not support it
	curProto.SupportBecomeNonParticipatingTransactions = false
	err = tx.WellFormed(SpecialAddresses{FeeSink: feeSink}, curProto)
	require.Error(t, err)
}

func TestWellFormedErrors(t *testing.T) {
	feeSink := basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
	specialAddr := SpecialAddresses{FeeSink: feeSink}
	curProto := config.Consensus[protocol.ConsensusCurrentVersion]
	addr1, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)
	usecases := []struct {
		tx            Transaction
		spec          SpecialAddresses
		proto         config.ConsensusParams
		expectedError error
	}{
		{
			tx: Transaction{
				Type: protocol.PaymentTx,
				Header: Header{
					Sender: addr1,
					Fee:    basics.MicroAlgos{Raw: 100},
				},
			},
			spec:          specialAddr,
			proto:         curProto,
			expectedError: makeMinFeeErrorf("transaction had fee %d, which is less than the minimum %d", 100, curProto.MinTxnFee),
		},
		{
			tx: Transaction{
				Type: protocol.PaymentTx,
				Header: Header{
					Sender:     addr1,
					Fee:        basics.MicroAlgos{Raw: 1000},
					LastValid:  100,
					FirstValid: 105,
				},
			},
			spec:          specialAddr,
			proto:         curProto,
			expectedError: fmt.Errorf("transaction invalid range (%d--%d)", 105, 100),
		},
	}
	for _, usecase := range usecases {
		err := usecase.tx.WellFormed(usecase.spec, usecase.proto)
		require.Equal(t, usecase.expectedError, err)
	}
}

func TestWellFormedKeyRegistrationTx(t *testing.T) {
	// addr has no significance here other than being a normal valid address
	addr, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	tx := generateDummyGoNonparticpatingTransaction(addr)
	curProto := config.Consensus[protocol.ConsensusCurrentVersion]
	feeSink := basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
	spec := SpecialAddresses{FeeSink: feeSink}
	if !curProto.SupportBecomeNonParticipatingTransactions {
		t.Skipf("Skipping rest of test because current protocol version %v does not support become-nonparticipating transactions", protocol.ConsensusCurrentVersion)
	}

	// this tx is well-formed
	err = tx.WellFormed(spec, curProto)
	require.NoError(t, err)

	testPermutations := func(proto config.ConsensusParams, expectedErrors []error) {
		checkIdx := 0
		// The KeyregTxnFields has 6 fields : VotePK, SelectionPK, VoteFirst, VoteLast, VoteKeyDilution, Nonparticipation
		// We'll be testing all the permutations against expected results set ( i.e. set vs. clear )
		for _, votePK := range []crypto.OneTimeSignatureVerifier{crypto.OneTimeSignatureVerifier{}, crypto.OneTimeSignatureVerifier{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}} {
			for _, selectionPK := range []crypto.VRFVerifier{crypto.VRFVerifier{}, crypto.VRFVerifier{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}} {
				for _, voteFirst := range []basics.Round{basics.Round(0), basics.Round(5)} {
					for _, voteLast := range []basics.Round{basics.Round(0), basics.Round(10)} {
						for _, voteKeyDilution := range []uint64{0, 10000} {
							for _, nonParticipation := range []bool{false, true} {
								tx.KeyregTxnFields.VotePK = votePK
								tx.KeyregTxnFields.SelectionPK = selectionPK
								tx.KeyregTxnFields.VoteFirst = voteFirst
								tx.KeyregTxnFields.VoteLast = voteLast
								tx.KeyregTxnFields.VoteKeyDilution = voteKeyDilution
								tx.KeyregTxnFields.Nonparticipation = nonParticipation
								err = tx.WellFormed(spec, curProto)
								require.Equal(t, expectedErrors[checkIdx], err)
								checkIdx++
							}
						}
					}
				}
			}
		}
	}

	curProto.SupportBecomeNonParticipatingTransactions = false
	curProto.EnableKeyregCoherencyCheck = false
	expectedErrors := []error{
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
		nil,
		errKeyregTxnUnsupportedSwitchToNonParticipating,
	}
	testPermutations(curProto, expectedErrors)

	curProto.SupportBecomeNonParticipatingTransactions = true
	curProto.EnableKeyregCoherencyCheck = false
	expectedErrors = []error{
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		errKeyregTxnGoingOnlineWithNonParticipating,
		nil,
		errKeyregTxnGoingOnlineWithNonParticipating,
		nil,
		errKeyregTxnGoingOnlineWithNonParticipating,
		nil,
		errKeyregTxnGoingOnlineWithNonParticipating,
		nil,
		errKeyregTxnGoingOnlineWithNonParticipating,
		nil,
		errKeyregTxnGoingOnlineWithNonParticipating,
		nil,
		errKeyregTxnGoingOnlineWithNonParticipating,
		nil,
		errKeyregTxnGoingOnlineWithNonParticipating,
	}
	testPermutations(curProto, expectedErrors)

	curProto.SupportBecomeNonParticipatingTransactions = true
	curProto.EnableKeyregCoherencyCheck = true
	expectedErrors = []error{
		nil,
		nil,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnOfflineTransactionHasVotingRounds,
		errKeyregTxnOfflineTransactionHasVotingRounds,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnOfflineTransactionHasVotingRounds,
		errKeyregTxnOfflineTransactionHasVotingRounds,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		nil,
		errKeyregTxnGoingOnlineWithNonParticipating,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		nil,
		errKeyregTxnGoingOnlineWithNonParticipating,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnFirstVotingRoundGreaterThanLastVotingRound,
		errKeyregTxnNonCoherentVotingKeys,
		errKeyregTxnNonCoherentVotingKeys,
		nil,
		errKeyregTxnGoingOnlineWithNonParticipating,
	}
	testPermutations(curProto, expectedErrors)
}
