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

package transactions

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/stateproofmsg"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

type stateproofTxnTestCase struct {
	expectedError error

	StateProofInterval uint64
	fee                basics.MicroAlgos
	note               []byte
	group              crypto.Digest
	lease              [32]byte
	rekeyValue         basics.Address
	sender             basics.Address
}

func TestUnsupportedStateProof(t *testing.T) {
	partitiontest.PartitionTest(t)

	curProto := config.Consensus[protocol.ConsensusCurrentVersion]
	curProto.StateProofInterval = 0
	err := Transaction{
		Type: protocol.StateProofTx,
		Header: Header{
			Sender: StateProofSender,
			Fee:    basics.MicroAlgos{Raw: 100},
		},
		StateProofTxnFields: StateProofTxnFields{},
	}.WellFormed(SpecialAddresses{}, curProto)
	require.ErrorContains(t, err, "state proofs not supported")
}

func (s *stateproofTxnTestCase) runIsWellFormedForTestCase() error {
	curProto := config.Consensus[protocol.ConsensusCurrentVersion]

	// edit txn params. wanted
	return Transaction{
		Type: protocol.StateProofTx,
		Header: Header{
			Sender:  s.sender,
			Fee:     s.fee,
			Note:    s.note,
			Group:   s.group,
			Lease:   s.lease,
			RekeyTo: s.rekeyValue,
		},
		StateProofTxnFields: StateProofTxnFields{},
	}.WellFormed(SpecialAddresses{}, curProto)
}

func TestWellFormedStateProofTxn(t *testing.T) {
	partitiontest.PartitionTest(t)
	// want to create different Txns, run on all of these cases the check, and have an expected result
	cases := []stateproofTxnTestCase{
		/* 0 */ {expectedError: errBadSenderInStateProofTxn, sender: basics.Address{1, 2, 3, 4}},
		/* 1 */ {expectedError: errFeeMustBeZeroInStateproofTxn, sender: StateProofSender, fee: basics.MicroAlgos{Raw: 1}},
		/* 2 */ {expectedError: errNoteMustBeEmptyInStateproofTxn, sender: StateProofSender, note: []byte{1, 2, 3}},
		/* 3 */ {expectedError: errGroupMustBeZeroInStateproofTxn, sender: StateProofSender, group: crypto.Digest{1, 2, 3}},
		/* 4 */ {expectedError: errRekeyToMustBeZeroInStateproofTxn, sender: StateProofSender, rekeyValue: basics.Address{1, 2, 3, 4}},
		/* 5 */ {expectedError: errLeaseMustBeZeroInStateproofTxn, sender: StateProofSender, lease: [32]byte{1, 2, 3, 4}},
		/* 6 */ {expectedError: nil, fee: basics.MicroAlgos{Raw: 0}, note: nil, group: crypto.Digest{}, lease: [32]byte{}, rekeyValue: basics.Address{}, sender: StateProofSender},
	}
	for i, testCase := range cases {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			t.Parallel()
			require.Equal(t, testCase.expectedError, testCase.runIsWellFormedForTestCase())
		})
	}
}

func TestStateProofTxnShouldBeZero(t *testing.T) {
	partitiontest.PartitionTest(t)

	addr1, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)

	curProto := config.Consensus[protocol.ConsensusCurrentVersion]
	curProto.StateProofInterval = 256
	txn := Transaction{
		Type: protocol.PaymentTx,
		Header: Header{
			Sender:      addr1,
			Fee:         basics.MicroAlgos{Raw: 100},
			FirstValid:  0,
			LastValid:   0,
			Note:        []byte{0, 1},
			GenesisID:   "",
			GenesisHash: crypto.Digest{},
		},
		StateProofTxnFields: StateProofTxnFields{},
	}

	const erroMsg = "type pay has non-zero fields for type stpf"
	txn.StateProofType = 1
	err = txn.WellFormed(SpecialAddresses{}, curProto)
	require.Error(t, err)
	require.Contains(t, err.Error(), erroMsg)

	txn.StateProofType = 0
	txn.Message = stateproofmsg.Message{FirstAttestedRound: 1}
	err = txn.WellFormed(SpecialAddresses{}, curProto)
	require.Error(t, err)
	require.Contains(t, err.Error(), erroMsg)

	txn.Message = stateproofmsg.Message{}
	txn.StateProof = stateproof.StateProof{SignedWeight: 100}
	err = txn.WellFormed(SpecialAddresses{}, curProto)
	require.Error(t, err)
	require.Contains(t, err.Error(), erroMsg)

	txn.StateProof = stateproof.StateProof{}
	txn.Message.LastAttestedRound = 512
	err = txn.WellFormed(SpecialAddresses{}, curProto)
	require.Error(t, err)
	require.Contains(t, err.Error(), erroMsg)

	txn.Message.LastAttestedRound = 0
	err = txn.WellFormed(SpecialAddresses{}, curProto)
	require.NoError(t, err)
}
