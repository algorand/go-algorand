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
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWellFormedHeartbeatErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	futureProto := config.Consensus[protocol.ConsensusFuture]
	protoV36 := config.Consensus[protocol.ConsensusV36]
	addr1, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)
	okHeader := Header{
		Sender:     addr1,
		Fee:        basics.MicroAlgos{Raw: 1000},
		LastValid:  105,
		FirstValid: 100,
	}
	usecases := []struct {
		tx            Transaction
		proto         config.ConsensusParams
		expectedError error
	}{
		{
			tx: Transaction{
				Type:   protocol.HeartbeatTx,
				Header: okHeader,
			},
			proto:         protoV36,
			expectedError: fmt.Errorf("heartbeat transaction not supported"),
		},
		{
			tx: Transaction{
				Type:   protocol.HeartbeatTx,
				Header: okHeader,
				HeartbeatTxnFields: &HeartbeatTxnFields{
					HbSeed:        committee.Seed{0x02},
					HbVoteID:      crypto.OneTimeSignatureVerifier{0x03},
					HbKeyDilution: 10,
				},
			},
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.HbProof is empty"),
		},
		{
			tx: Transaction{
				Type:   protocol.HeartbeatTx,
				Header: okHeader,
				HeartbeatTxnFields: &HeartbeatTxnFields{
					HbProof: crypto.HeartbeatProof{
						Sig: [64]byte{0x01},
					},
					HbVoteID:      crypto.OneTimeSignatureVerifier{0x03},
					HbKeyDilution: 10,
				},
			},
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.HbSeed is empty"),
		},
		{
			tx: Transaction{
				Type:   protocol.HeartbeatTx,
				Header: okHeader,
				HeartbeatTxnFields: &HeartbeatTxnFields{
					HbProof: crypto.HeartbeatProof{
						Sig: [64]byte{0x01},
					},
					HbSeed:        committee.Seed{0x02},
					HbKeyDilution: 10,
				},
			},
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.HbVoteID is empty"),
		},
		{
			tx: Transaction{
				Type:   protocol.HeartbeatTx,
				Header: okHeader,
				HeartbeatTxnFields: &HeartbeatTxnFields{
					HbProof: crypto.HeartbeatProof{
						Sig: [64]byte{0x01},
					},
					HbSeed:   committee.Seed{0x02},
					HbVoteID: crypto.OneTimeSignatureVerifier{0x03},
				},
			},
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.HbKeyDilution is zero"),
		},
		{
			tx: Transaction{
				Type:   protocol.HeartbeatTx,
				Header: okHeader,
				HeartbeatTxnFields: &HeartbeatTxnFields{
					HbProof: crypto.HeartbeatProof{
						Sig: [64]byte{0x01},
					},
					HbSeed:        committee.Seed{0x02},
					HbVoteID:      crypto.OneTimeSignatureVerifier{0x03},
					HbKeyDilution: 10,
				},
			},
			proto: futureProto,
		},
		{
			tx: Transaction{
				Type: protocol.HeartbeatTx,
				Header: Header{
					Sender:     addr1,
					Fee:        basics.MicroAlgos{Raw: 100},
					LastValid:  105,
					FirstValid: 100,
					Note:       []byte{0x01},
				},
				HeartbeatTxnFields: &HeartbeatTxnFields{
					HbProof: crypto.HeartbeatProof{
						Sig: [64]byte{0x01},
					},
					HbSeed:        committee.Seed{0x02},
					HbVoteID:      crypto.OneTimeSignatureVerifier{0x03},
					HbKeyDilution: 10,
				},
			},
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.Note is set in cheap heartbeat"),
		},
		{
			tx: Transaction{
				Type: protocol.HeartbeatTx,
				Header: Header{
					Sender:     addr1,
					Fee:        basics.MicroAlgos{Raw: 100},
					LastValid:  105,
					FirstValid: 100,
					Lease:      [32]byte{0x01},
				},
				HeartbeatTxnFields: &HeartbeatTxnFields{
					HbProof: crypto.HeartbeatProof{
						Sig: [64]byte{0x01},
					},
					HbSeed:        committee.Seed{0x02},
					HbVoteID:      crypto.OneTimeSignatureVerifier{0x03},
					HbKeyDilution: 10,
				},
			},
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.Lease is set in cheap heartbeat"),
		},
		{
			tx: Transaction{
				Type: protocol.HeartbeatTx,
				Header: Header{
					Sender:     addr1,
					LastValid:  105,
					FirstValid: 100,
					RekeyTo:    [32]byte{0x01},
				},
				HeartbeatTxnFields: &HeartbeatTxnFields{
					HbProof: crypto.HeartbeatProof{
						Sig: [64]byte{0x01},
					},
					HbSeed:        committee.Seed{0x02},
					HbVoteID:      crypto.OneTimeSignatureVerifier{0x03},
					HbKeyDilution: 10,
				},
			},
			proto:         futureProto,
			expectedError: fmt.Errorf("tx.RekeyTo is set in free heartbeat"),
		},
	}
	for _, usecase := range usecases {
		err := usecase.tx.WellFormed(SpecialAddresses{}, usecase.proto)
		assert.Equal(t, usecase.expectedError, err)
	}
}
