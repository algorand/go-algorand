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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func keypair() *crypto.SignatureSecrets {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

func TestAlgosEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)

	var a basics.MicroAlgos
	var b basics.MicroAlgos
	var i uint64

	a.Raw = 222233333
	err := protocol.Decode(protocol.Encode(&a), &b)
	if err != nil {
		panic(err)
	}
	require.Equal(t, a, b)

	a.Raw = 12345678
	err = protocol.DecodeReflect(protocol.Encode(a), &i)
	if err != nil {
		panic(err)
	}
	require.Equal(t, a.Raw, i)

	i = 87654321
	err = protocol.Decode(protocol.EncodeReflect(i), &a)
	if err != nil {
		panic(err)
	}
	require.Equal(t, a.Raw, i)

	x := true
	err = protocol.Decode(protocol.EncodeReflect(x), &a)
	if err == nil {
		panic("decode of bool into MicroAlgos succeeded")
	}
}

func TestPaymentWellFormed(t *testing.T) {
	partitiontest.PartitionTest(t)

	v7 := config.Consensus[protocol.ConsensusV7]
	v39 := config.Consensus[protocol.ConsensusV39]
	vFuture := config.Consensus[protocol.ConsensusFuture]

	secretSrc := keypair()
	src := basics.Address(secretSrc.SignatureVerifier)

	secretDst := keypair()
	dst := basics.Address(secretDst.SignatureVerifier)

	tx := Transaction{
		Type: protocol.PaymentTx,
		Header: Header{
			Sender:     src,
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: basics.Round(100),
			LastValid:  basics.Round(1000),
		},
		PaymentTxnFields: PaymentTxnFields{
			Receiver: dst,
			Amount:   basics.MicroAlgos{Raw: uint64(50)},
		},
	}

	feeSink := basics.Address{0x01}
	poolAddr := basics.Address{0x02}
	var spec = SpecialAddresses{
		FeeSink:     feeSink,
		RewardsPool: poolAddr,
	}

	tx.Sender = feeSink
	require.ErrorContains(t, tx.PaymentTxnFields.wellFormed(tx.Header, spec, v7),
		"to non incentive pool address")
	require.ErrorContains(t, tx.PaymentTxnFields.wellFormed(tx.Header, spec, v39),
		"to non incentive pool address")
	require.ErrorContains(t, tx.PaymentTxnFields.wellFormed(tx.Header, spec, vFuture),
		"cannot spend from fee sink")

	tx.Receiver = poolAddr
	require.NoError(t, tx.PaymentTxnFields.wellFormed(tx.Header, spec, v7))
	require.NoError(t, tx.PaymentTxnFields.wellFormed(tx.Header, spec, v39))
	require.ErrorContains(t, tx.PaymentTxnFields.wellFormed(tx.Header, spec, vFuture),
		"cannot spend from fee sink")

	tx.CloseRemainderTo = poolAddr
	require.ErrorContains(t, tx.PaymentTxnFields.wellFormed(tx.Header, spec, v7),
		"cannot close fee sink")
	require.ErrorContains(t, tx.PaymentTxnFields.wellFormed(tx.Header, spec, v39),
		"cannot close fee sink")
	require.ErrorContains(t, tx.PaymentTxnFields.wellFormed(tx.Header, spec, vFuture),
		"cannot spend from fee sink")

	// When not sending from fee sink, everything's fine
	tx.Sender = src
	require.NoError(t, tx.PaymentTxnFields.wellFormed(tx.Header, spec, v7))
	require.NoError(t, tx.PaymentTxnFields.wellFormed(tx.Header, spec, v39))
	require.NoError(t, tx.PaymentTxnFields.wellFormed(tx.Header, spec, vFuture))
}

func TestWellFormedPaymentErrors(t *testing.T) {
	partitiontest.PartitionTest(t)

	curProto := config.Consensus[protocol.ConsensusCurrentVersion]
	protoV27 := config.Consensus[protocol.ConsensusV27]
	addr1, err := basics.UnmarshalChecksumAddress("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
	require.NoError(t, err)
	usecases := []struct {
		tx            Transaction
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
			proto:         protoV27,
			expectedError: makeMinFeeErrorf("transaction had fee %d, which is less than the minimum %d", 100, curProto.MinTxnFee),
		},
		{
			tx: Transaction{
				Type: protocol.PaymentTx,
				Header: Header{
					Sender: addr1,
					Fee:    basics.MicroAlgos{Raw: 100},
				},
			},
			proto: curProto,
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
			proto:         curProto,
			expectedError: fmt.Errorf("transaction invalid range (%d--%d)", 105, 100),
		},
	}
	for _, usecase := range usecases {
		err := usecase.tx.WellFormed(SpecialAddresses{}, usecase.proto)
		assert.Equal(t, usecase.expectedError, err)
	}
}
