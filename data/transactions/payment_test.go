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
	"testing"

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

func TestCheckSpender(t *testing.T) {
	partitiontest.PartitionTest(t)

	paramsCurrent := config.Consensus[protocol.ConsensusCurrentVersion]
	paramsV7 := config.Consensus[protocol.ConsensusV7]

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

	tx.Sender = basics.Address(feeSink)
	require.Error(t, tx.PaymentTxnFields.checkSpender(tx.Header, spec, paramsCurrent))

	tx.Receiver = poolAddr
	require.NoError(t, tx.PaymentTxnFields.checkSpender(tx.Header, spec, paramsCurrent))

	tx.CloseRemainderTo = poolAddr
	require.Error(t, tx.PaymentTxnFields.checkSpender(tx.Header, spec, paramsCurrent))
	require.Error(t, tx.PaymentTxnFields.checkSpender(tx.Header, spec, paramsV7))

	tx.Sender = src
	require.NoError(t, tx.PaymentTxnFields.checkSpender(tx.Header, spec, paramsV7))
}
