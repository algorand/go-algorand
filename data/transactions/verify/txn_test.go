// Copyright (C) 2019-2020 Algorand, Inc.
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

package verify

import (
	"context"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/execpool"
)

var feeSink = basics.Address{0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6, 0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e, 0xa2, 0x21}
var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

var spec = transactions.SpecialAddresses{
	FeeSink:     feeSink,
	RewardsPool: poolAddr,
}

func keypair() *crypto.SignatureSecrets {
	var seed crypto.Seed
	crypto.RandBytes(seed[:])
	s := crypto.GenerateSignatureSecrets(seed)
	return s
}

func generateTestObjects(numTxs, numAccs int, blockRound basics.Round) ([]transactions.Transaction, []transactions.SignedTxn, []*crypto.SignatureSecrets, []basics.Address) {
	txs := make([]transactions.Transaction, numTxs)
	signed := make([]transactions.SignedTxn, numTxs)
	secrets := make([]*crypto.SignatureSecrets, numAccs)
	addresses := make([]basics.Address, numAccs)

	for i := 0; i < numAccs; i++ {
		secret := keypair()
		addr := basics.Address(secret.SignatureVerifier)
		secrets[i] = secret
		addresses[i] = addr
	}
	var iss, exp int
	for i := 0; i < numTxs; i++ {
		s := rand.Intn(numAccs)
		r := rand.Intn(numAccs)
		a := rand.Intn(1000)
		f := config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee + uint64(rand.Intn(10))
		if blockRound == 0 {
			iss = 50 + rand.Intn(30)
			exp = iss + 10
		} else {
			iss = int(blockRound) / 2
			exp = int(blockRound) + rand.Intn(30)
		}

		txs[i] = transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:      addresses[s],
				Fee:         basics.MicroAlgos{Raw: f},
				FirstValid:  basics.Round(iss),
				LastValid:   basics.Round(exp),
				GenesisHash: crypto.Hash([]byte{1, 2, 3, 4, 5}),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: addresses[r],
				Amount:   basics.MicroAlgos{Raw: uint64(a)},
			},
		}
		signed[i] = txs[i].Sign(secrets[s])
	}

	return txs, signed, secrets, addresses
}

func TestSignedPayment(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]

	payments, stxns, secrets, addrs := generateTestObjects(1, 1, 0)
	payment, stxn, secret, addr := payments[0], stxns[0], secrets[0], addrs[0]

	require.NoError(t, payment.WellFormed(spec, proto), "generateTestObjects generated an invalid payment")
	require.NoError(t, Txn(&stxn, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: protocol.ConsensusCurrentVersion}}), "generateTestObjects generated a bad signedtxn")

	stxn2 := payment.Sign(secret)
	require.Equal(t, stxn2.Sig, stxn.Sig, "got two different signatures for the same transaction (our signing function is deterministic)")

	stxn2.MessUpSigForTesting()
	require.Equal(t, stxn.ID(), stxn2.ID(), "changing sig caused txid to change")
	require.Error(t, Txn(&stxn2, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: protocol.ConsensusCurrentVersion}}), "verify succeeded with bad sig")

	require.True(t, crypto.SignatureVerifier(addr).Verify(payment, stxn.Sig), "signature on the transaction is not the signature of the hash of the transaction under the spender's key")
}

func TestTxnValidationEncodeDecode(t *testing.T) {
	_, signed, _, _ := generateTestObjects(100, 50, 0)

	for _, txn := range signed {
		if Txn(&txn, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: protocol.ConsensusCurrentVersion}}) != nil {
			t.Errorf("signed transaction %#v did not verify", txn)
		}

		x := protocol.Encode(&txn)
		var signedTx transactions.SignedTxn
		protocol.Decode(x, &signedTx)

		if Txn(&signedTx, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: protocol.ConsensusCurrentVersion}}) != nil {
			t.Errorf("signed transaction %#v did not verify", txn)
		}
	}
}

func TestTxnValidationEmptySig(t *testing.T) {
	_, signed, _, _ := generateTestObjects(100, 50, 0)

	for _, txn := range signed {
		if Txn(&txn, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: protocol.ConsensusCurrentVersion}}) != nil {
			t.Errorf("signed transaction %#v did not verify", txn)
		}

		txn.Sig = crypto.Signature{}
		txn.Msig = crypto.MultisigSig{}
		txn.Lsig = transactions.LogicSig{}
		if Txn(&txn, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: protocol.ConsensusCurrentVersion}}) == nil {
			t.Errorf("transaction %#v verified without sig", txn)
		}
	}
}

const ccProto = protocol.ConsensusVersion("test-compact-cert-enabled")

func TestTxnValidationCompactCert(t *testing.T) {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	proto.CompactCertRounds = 128
	config.Consensus[ccProto] = proto

	stxn := transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.CompactCertTx,
			Header: transactions.Header{
				Sender:     transactions.CompactCertSender,
				FirstValid: 0,
				LastValid:  10,
			},
		},
	}

	err := Txn(&stxn, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: ccProto}})
	require.NoError(t, err, "compact cert txn %#v did not verify", stxn)

	stxn2 := stxn
	stxn2.Txn.Type = protocol.PaymentTx
	stxn2.Txn.Header.Fee = basics.MicroAlgos{Raw: proto.MinTxnFee}
	err = Txn(&stxn2, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: ccProto}})
	require.Error(t, err, "payment txn %#v verified from CompactCertSender", stxn2)

	secret := keypair()
	stxn2 = stxn
	stxn2.Txn.Header.Sender = basics.Address(secret.SignatureVerifier)
	stxn2.Txn.Header.Fee = basics.MicroAlgos{Raw: proto.MinTxnFee}
	stxn2 = stxn2.Txn.Sign(secret)
	err = Txn(&stxn2, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: ccProto}})
	require.Error(t, err, "compact cert txn %#v verified from non-CompactCertSender", stxn2)

	// Compact cert txns are not allowed to have non-zero values for many fields
	stxn2 = stxn
	stxn2.Txn.Header.Fee = basics.MicroAlgos{Raw: proto.MinTxnFee}
	err = Txn(&stxn2, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: ccProto}})
	require.Error(t, err, "compact cert txn %#v verified", stxn2)

	stxn2 = stxn
	stxn2.Txn.Header.Note = []byte{'A'}
	err = Txn(&stxn2, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: ccProto}})
	require.Error(t, err, "compact cert txn %#v verified", stxn2)

	stxn2 = stxn
	stxn2.Txn.Lease[0] = 1
	err = Txn(&stxn2, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: ccProto}})
	require.Error(t, err, "compact cert txn %#v verified", stxn2)

	stxn2 = stxn
	stxn2.Txn.RekeyTo = basics.Address(secret.SignatureVerifier)
	err = Txn(&stxn2, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: ccProto}})
	require.Error(t, err, "compact cert txn %#v verified", stxn2)
}

func TestDecodeNil(t *testing.T) {
	// This is a regression test for improper decoding of a nil SignedTxn.
	// This is a subtle case because decoding a msgpack nil does not run
	// SignedTxn.CodecDecodeSelf().
	nilEncoding := []byte{0xc0}

	var st transactions.SignedTxn
	err := protocol.Decode(nilEncoding, &st)
	if err == nil {
		// This used to panic when run on a zero value of SignedTxn.
		Txn(&st, Context{Params: Params{CurrSpecAddrs: spec, CurrProto: protocol.ConsensusCurrentVersion}})
	}
}

func TestPaysetGroups(t *testing.T) {
	_, signedTxn, _, _ := generateTestObjects(10000, 20, 50)
	blk := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round:       50,
			GenesisHash: crypto.Hash([]byte{1, 2, 3, 4, 5}),
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusCurrentVersion,
			},
			RewardsState: bookkeeping.RewardsState{
				FeeSink:     feeSink,
				RewardsPool: poolAddr,
			},
		},
	}
	execPool := execpool.MakePool(t)
	verificationPool := execpool.MakeBacklog(execPool, 64, execpool.LowPriority, t)
	defer verificationPool.Shutdown()

	// divide the transactions into transaction groups.
	txnGroups := make([][]transactions.SignedTxn, 0, len(signedTxn))
	for i := 0; i < len(signedTxn)-16; i++ {
		txnPerGroup := rand.Intn(16)
		txnGroups = append(txnGroups, signedTxn[i:i+txnPerGroup+1])
		i += txnPerGroup
	}

	err := PaysetGroups(context.Background(), txnGroups, blk, verificationPool)
	require.NoError(t, err)

	// break the signature and see if it fails.
	txnGroups[0][0].Sig[0] = txnGroups[0][0].Sig[0] + 1
	err = PaysetGroups(context.Background(), txnGroups, blk, verificationPool)
	require.Error(t, err)

	// ensure the rest are fine
	err = PaysetGroups(context.Background(), txnGroups[1:], blk, verificationPool)
	require.NoError(t, err)
}

func BenchmarkPaysetGroups(b *testing.B) {
	if b.N < 2000 {
		b.N = 2000
	}
	_, signedTxn, _, _ := generateTestObjects(b.N, 20, 50)
	blk := bookkeeping.Block{
		BlockHeader: bookkeeping.BlockHeader{
			Round:       50,
			GenesisHash: crypto.Hash([]byte{1, 2, 3, 4, 5}),
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusCurrentVersion,
			},
			RewardsState: bookkeeping.RewardsState{
				FeeSink:     feeSink,
				RewardsPool: poolAddr,
			},
		},
	}
	execPool := execpool.MakePool(b)
	verificationPool := execpool.MakeBacklog(execPool, 64, execpool.LowPriority, b)
	defer verificationPool.Shutdown()

	// divide the transactions into transaction groups.
	txnGroups := make([][]transactions.SignedTxn, 0, len(signedTxn))
	for i := 0; i < len(signedTxn)-16; i++ {
		txnPerGroup := rand.Intn(16)
		txnGroups = append(txnGroups, signedTxn[i:i+txnPerGroup+1])
		i += txnPerGroup
	}

	b.ResetTimer()
	err := PaysetGroups(context.Background(), txnGroups, blk, verificationPool)
	require.NoError(b, err)
	b.StopTimer()
}
