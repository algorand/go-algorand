// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

func TestEncoding(t *testing.T) {
	partitiontest.PartitionTest(t)

	secrets := keypair()
	zeroPayment := Transaction{Type: protocol.PaymentTx, Header: Header{Sender: basics.Address{0x01}}}
	zeroKeyReg := Transaction{Type: protocol.KeyRegistrationTx, Header: Header{Sender: basics.Address{0x01}}}
	require.NotEqual(t, zeroPayment.ID(), zeroKeyReg.ID(), "payment and key reg have the same Txid -- domain separation is broken")

	stxn1 := zeroPayment.Sign(secrets)
	stxn2 := zeroKeyReg.Sign(secrets)

	ids := make(map[Txid]bool)
	ids[stxn1.ID()] = true
	ids[stxn2.ID()] = true
	require.Len(t, ids, 2, "Signed payment and signed key reg have the same Txid -- either domain separation or txid caching is broken")

	paymentBytes := protocol.Encode(&stxn1)
	keyRegBytes := protocol.Encode(&stxn2)

	bytes := make(map[crypto.Digest]bool)
	bytes[crypto.Hash(paymentBytes)] = true
	bytes[crypto.Hash(keyRegBytes)] = true
	require.Len(t, bytes, 2, "Encoding of a signed payment and a signed key reg were identical")

	var decodedPayment, decodedKeyReg SignedTxn
	require.NoError(t, protocol.Decode(paymentBytes, &decodedPayment), "error decoding encoded signed payment")
	require.NoError(t, protocol.Decode(keyRegBytes, &decodedKeyReg), "error decoding encoded signed keyreg")

	if decodedPayment.Txn.Type != protocol.PaymentTx {
		t.Errorf("decoding a signed payment gave a signedtxn of the wrong type: %v", decodedPayment.Txn)
	}
	if decodedKeyReg.Txn.Type != protocol.KeyRegistrationTx {
		t.Errorf("decoding a signed keyreg gave a signedtxn of the wrong type: %v", decodedKeyReg.Txn)
	}
}

func TestDecodeNil(t *testing.T) {
	partitiontest.PartitionTest(t)

	// This is a regression test for improper decoding of a nil SignedTxn.
	// This is a subtle case because decoding a msgpack nil does not run
	// SignedTxn.CodecDecodeSelf().
	nilEncoding := []byte{0xc0}

	var st SignedTxn
	err := protocol.Decode(nilEncoding, &st)
	if err == nil {
		// This function used to panic when run on a zero value of SignedTxn.
		st.ID()
	}
}

func TestSignedTxnInBlockHash(t *testing.T) {
	partitiontest.PartitionTest(t)

	var stib SignedTxnInBlock
	crypto.RandBytes(stib.Txn.Sender[:])
	require.Equal(t, crypto.HashObj(&stib), stib.Hash())
}

// TestSignedTxnHasSignature pins that every signature category counts as a
// signature, including a salted-key signature nested in the LogicSig, which relies on
// LogicSig.Blank covering the SKsig field.
func TestSignedTxnHasSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makeSaltedKeySigTestFixture(t, 14, protocol.SigSchemeFalcon1024)
	nonblankSig := crypto.Signature{}
	nonblankSig[0] = 1

	tests := []struct {
		name         string
		stxn         SignedTxn
		hasSignature bool
	}{
		{name: "unsigned"},
		{name: "sig", stxn: SignedTxn{Sig: nonblankSig}, hasSignature: true},
		{name: "msig", stxn: SignedTxn{Msig: crypto.MultisigSig{Version: 1}}, hasSignature: true},
		{name: "pqsig", stxn: SignedTxn{SKsig: fixture.sksig}, hasSignature: true},
		{name: "lsig program", stxn: SignedTxn{Lsig: LogicSig{Logic: []byte{1}}}, hasSignature: true},
		{name: "lsig nested sksig only", stxn: SignedTxn{Lsig: LogicSig{SKsig: fixture.sksig}}, hasSignature: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.hasSignature, test.stxn.HasSignature())
		})
	}
}

func TestSignedTxnFeeFactorSaltedKeySignatureContribution(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusFuture]
	fixture := makeSaltedKeySigTestFixture(t, 0, protocol.SigSchemeFalcon1024)

	baseTxn := SignedTxn{Txn: fixture.txn}
	regularSigned := baseTxn
	regularSigned.Sig[0] = 1
	msigSigned := baseTxn
	msigSigned.Msig = crypto.MultisigSig{Version: 1}
	lsigSigned := baseTxn
	lsigSigned.Lsig = LogicSig{Logic: []byte{1}}
	unknownSKsigSigned := baseTxn
	unknownSKsigSigned.SKsig = SaltedKeySig{Scheme: protocol.SigScheme{'x', '1'}}
	sksigSigned := SignedTxn{Txn: fixture.txn, SKsig: fixture.sksig}
	delegatedSKsigSigned := baseTxn
	delegatedSKsigSigned.Lsig = LogicSig{Logic: []byte{1}, SKsig: fixture.sksig}
	edSaltedKeySig := SaltedKeySig{Scheme: protocol.SigSchemeEd25519}
	edSKsigSigned := SignedTxn{Txn: fixture.txn, SKsig: edSaltedKeySig}
	edDelegatedSKsigSigned := baseTxn
	edDelegatedSKsigSigned.Lsig = LogicSig{Logic: []byte{1}, SKsig: edSaltedKeySig}
	unknownDelegatedSKsigSigned := baseTxn
	unknownDelegatedSKsigSigned.Lsig = LogicSig{Logic: []byte{1}, SKsig: SaltedKeySig{Scheme: protocol.SigScheme{'x', '1'}}}
	rekeyedDelegatedSKsigSigned := delegatedSKsigSigned
	rekeyedDelegatedSKsigSigned.AuthAddr = basics.Address{2}
	programlessLsigSKsigSigned := regularSigned
	programlessLsigSKsigSigned.Lsig = LogicSig{SKsig: fixture.sksig}
	sksigAndRegularSigned := sksigSigned
	sksigAndRegularSigned.Sig[0] = 1
	regularSingletonHeartbeat := regularSigned
	regularSingletonHeartbeat.Txn.Type = protocol.HeartbeatTx
	regularSingletonHeartbeat.Txn.HeartbeatTxnFields = &HeartbeatTxnFields{}
	regularSingletonHeartbeat.Txn.PaymentTxnFields = PaymentTxnFields{}
	sksigSingletonHeartbeat := sksigSigned
	sksigSingletonHeartbeat.Txn.Type = protocol.HeartbeatTx
	sksigSingletonHeartbeat.Txn.HeartbeatTxnFields = &HeartbeatTxnFields{}
	sksigSingletonHeartbeat.Txn.PaymentTxnFields = PaymentTxnFields{}
	mixedSingletonHeartbeat := sksigAndRegularSigned
	mixedSingletonHeartbeat.Txn.Type = protocol.HeartbeatTx
	mixedSingletonHeartbeat.Txn.HeartbeatTxnFields = &HeartbeatTxnFields{}
	mixedSingletonHeartbeat.Txn.PaymentTxnFields = PaymentTxnFields{}
	sksigPaidSingletonHeartbeat := sksigSingletonHeartbeat
	sksigPaidSingletonHeartbeat.Txn.Fee = proto.MinFee()
	sksigGroupedHeartbeat := sksigSingletonHeartbeat
	sksigGroupedHeartbeat.Txn.Group = crypto.Digest{1}
	// A challenged heartbeat gets one min fee off, but still owes any signature
	// surcharge: only the base fee is discounted.
	challengedHeartbeat := regularSingletonHeartbeat
	challengedHeartbeat.Txn.HeartbeatTxnFields = &HeartbeatTxnFields{HbChallengeDiscount: true}
	sksigChallengedHeartbeat := sksigSingletonHeartbeat
	sksigChallengedHeartbeat.Txn.HeartbeatTxnFields = &HeartbeatTxnFields{HbChallengeDiscount: true}
	sksigChallengedGrouped := sksigChallengedHeartbeat
	sksigChallengedGrouped.Txn.Group = crypto.Digest{1}
	delegatedSKsigSingletonHeartbeat := sksigSingletonHeartbeat
	delegatedSKsigSingletonHeartbeat.SKsig = SaltedKeySig{}
	delegatedSKsigSingletonHeartbeat.Lsig = delegatedSKsigSigned.Lsig
	delegatedSKsigPaidSingletonHeartbeat := delegatedSKsigSingletonHeartbeat
	delegatedSKsigPaidSingletonHeartbeat.Txn.Fee = proto.MinFee()
	delegatedSKsigGroupedHeartbeat := delegatedSKsigSingletonHeartbeat
	delegatedSKsigGroupedHeartbeat.Txn.Group = crypto.Digest{1}

	for _, stxn := range []SignedTxn{baseTxn, regularSigned, msigSigned, lsigSigned} {
		require.Equal(t, basics.Micros(1e6), stxn.FeeFactor(proto))
	}
	require.Equal(t, basics.Micros(2e6), SigSchemeFeeContribution(proto, protocol.SigSchemeFalcon1024))
	require.Equal(t, basics.Micros(1e6), SigSchemeFeeContribution(proto, protocol.SigSchemeFalcon512))
	require.Equal(t, basics.Micros(0), SigSchemeFeeContribution(proto, protocol.SigSchemeEd25519))
	require.Equal(t, basics.Micros(0.6e6), SigSchemeFeeContribution(proto, protocol.SigSchemeMLDSA44))
	require.Equal(t, basics.Micros(0.9e6), SigSchemeFeeContribution(proto, protocol.SigSchemeMLDSA65))
	require.Equal(t, basics.Micros(1.3e6), SigSchemeFeeContribution(proto, protocol.SigSchemeMLDSA87))
	// Every scheme's surcharge applies alike to direct and delegated authorization.
	for scheme, ss := range sigSchemes {
		direct := SignedTxn{Txn: fixture.txn, SKsig: SaltedKeySig{Scheme: scheme}}
		delegated := SignedTxn{Txn: fixture.txn, Lsig: LogicSig{Logic: []byte{1}, SKsig: SaltedKeySig{Scheme: scheme}}}
		require.Equal(t, 1e6+ss.fee, direct.FeeFactor(proto), scheme)
		require.Equal(t, 1e6+ss.fee, delegated.FeeFactor(proto), scheme)
	}
	require.Equal(t, basics.Micros(1e6), unknownSKsigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(1e6), unknownDelegatedSKsigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(1e6), edSKsigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(1e6), edDelegatedSKsigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), sksigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), delegatedSKsigSigned.FeeFactor(proto))
	require.Equal(t, sksigSigned.FeeFactor(proto), delegatedSKsigSigned.FeeFactor(proto))
	require.Equal(t, delegatedSKsigSigned.FeeFactor(proto), rekeyedDelegatedSKsigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), programlessLsigSKsigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), sksigAndRegularSigned.FeeFactor(proto))
	// With the explicit-discount rule a plain heartbeat pays the base fee (plus surcharges),
	// whether or not it is a singleton.
	require.Equal(t, basics.Micros(1e6), regularSingletonHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), sksigSingletonHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), mixedSingletonHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), sksigPaidSingletonHeartbeat.FeeFactor(proto))
	// A LogicSig delegated by a salted-key signature owes the same surcharge as a
	// top-level salted-key signature, so its heartbeat behaves like
	// sksigSingletonHeartbeat regardless of fee.
	require.Equal(t, basics.Micros(3e6), delegatedSKsigSingletonHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), delegatedSKsigPaidSingletonHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), sksigGroupedHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), delegatedSKsigGroupedHeartbeat.FeeFactor(proto))
	// The challenge discount removes exactly one min fee, leaving surcharges.
	require.Equal(t, basics.Micros(0), challengedHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(2e6), sksigChallengedHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(2e6), sksigChallengedGrouped.FeeFactor(proto))

	requiredFee, _, overflow := proto.MinFee().FeeForUsage(sksigSigned.FeeFactor(proto), 1e6, 0)
	require.False(t, overflow)
	require.Equal(t, proto.MinFee().Raw*3, requiredFee.Raw)

	requiredDelegatedFee, _, overflow := proto.MinFee().FeeForUsage(delegatedSKsigSigned.FeeFactor(proto), 1e6, 0)
	require.False(t, overflow)
	require.Equal(t, requiredFee, requiredDelegatedFee)

	usage, _ := SummarizeFees(WrapSignedTxnsWithAD([]SignedTxn{regularSigned, delegatedSKsigSigned}), proto)
	require.Equal(t, basics.Micros(4e6), usage)
}

// TestLogicSigSaltedKeySigFee checks that a program authorizing from an ls-scheme
// SaltedKeySig is priced by the byte like one in a LogicSig, and carries no scheme
// surcharge of its own.
func TestLogicSigSaltedKeySigFee(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusFuture]
	require.True(t, proto.TxnSizePricingEnabled())

	// Charging the Falcon surcharge here would make the off-curve form cost
	// more than the on-curve LogicSig it exists to replace.
	lsSKsigSigned := SignedTxn{SKsig: SaltedKeySig{
		Scheme:    protocol.SigSchemeLogicSig,
		PublicKey: make([]byte, proto.LogicSigMaxSize),
	}}
	require.Equal(t, basics.Micros(1e6), lsSKsigSigned.FeeFactor(proto))

	// A program is free up to the group's per-transaction allowance, whether it
	// sits in the Lsig or stands in for a salted-key signature's public key.
	group := WrapSignedTxnsWithAD([]SignedTxn{lsSKsigSigned})
	usage, _ := SummarizeFees(group, proto)
	require.Equal(t, basics.Micros(1e6), usage)

	// Beyond it, the bytes are surcharged exactly as a LogicSig's are.
	overBy := 500
	lsOver := lsSKsigSigned
	lsOver.SKsig.PublicKey = make([]byte, int(proto.LogicSigMaxSize)+overBy)
	lsigOver := SignedTxn{Lsig: LogicSig{Logic: make([]byte, int(proto.LogicSigMaxSize)+overBy)}}

	lsUsage, _ := SummarizeFees(WrapSignedTxnsWithAD([]SignedTxn{lsOver}), proto)
	lsigUsage, _ := SummarizeFees(WrapSignedTxnsWithAD([]SignedTxn{lsigOver}), proto)
	require.Equal(t, lsigUsage, lsUsage)

	surcharge, _ := proto.PerByteTxnSurcharge.MulInt(overBy)
	require.Equal(t, basics.AddSaturate(basics.Micros(1e6), surcharge), lsUsage)
}

//TODO: test multisig

func TestGetEncodedLengthDecode(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var stib SignedTxnInBlock
	stib.Txn.Type = protocol.PaymentTx
	stib.Txn.Sender = basics.Address{1}
	plain, err := stib.GetEncodedLength(false)
	require.NoError(t, err)
	require.Equal(t, len(protocol.Encode(&stib)), plain)
	checked, err := stib.GetEncodedLength(true)
	require.NoError(t, err)
	require.Equal(t, plain, checked)

	// Without its required sender, the transaction still encodes but no
	// longer decodes.
	stib.Txn.Sender = basics.Address{}
	plain, err = stib.GetEncodedLength(false)
	require.NoError(t, err)
	require.Equal(t, len(protocol.Encode(&stib)), plain)
	_, err = stib.GetEncodedLength(true)
	require.ErrorContains(t, err, "missing required field")
}
