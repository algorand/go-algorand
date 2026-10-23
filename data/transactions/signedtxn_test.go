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
// signature, including a hashed-key signature nested in the LogicSig, which relies on
// LogicSig.Blank covering the Hsig field.
func TestSignedTxnHasSignature(t *testing.T) {
	partitiontest.PartitionTest(t)

	fixture := makeHashedKeySigTestFixture(t, 14, protocol.SigSchemeFalcon1024)
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
		{name: "pqsig", stxn: SignedTxn{Hsig: fixture.hsig}, hasSignature: true},
		{name: "lsig program", stxn: SignedTxn{Lsig: LogicSig{Logic: []byte{1}}}, hasSignature: true},
		{name: "lsig nested hsig only", stxn: SignedTxn{Lsig: LogicSig{Hsig: fixture.hsig}}, hasSignature: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.hasSignature, test.stxn.HasSignature())
		})
	}
}

func TestSignedTxnFeeFactorHashedKeySignatureContribution(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusFuture]
	fixture := makeHashedKeySigTestFixture(t, 0, protocol.SigSchemeFalcon1024)

	baseTxn := SignedTxn{Txn: fixture.txn}
	regularSigned := baseTxn
	regularSigned.Sig[0] = 1
	msigSigned := baseTxn
	msigSigned.Msig = crypto.MultisigSig{Version: 1}
	lsigSigned := baseTxn
	lsigSigned.Lsig = LogicSig{Logic: []byte{1}}
	unknownHsigSigned := baseTxn
	unknownHsigSigned.Hsig = HashedKeySig{Scheme: protocol.SigScheme{'x', '1'}}
	hsigSigned := SignedTxn{Txn: fixture.txn, Hsig: fixture.hsig}
	delegatedHsigSigned := baseTxn
	delegatedHsigSigned.Lsig = LogicSig{Logic: []byte{1}, Hsig: fixture.hsig}
	edHashedKeySig := HashedKeySig{Scheme: protocol.SigSchemeEd25519}
	edHsigSigned := SignedTxn{Txn: fixture.txn, Hsig: edHashedKeySig}
	edDelegatedHsigSigned := baseTxn
	edDelegatedHsigSigned.Lsig = LogicSig{Logic: []byte{1}, Hsig: edHashedKeySig}
	unknownDelegatedHsigSigned := baseTxn
	unknownDelegatedHsigSigned.Lsig = LogicSig{Logic: []byte{1}, Hsig: HashedKeySig{Scheme: protocol.SigScheme{'x', '1'}}}
	rekeyedDelegatedHsigSigned := delegatedHsigSigned
	rekeyedDelegatedHsigSigned.AuthAddr = basics.Address{2}
	programlessLsigHsigSigned := regularSigned
	programlessLsigHsigSigned.Lsig = LogicSig{Hsig: fixture.hsig}
	hsigAndRegularSigned := hsigSigned
	hsigAndRegularSigned.Sig[0] = 1
	regularSingletonHeartbeat := regularSigned
	regularSingletonHeartbeat.Txn.Type = protocol.HeartbeatTx
	regularSingletonHeartbeat.Txn.HeartbeatTxnFields = &HeartbeatTxnFields{}
	regularSingletonHeartbeat.Txn.PaymentTxnFields = PaymentTxnFields{}
	hsigSingletonHeartbeat := hsigSigned
	hsigSingletonHeartbeat.Txn.Type = protocol.HeartbeatTx
	hsigSingletonHeartbeat.Txn.HeartbeatTxnFields = &HeartbeatTxnFields{}
	hsigSingletonHeartbeat.Txn.PaymentTxnFields = PaymentTxnFields{}
	mixedSingletonHeartbeat := hsigAndRegularSigned
	mixedSingletonHeartbeat.Txn.Type = protocol.HeartbeatTx
	mixedSingletonHeartbeat.Txn.HeartbeatTxnFields = &HeartbeatTxnFields{}
	mixedSingletonHeartbeat.Txn.PaymentTxnFields = PaymentTxnFields{}
	hsigPaidSingletonHeartbeat := hsigSingletonHeartbeat
	hsigPaidSingletonHeartbeat.Txn.Fee = proto.MinFee()
	hsigGroupedHeartbeat := hsigSingletonHeartbeat
	hsigGroupedHeartbeat.Txn.Group = crypto.Digest{1}
	// A challenged heartbeat gets one min fee off, but still owes any signature
	// surcharge: only the base fee is discounted.
	challengedHeartbeat := regularSingletonHeartbeat
	challengedHeartbeat.Txn.HeartbeatTxnFields = &HeartbeatTxnFields{HbChallengeDiscount: true}
	hsigChallengedHeartbeat := hsigSingletonHeartbeat
	hsigChallengedHeartbeat.Txn.HeartbeatTxnFields = &HeartbeatTxnFields{HbChallengeDiscount: true}
	hsigChallengedGrouped := hsigChallengedHeartbeat
	hsigChallengedGrouped.Txn.Group = crypto.Digest{1}
	delegatedHsigSingletonHeartbeat := hsigSingletonHeartbeat
	delegatedHsigSingletonHeartbeat.Hsig = HashedKeySig{}
	delegatedHsigSingletonHeartbeat.Lsig = delegatedHsigSigned.Lsig
	delegatedHsigPaidSingletonHeartbeat := delegatedHsigSingletonHeartbeat
	delegatedHsigPaidSingletonHeartbeat.Txn.Fee = proto.MinFee()
	delegatedHsigGroupedHeartbeat := delegatedHsigSingletonHeartbeat
	delegatedHsigGroupedHeartbeat.Txn.Group = crypto.Digest{1}

	for _, stxn := range []SignedTxn{baseTxn, regularSigned, msigSigned, lsigSigned} {
		require.Equal(t, basics.Micros(1e6), stxn.FeeFactor(proto))
	}
	require.Equal(t, basics.Micros(2e6), SigSchemeFeeContribution(proto, protocol.SigSchemeFalcon1024))
	require.Equal(t, basics.Micros(1e6), SigSchemeFeeContribution(proto, protocol.SigSchemeFalcon512))
	require.Equal(t, basics.Micros(0), SigSchemeFeeContribution(proto, protocol.SigSchemeEd25519))
	require.Equal(t, basics.Micros(1e6), unknownHsigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(1e6), unknownDelegatedHsigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(1e6), edHsigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(1e6), edDelegatedHsigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), hsigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), delegatedHsigSigned.FeeFactor(proto))
	require.Equal(t, hsigSigned.FeeFactor(proto), delegatedHsigSigned.FeeFactor(proto))
	require.Equal(t, delegatedHsigSigned.FeeFactor(proto), rekeyedDelegatedHsigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), programlessLsigHsigSigned.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), hsigAndRegularSigned.FeeFactor(proto))
	// With the explicit-discount rule a plain heartbeat pays the base fee (plus surcharges),
	// whether or not it is a singleton.
	require.Equal(t, basics.Micros(1e6), regularSingletonHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), hsigSingletonHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), mixedSingletonHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), hsigPaidSingletonHeartbeat.FeeFactor(proto))
	// A LogicSig delegated by a hashed-key signature owes the same surcharge as a
	// top-level hashed-key signature, so its heartbeat behaves like
	// hsigSingletonHeartbeat regardless of fee.
	require.Equal(t, basics.Micros(3e6), delegatedHsigSingletonHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), delegatedHsigPaidSingletonHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), hsigGroupedHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(3e6), delegatedHsigGroupedHeartbeat.FeeFactor(proto))
	// The challenge discount removes exactly one min fee, leaving surcharges.
	require.Equal(t, basics.Micros(0), challengedHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(2e6), hsigChallengedHeartbeat.FeeFactor(proto))
	require.Equal(t, basics.Micros(2e6), hsigChallengedGrouped.FeeFactor(proto))

	requiredFee, _, overflow := proto.MinFee().FeeForUsage(hsigSigned.FeeFactor(proto), 1e6, 0)
	require.False(t, overflow)
	require.Equal(t, proto.MinFee().Raw*3, requiredFee.Raw)

	requiredDelegatedFee, _, overflow := proto.MinFee().FeeForUsage(delegatedHsigSigned.FeeFactor(proto), 1e6, 0)
	require.False(t, overflow)
	require.Equal(t, requiredFee, requiredDelegatedFee)

	usage, _ := SummarizeFees(WrapSignedTxnsWithAD([]SignedTxn{regularSigned, delegatedHsigSigned}), proto)
	require.Equal(t, basics.Micros(4e6), usage)
}

// TestLogicSigHashedKeySigFee checks that a program authorizing from an ls-scheme
// HashedKeySig is priced by the byte like one in a LogicSig, and carries no scheme
// surcharge of its own.
func TestLogicSigHashedKeySigFee(t *testing.T) {
	partitiontest.PartitionTest(t)

	proto := config.Consensus[protocol.ConsensusFuture]
	require.True(t, proto.TxnSizePricingEnabled())

	// Charging the Falcon surcharge here would make the off-curve form cost
	// more than the on-curve LogicSig it exists to replace.
	lsHsigSigned := SignedTxn{Hsig: HashedKeySig{
		Scheme:    protocol.SigSchemeLogicSig,
		PublicKey: make([]byte, proto.LogicSigMaxSize),
	}}
	require.Equal(t, basics.Micros(1e6), lsHsigSigned.FeeFactor(proto))

	// A program is free up to the group's per-transaction allowance, whether it
	// sits in the Lsig or stands in for a hashed-key signature's public key.
	group := WrapSignedTxnsWithAD([]SignedTxn{lsHsigSigned})
	usage, _ := SummarizeFees(group, proto)
	require.Equal(t, basics.Micros(1e6), usage)

	// Beyond it, the bytes are surcharged exactly as a LogicSig's are.
	overBy := 500
	lsOver := lsHsigSigned
	lsOver.Hsig.PublicKey = make([]byte, int(proto.LogicSigMaxSize)+overBy)
	lsigOver := SignedTxn{Lsig: LogicSig{Logic: make([]byte, int(proto.LogicSigMaxSize)+overBy)}}

	lsUsage, _ := SummarizeFees(WrapSignedTxnsWithAD([]SignedTxn{lsOver}), proto)
	lsigUsage, _ := SummarizeFees(WrapSignedTxnsWithAD([]SignedTxn{lsigOver}), proto)
	require.Equal(t, lsigUsage, lsUsage)

	surcharge, _ := proto.PerByteTxnSurcharge.MulInt(overBy)
	require.Equal(t, basics.AddSaturate(basics.Micros(1e6), surcharge), lsUsage)
}

//TODO: test multisig
