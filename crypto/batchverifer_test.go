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

package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBatchVerifierSingle(t *testing.T) {
	// test expected success
	bv := MakeBatchVerifier(1)
	msg := randString()
	var s Seed
	RandBytes(s[:])
	sigSecrets := GenerateSignatureSecrets(s)
	sig := sigSecrets.Sign(msg)
	bv.Enqueue(sigSecrets.SignatureVerifier, msg, sig)
	require.True(t, bv.VerifySlow())
	require.True(t, bv.Verify())

	// test expected failuire
	bv = MakeBatchVerifier(1)
	msg = randString()
	RandBytes(s[:])
	sigSecrets = GenerateSignatureSecrets(s)
	sig = sigSecrets.Sign(msg)
	// break the signature:
	sig[0] = sig[0] + 1
	bv.Enqueue(sigSecrets.SignatureVerifier, msg, sig)
	require.False(t, bv.VerifySlow())
	require.False(t, bv.Verify())
}

func TestBatchVerifierBulk(t *testing.T) {
	for i := 1; i < 64*2+3; i++ {
		n := i
		bv := MakeBatchVerifier(n)
		var s Seed
		RandBytes(s[:])

		for i := 0; i < n; i++ {
			msg := randString()
			sigSecrets := GenerateSignatureSecrets(s)
			sig := sigSecrets.Sign(msg)
			bv.Enqueue(sigSecrets.SignatureVerifier, msg, sig)
		}
		require.True(t, bv.VerifySlow())
		require.True(t, bv.Verify())
	}

}

func TestBatchMultisigAddr(t *testing.T) {

	bv := MakeBatchVerifier(1)
	var msig MultisigSig
	var sigs []MultisigSig

	var s Seed
	var userkeypair []*SecretKey
	var pk []PublicKey

	var err error
	var addr Digest

	version := uint8(1)
	threshold := uint8(3)
	txid := TestingHashable{[]byte("test: txid 1000")}

	userkeypair = make([]*SecretKey, 5)
	for i := 0; i < 5; i++ {
		RandBytes(s[:])
		userkeypair[i] = GenerateSignatureSecrets(s)
	}

	// addr  = hash (... |pk0|pk1|pk2|pk3), pk4 is not included
	pk = make([]PublicKey, 4)
	pk[0] = userkeypair[0].SignatureVerifier
	pk[1] = userkeypair[1].SignatureVerifier
	pk[2] = userkeypair[2].SignatureVerifier
	pk[3] = userkeypair[3].SignatureVerifier
	addr, err = MultisigAddrGen(version, threshold, pk)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")

	// now testing signing functions
	// check if invalid version can be detected
	_, err = MultisigSign(txid, addr, version+1, threshold, pk, *userkeypair[0])
	require.Error(t, err, "should be able to detect invalid version number")
	//	check if invalid secret key can be detected
	_, err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[4])
	require.Error(t, err, "should be able to detect invalid secret key used")

	// test assembling
	// test1: assemble a single signature -- should return failure
	sigs = make([]MultisigSig, 1)
	sigs[0], err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[3])
	require.NoError(t, err, "Multisig: unexpected failure in multisig signing")
	_, err = MultisigAssemble(sigs)
	require.Error(t, err, "should be able to detect insufficient signatures for assembling")

	// test2: assemble 3 signatures
	// signing three signatures with pk0, pk1 and pk2
	sigs = make([]MultisigSig, 3)
	sigs[0], err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[0])
	require.NoError(t, err, "Multisig: unexpected failure in generating sig from pk 0")
	sigs[1], err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[1])
	require.NoError(t, err, "Multisig: unexpected failure in generating sig from pk 1")
	sigs[2], err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[2])
	require.NoError(t, err, "Multisig: unexpected failure in generating sig from pk 2")
	msig, err = MultisigAssemble(sigs)
	require.NoError(t, err, "Multisig: unexpected failure when assembling multisig")
	bv.EnqueueMultisig(addr, txid, msig)
	verify := bv.Verify()
	//verify, err := MultisigVerify(txid, addr, msig)
	require.True(t, verify, "Multisig: verification failed, verify flag was false")
	require.NoError(t, err, "Multisig: unexpected verification failure with err")
}
func BenchmarkBatchVerifier(b *testing.B) {
	c := makeCurve25519Secret()
	bv := MakeBatchVerifier(1)
	for i := 0; i < b.N; i++ {
		str := randString()
		bv.Enqueue(c.SignatureVerifier, str, c.Sign(str))
	}

	b.ResetTimer()
	require.True(b, bv.Verify())
}

func BenchmarkVerifyDonna(b *testing.B) {
	c := makeCurve25519Secret()
	strs := make([]TestingHashable, b.N)
	sigs := make([]Signature, b.N)
	for i := 0; i < b.N; i++ {
		strs[i] = randString()
		sigs[i] = c.Sign(strs[i])
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = DonnaSignatureVerifier(c.SignatureVerifier).Verify(strs[i], DonnaSignature(sigs[i]))
	}
}
