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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func MultisigSigPrint(sig MultisigSig) {

	fmt.Println("version", sig.Version)
	fmt.Println("threshold", sig.Threshold)
	fmt.Println("number of keys", len(sig.Subsigs))
	for i := 0; i < len(sig.Subsigs); i++ {
		fmt.Println("the ", i, "th key/sig pair")
		fmt.Println(sig.Subsigs[i].Key)
		fmt.Println(sig.Subsigs[i].Sig)
	}
}

// test cases for address generation
// detect invalid threshold and versions
//
func TestMultisigAddr(t *testing.T) {
	var s Seed
	var userkeypair []*SecretKey
	var pk []PublicKey
	var err error

	version := uint8(1)
	threshold := uint8(3)

	userkeypair = make([]*SecretKey, 4)

	for i := 0; i < 4; i++ {
		RandBytes(s[:])
		userkeypair[i] = GenerateSignatureSecrets(s)
	}

	pk = make([]PublicKey, 2)
	pk[0] = userkeypair[0].SignatureVerifier
	pk[1] = userkeypair[1].SignatureVerifier

	// test if invalid threshold can be detected
	// #keys= 2 < threshold = 3
	_, err = MultisigAddrGen(version, threshold, pk)
	require.Error(t, err, "MultisigAddr: unable to detect invalid threshold (keys == %d, threshold == %d)", len(pk), threshold)
	// #keys = 3 == threshold = 3
	pk = append(pk, userkeypair[2].SignatureVerifier)
	_, err = MultisigAddrGen(version, threshold, pk)
	require.NoError(t, err, "MultisigAddr: unexpected failure generating message digest with %d keys and a threshold of %d", len(pk), threshold)
	// #keys = 4 > threshold = 3
	pk = append(pk, userkeypair[3].SignatureVerifier)
	_, err = MultisigAddrGen(version, threshold, pk)
	require.NoError(t, err, "MultisigAddr: unexpected failure generating message digest with %d keys and a threshold of %d", len(pk), threshold)
}

func TestEmptyMultisig(t *testing.T) {

	var s Seed
	var userkeypair *SecretKey
	var pk []PublicKey

	txid := TestingHashable{[]byte("test: txid 1000")}
	version := uint8(1)
	threshold := uint8(1)
	RandBytes(s[:])
	userkeypair = GenerateSignatureSecrets(s)
	pk = make([]PublicKey, 1)
	pk[0] = userkeypair.SignatureVerifier

	addr, err := MultisigAddrGen(version, threshold, pk)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")
	emptyMutliSig := MultisigSig{Version: version, Threshold: threshold, Subsigs: make([]MultisigSubsig, 0)}
	err = MultisigVerify(txid, addr, emptyMutliSig)
	require.Error(t, err, "Multisig: did not return error as expected")
	br := MakeBatchVerifier(1)
	err = MultisigVerifyInBatch(txid, addr, emptyMutliSig, br)
	require.Error(t, err, "Multisig: did not return error as expected")
}

func TestIncorrectAddrresInMultisig(t *testing.T) {
	var s Seed
	var userkeypair *SecretKey
	var pk []PublicKey

	txid := TestingHashable{[]byte("test: txid 1000")}
	version := uint8(1)
	threshold := uint8(1)
	RandBytes(s[:])
	userkeypair = GenerateSignatureSecrets(s)
	pk = make([]PublicKey, 1)
	pk[0] = userkeypair.SignatureVerifier

	addr, err := MultisigAddrGen(version, threshold, pk)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")
	MutliSig, err := MultisigSign(txid, addr, version, threshold, pk, *userkeypair)
	require.NoError(t, err, "Multisig: could not create mutlisig")
	addr[0] = addr[0] + 1
	err = MultisigVerify(txid, addr, MutliSig)
	require.Error(t, err, "Multisig: signatures validation passed")
	br := MakeBatchVerifier(1)
	err = MultisigVerifyInBatch(txid, addr, MutliSig, br)
	require.Error(t, err, "Multisig: signatures validation in batch passed")
}

func TestMoreThanMaxSigsInMultisig(t *testing.T) {
	var s Seed
	var userkeypair []*SecretKey
	var pk []PublicKey
	multiSigLen := maxMultisig + 1
	txid := TestingHashable{[]byte("test: txid 1000")}
	version := uint8(1)
	threshold := uint8(1)
	pk = make([]PublicKey, multiSigLen)
	userkeypair = make([]*SecretKey, multiSigLen)
	for i := 0; i < multiSigLen; i++ {
		RandBytes(s[:])
		userkeypair[i] = GenerateSignatureSecrets(s)
		pk[i] = userkeypair[i].SignatureVerifier
	}

	addr, err := MultisigAddrGen(version, threshold, pk)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")

	sigs := make([]MultisigSig, multiSigLen)

	for i := 0; i < len(sigs); i++ {
		sigs[i], err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[i])
		require.NoError(t, err, "Multisig: unexpected failure in generating sig from pk %v", i)
	}

	msig, err := MultisigAssemble(sigs)
	require.NoError(t, err, "Multisig: error assmeble multisig")
	err = MultisigVerify(txid, addr, msig)
	require.Error(t, err, "Multisig: transaction validation passed")
	br := MakeBatchVerifier(1)
	err = MultisigVerifyInBatch(txid, addr, msig, br)
	require.Error(t, err, "Multisig: transaction batch validation passed")
}

func TestOneSignatureIsEmpty(t *testing.T) {
	var s Seed
	var userkeypair []*SecretKey
	var pk []PublicKey
	multiSigLen := 6
	txid := TestingHashable{[]byte("test: txid 1000")}
	version := uint8(1)
	threshold := uint8(multiSigLen)
	pk = make([]PublicKey, multiSigLen)
	userkeypair = make([]*SecretKey, multiSigLen)
	for i := 0; i < multiSigLen; i++ {
		RandBytes(s[:])
		userkeypair[i] = GenerateSignatureSecrets(s)
		pk[i] = userkeypair[i].SignatureVerifier
	}

	addr, err := MultisigAddrGen(version, threshold, pk)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")

	sigs := make([]MultisigSig, multiSigLen)

	for i := 0; i < multiSigLen; i++ {
		sigs[i], err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[i])
		require.NoError(t, err, "Multisig: unexpected failure in generating sig from pk %v", i)
	}

	msig, err := MultisigAssemble(sigs)
	require.NoError(t, err, "Multisig: error assmeble multisig")
	msig.Subsigs[0].Sig = Signature{}
	err = MultisigVerify(txid, addr, msig)
	require.Error(t, err, "Multisig: one sig empty validation failed")
	br := MakeBatchVerifier(1)
	err = MultisigVerifyInBatch(txid, addr, msig, br)
	require.Error(t, err, "Multisig: one sig empty validation failed")
}

func TestOneSignatureIsInvalid(t *testing.T) {
	var s Seed
	var userkeypair []*SecretKey
	var pk []PublicKey
	multiSigLen := 6
	txid := TestingHashable{[]byte("test: txid 1000")}
	version := uint8(1)
	threshold := uint8(multiSigLen)
	pk = make([]PublicKey, multiSigLen)
	userkeypair = make([]*SecretKey, multiSigLen)
	for i := 0; i < multiSigLen; i++ {
		RandBytes(s[:])
		userkeypair[i] = GenerateSignatureSecrets(s)
		pk[i] = userkeypair[i].SignatureVerifier
	}

	addr, err := MultisigAddrGen(version, threshold, pk)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")

	sigs := make([]MultisigSig, multiSigLen)

	for i := 0; i < multiSigLen; i++ {
		sigs[i], err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[i])
		require.NoError(t, err, "Multisig: unexpected failure in generating sig from pk %v", i)
	}

	sigs[1].Subsigs[1].Sig[5] = sigs[1].Subsigs[1].Sig[5] + 1
	msig, err := MultisigAssemble(sigs)
	require.NoError(t, err, "Multisig: error assmeble multisig")
	err = MultisigVerify(txid, addr, msig)
	require.Error(t, err, "Multisig: signature verification passed on broken signature")
	br := MakeBatchVerifier(1)
	err = MultisigVerifyInBatch(txid, addr, msig, br)
	require.NoError(t, err, "Multisig: multisig is invalid")
	res := br.Verify()
	require.False(t, res, "Multisig: batch verification passed on broken signature")

}

// this test generates a set of 4 public keys for a threshold of 3
// signs with 3 keys to get 3 signatures
// assembles 3 signatures, verify the msig
func TestMultisig(t *testing.T) {
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
	err = MultisigVerify(txid, addr, msig)
	require.NoError(t, err, "Multisig: unexpected verification failure with err")

	br := MakeBatchVerifier(3)
	err = MultisigVerifyInBatch(txid, addr, msig, br)
	require.NoError(t, err, "Multisig: multisig is invalid")
	res := br.Verify()
	require.True(t, res, "Multisig: batch verification failed")
}

// test multisig merge functions
// 1. assembles 2 signatures, adds a 3rd one to form msig1
// 2. verifies msig1
// 3. assembles 4th and 5th to get msig2
// 4. merge msig1 and msig2
// 5. verify the merged one
func TestMultisigAddAndMerge(t *testing.T) {
	var msig1 MultisigSig
	var msig2 MultisigSig
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

	RandBytes(s[:])

	pk = make([]PublicKey, 5)
	for i := 0; i < 5; i++ {
		userkeypair[i] = GenerateSignatureSecrets(s)
		pk[i] = userkeypair[i].SignatureVerifier
	}

	// addr = hash (... |pk0|pk1|pk2|pk3|pk4)
	addr, err = MultisigAddrGen(version, threshold, pk)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")

	// msig1 = {sig0,sig1}
	sigs = make([]MultisigSig, 2)
	sigs[0], err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[0])
	require.NoError(t, err, "Multisig: unexpected failure signing with pk 0")
	sigs[1], err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[1])
	require.NoError(t, err, "Multisig: unexpected failure signing with pk 1")
	msig1, err = MultisigAssemble(sigs)
	require.NoError(t, err, "Multisig: unexpected failure assembling message from signatures 0 and 1")
	// add sig3 to msig and then verify
	sigs = make([]MultisigSig, 1)
	sigs[0], err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[2])
	require.NoError(t, err, "Multisig: unexpected failure signing with pk 2")
	err = MultisigAdd(sigs, &msig1)
	require.NoError(t, err, "Multisig: unexpected err adding pk 2 signature to that of pk 0 and 1")
	err = MultisigVerify(txid, addr, msig1)
	require.NoError(t, err, "Multisig: unexpected verification failure with err")

	// msig2 = {sig3, sig4}
	sigs = make([]MultisigSig, 2)
	sigs[0], err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[3])
	require.NoError(t, err, "Multisig: unexpected failure signing with pk 3")
	sigs[1], err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[4])
	require.NoError(t, err, "Multisig: unexpected failure signing with pk 4")
	msig2, err = MultisigAssemble(sigs)
	require.NoError(t, err, "Multisig: unexpected failure assembling message from signatures 3 and 4")
	// merge two msigs and then verify
	msigt, err := MultisigMerge(msig1, msig2)
	require.NoError(t, err, "Multisig: unexpected failure merging multisig messages {0, 1, 2} and {3, 4}")
	err = MultisigVerify(txid, addr, msigt)
	require.NoError(t, err, "Multisig: unexpected verification failure with err")

	// create a valid duplicate on purpose
	// msig1 = {sig0, sig1, sig2}
	// msig2 = {sig2, sig3, sig4}
	// then verify the merged signature
	sigs = make([]MultisigSig, 1)
	sigs[0], err = MultisigSign(txid, addr, version, threshold, pk, *userkeypair[2])
	require.NoError(t, err, "Multisig: unexpected failure signing with pk 2")
	err = MultisigAdd(sigs, &msig2)
	require.NoError(t, err, "Multisig: unexpected failure adding pk 2 signature to that of pk 3 and 4")
	msigt, err = MultisigMerge(msig1, msig2)
	require.NoError(t, err, "Multisig: unexpected failure merging multisig messages {0, 1, 2} and {2, 3, 4}")
	err = MultisigVerify(txid, addr, msigt)
	require.NoError(t, err, "Multisig: unexpected verification failure with err")

	return
}
