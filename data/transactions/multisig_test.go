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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

type multisigTestMessage string

func (msg multisigTestMessage) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.TestHashable, []byte(msg)
}

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
func TestMultisigAddr(t *testing.T) {
	partitiontest.PartitionTest(t)
	var s crypto.Seed
	var secrets []*crypto.SignatureSecrets
	var pks []crypto.PublicKey
	var err error

	version := uint8(1)
	threshold := uint8(3)

	secrets = make([]*crypto.SignatureSecrets, 4)

	for i := 0; i < 4; i++ {
		crypto.RandBytes(s[:])
		secrets[i] = crypto.GenerateSignatureSecrets(s)
	}

	pks = make([]crypto.PublicKey, 2)
	pks[0] = secrets[0].SignatureVerifier
	pks[1] = secrets[1].SignatureVerifier

	// test if invalid threshold can be detected
	// #keys= 2 < threshold = 3
	_, err = MultisigAddrGen(version, threshold, pks)
	require.ErrorIs(t, err, errInvalidThreshold, "MultisigAddr: unable to detect invalid threshold (keys == %d, threshold == %d)", len(pks), threshold)
	// #keys = 3 == threshold = 3
	pks = append(pks, secrets[2].SignatureVerifier)
	_, err = MultisigAddrGen(version, threshold, pks)
	require.NoError(t, err, "MultisigAddr: unexpected failure generating message digest with %d keys and a threshold of %d", len(pks), threshold)
	// #keys = 4 > threshold = 3
	pks = append(pks, secrets[3].SignatureVerifier)
	_, err = MultisigAddrGen(version, threshold, pks)
	require.NoError(t, err, "MultisigAddr: unexpected failure generating message digest with %d keys and a threshold of %d", len(pks), threshold)
}

// this test generates a set of 4 public keys for a threshold of 3
// signs with 3 keys to get 3 signatures
// assembles 3 signatures, verify the msig
func TestMultisig(t *testing.T) {
	partitiontest.PartitionTest(t)
	var msig MultisigSig
	var sigs []MultisigSig

	var s crypto.Seed
	var secrets []*crypto.SignatureSecrets
	var pks []crypto.PublicKey

	var err error
	var addr crypto.Digest

	version := uint8(1)
	threshold := uint8(3)
	txid := multisigTestMessage("test: txid 1000")

	secrets = make([]*crypto.SignatureSecrets, 5)
	for i := 0; i < 5; i++ {
		crypto.RandBytes(s[:])
		secrets[i] = crypto.GenerateSignatureSecrets(s)
	}

	// addr  = hash (... |pk0|pk1|pk2|pk3), pk4 is not included
	pks = make([]crypto.PublicKey, 4)
	pks[0] = secrets[0].SignatureVerifier
	pks[1] = secrets[1].SignatureVerifier
	pks[2] = secrets[2].SignatureVerifier
	pks[3] = secrets[3].SignatureVerifier
	addr, err = MultisigAddrGen(version, threshold, pks)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")

	// now testing signing functions
	// check if invalid version can be detected
	_, err = MultisigSign(txid, addr, version+1, threshold, pks, *secrets[0])
	require.ErrorIs(t, err, errUnknownVersion, "should be able to detect invalid version number")
	//	check if invalid secret key can be detected
	_, err = MultisigSign(txid, addr, version, threshold, pks, *secrets[4])
	require.ErrorIs(t, err, errKeyNotExist, "should be able to detect invalid secret key used")

	// test assembling
	// test1: assemble a single signature -- should return failure
	sigs = make([]MultisigSig, 1)
	sigs[0], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[3])
	require.NoError(t, err, "Multisig: unexpected failure in multisig signing")
	_, err = MultisigAssemble(sigs)
	require.ErrorContains(t, err, `invalid number of signatures to assemble`, "should be able to detect insufficient signatures for assembling")

	// test2: assemble 3 signatures
	// signing three signatures with pk0, pk1 and pk2
	sigs = make([]MultisigSig, 3)
	sigs[0], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[0])
	require.NoError(t, err, "Multisig: unexpected failure in generating sig from pk 0")
	sigs[1], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[1])
	require.NoError(t, err, "Multisig: unexpected failure in generating sig from pk 1")
	sigs[2], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[2])
	require.NoError(t, err, "Multisig: unexpected failure in generating sig from pk 2")
	msig, err = MultisigAssemble(sigs)
	require.NoError(t, err, "Multisig: unexpected failure when assembling multisig")
	err = MultisigVerify(txid, addr, msig)
	require.NoError(t, err, "Multisig: unexpected verification failure with err")

	//test3: use the batch verification
	br := crypto.MakeBatchVerifier()
	err = MultisigBatchPrep(txid, addr, msig, br)
	require.NoError(t, err, "Multisig: unexpected verification failure with err")
	res := br.Verify()
	require.NoError(t, res, "Multisig: batch verification failed")
}

// test multisig merge functions
// 1. assembles 2 signatures, adds a 3rd one to form msig1
// 2. verifies msig1
// 3. assembles 4th and 5th to get msig2
// 4. merge msig1 and msig2
// 5. verify the merged one
func TestMultisigAddAndMerge(t *testing.T) {
	partitiontest.PartitionTest(t)
	var msig1 MultisigSig
	var msig2 MultisigSig
	var sigs []MultisigSig

	var s crypto.Seed
	var secrets []*crypto.SignatureSecrets
	var pks []crypto.PublicKey

	var err error
	var addr crypto.Digest

	version := uint8(1)
	threshold := uint8(3)
	txid := multisigTestMessage("test: txid 1000")

	secrets = make([]*crypto.SignatureSecrets, 5)

	crypto.RandBytes(s[:])

	pks = make([]crypto.PublicKey, 5)
	for i := 0; i < 5; i++ {
		secrets[i] = crypto.GenerateSignatureSecrets(s)
		pks[i] = secrets[i].SignatureVerifier
	}

	// addr = hash (... |pk0|pk1|pk2|pk3|pk4)
	addr, err = MultisigAddrGen(version, threshold, pks)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")

	// msig1 = {sig0,sig1}
	sigs = make([]MultisigSig, 2)
	sigs[0], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[0])
	require.NoError(t, err, "Multisig: unexpected failure signing with pk 0")
	sigs[1], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[1])
	require.NoError(t, err, "Multisig: unexpected failure signing with pk 1")
	msig1, err = MultisigAssemble(sigs)
	require.NoError(t, err, "Multisig: unexpected failure assembling message from signatures 0 and 1")
	// add sig3 to msig and then verify
	sigs = make([]MultisigSig, 1)
	sigs[0], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[2])
	require.NoError(t, err, "Multisig: unexpected failure signing with pk 2")
	err = MultisigAdd(sigs, &msig1)
	require.NoError(t, err, "Multisig: unexpected err adding pk 2 signature to that of pk 0 and 1")
	err = MultisigVerify(txid, addr, msig1)
	require.NoError(t, err, "Multisig: unexpected verification failure with err")

	// msig2 = {sig3, sig4}
	sigs = make([]MultisigSig, 2)
	sigs[0], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[3])
	require.NoError(t, err, "Multisig: unexpected failure signing with pk 3")
	sigs[1], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[4])
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
	sigs[0], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[2])
	require.NoError(t, err, "Multisig: unexpected failure signing with pk 2")
	err = MultisigAdd(sigs, &msig2)
	require.NoError(t, err, "Multisig: unexpected failure adding pk 2 signature to that of pk 3 and 4")
	msigt, err = MultisigMerge(msig1, msig2)
	require.NoError(t, err, "Multisig: unexpected failure merging multisig messages {0, 1, 2} and {2, 3, 4}")
	err = MultisigVerify(txid, addr, msigt)
	require.NoError(t, err, "Multisig: unexpected verification failure with err")

	return
}

func TestEmptyMultisig(t *testing.T) {
	partitiontest.PartitionTest(t)
	var s crypto.Seed
	var secrets *crypto.SignatureSecrets
	var pks []crypto.PublicKey

	txid := multisigTestMessage("test: txid 1000")
	version := uint8(1)
	threshold := uint8(1)
	crypto.RandBytes(s[:])
	secrets = crypto.GenerateSignatureSecrets(s)
	pks = make([]crypto.PublicKey, 1)
	pks[0] = secrets.SignatureVerifier

	addr, err := MultisigAddrGen(version, threshold, pks)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")
	emptyMutliSig := MultisigSig{Version: version, Threshold: threshold, Subsigs: make([]MultisigSubsig, 0)}
	err = MultisigVerify(txid, addr, emptyMutliSig)
	require.ErrorIs(t, err, errInvalidNumberOfSignature)
	br := crypto.MakeBatchVerifier()
	err = MultisigBatchPrep(txid, addr, emptyMutliSig, br)
	require.ErrorIs(t, err, errInvalidNumberOfSignature)
}

func TestIncorrectAddrresInMultisig(t *testing.T) {
	partitiontest.PartitionTest(t)
	var s crypto.Seed
	var secrets *crypto.SignatureSecrets
	var pks []crypto.PublicKey

	txid := multisigTestMessage("test: txid 1000")
	version := uint8(1)
	threshold := uint8(1)
	crypto.RandBytes(s[:])
	secrets = crypto.GenerateSignatureSecrets(s)
	pks = make([]crypto.PublicKey, 1)
	pks[0] = secrets.SignatureVerifier

	addr, err := MultisigAddrGen(version, threshold, pks)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")
	MutliSig, err := MultisigSign(txid, addr, version, threshold, pks, *secrets)
	require.NoError(t, err, "Multisig: could not create mutlisig")
	addr[0] = addr[0] + 1
	err = MultisigVerify(txid, addr, MutliSig)
	require.ErrorIs(t, err, errInvalidAddress)
	br := crypto.MakeBatchVerifier()
	err = MultisigBatchPrep(txid, addr, MutliSig, br)
	require.ErrorIs(t, err, errInvalidAddress)

}

func TestMoreThanMaxSigsInMultisig(t *testing.T) {
	partitiontest.PartitionTest(t)
	var s crypto.Seed
	var secrets []*crypto.SignatureSecrets
	var pks []crypto.PublicKey
	multiSigLen := maxMultisig + 1
	txid := multisigTestMessage("test: txid 1000")
	version := uint8(1)
	threshold := uint8(1)
	pks = make([]crypto.PublicKey, multiSigLen)
	secrets = make([]*crypto.SignatureSecrets, multiSigLen)
	for i := 0; i < multiSigLen; i++ {
		crypto.RandBytes(s[:])
		secrets[i] = crypto.GenerateSignatureSecrets(s)
		pks[i] = secrets[i].SignatureVerifier
	}

	addr, err := MultisigAddrGen(version, threshold, pks)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")

	sigs := make([]MultisigSig, multiSigLen)

	for i := 0; i < len(sigs); i++ {
		sigs[i], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[i])
		require.NoError(t, err, "Multisig: unexpected failure in generating sig from pk %v", i)
	}

	msig, err := MultisigAssemble(sigs)
	require.NoError(t, err, "Multisig: error assemble multisig")
	err = MultisigVerify(txid, addr, msig)
	require.ErrorIs(t, err, errInvalidNumberOfSignature)
	br := crypto.MakeBatchVerifier()
	err = MultisigBatchPrep(txid, addr, msig, br)
	require.ErrorIs(t, err, errInvalidNumberOfSignature)
}

func TestOneSignatureIsEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)
	var s crypto.Seed
	var secrets []*crypto.SignatureSecrets
	var pks []crypto.PublicKey
	multiSigLen := 6
	txid := multisigTestMessage("test: txid 1000")
	version := uint8(1)
	threshold := uint8(multiSigLen)
	pks = make([]crypto.PublicKey, multiSigLen)
	secrets = make([]*crypto.SignatureSecrets, multiSigLen)
	for i := 0; i < multiSigLen; i++ {
		crypto.RandBytes(s[:])
		secrets[i] = crypto.GenerateSignatureSecrets(s)
		pks[i] = secrets[i].SignatureVerifier
	}

	addr, err := MultisigAddrGen(version, threshold, pks)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")

	sigs := make([]MultisigSig, multiSigLen)

	for i := 0; i < multiSigLen; i++ {
		sigs[i], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[i])
		require.NoError(t, err, "Multisig: unexpected failure in generating sig from pk %v", i)
	}

	msig, err := MultisigAssemble(sigs)
	require.NoError(t, err, "Multisig: error assemble multisig")
	msig.Subsigs[0].Sig = crypto.Signature{}
	err = MultisigVerify(txid, addr, msig)
	require.ErrorIs(t, err, errInvalidNumberOfSignature)
	br := crypto.MakeBatchVerifier()
	err = MultisigBatchPrep(txid, addr, msig, br)
	require.ErrorIs(t, err, errInvalidNumberOfSignature)
}

// in this test we want to test what happen if one of the signatures are not valid.
// we create case where are enoguht valid signatures (that pass the thrashold). but since one is false. everything fails.
func TestOneSignatureIsInvalid(t *testing.T) {
	partitiontest.PartitionTest(t)
	var s crypto.Seed
	var userkeypair []*crypto.SignatureSecrets
	var pks []crypto.PublicKey
	multiSigLen := 6
	txid := multisigTestMessage("test: txid 1000")
	version := uint8(1)
	threshold := uint8(3)
	pks = make([]crypto.PublicKey, multiSigLen)
	userkeypair = make([]*crypto.SignatureSecrets, multiSigLen)
	for i := 0; i < multiSigLen; i++ {
		crypto.RandBytes(s[:])
		userkeypair[i] = crypto.GenerateSignatureSecrets(s)
		pks[i] = userkeypair[i].SignatureVerifier
	}

	addr, err := MultisigAddrGen(version, threshold, pks)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")

	sigs := make([]MultisigSig, multiSigLen)

	for i := 0; i < multiSigLen; i++ {
		sigs[i], err = MultisigSign(txid, addr, version, threshold, pks, *userkeypair[i])
		require.NoError(t, err, "Multisig: unexpected failure in generating sig from pk %v", i)
	}

	sigs[1].Subsigs[1].Sig[5] = sigs[1].Subsigs[1].Sig[5] + 1
	msig, err := MultisigAssemble(sigs)
	require.NoError(t, err, "Multisig: error assemble multisig")
	err = MultisigVerify(txid, addr, msig)
	require.ErrorIs(t, err, crypto.ErrBatchHasFailedSigs)
	br := crypto.MakeBatchVerifier()
	err = MultisigBatchPrep(txid, addr, msig, br)
	require.NoError(t, err)
	res := br.Verify()
	require.ErrorIs(t, res, crypto.ErrBatchHasFailedSigs)

}

func TestMultisigLessThanTrashold(t *testing.T) {
	partitiontest.PartitionTest(t)
	var msig MultisigSig
	var sigs []MultisigSig

	var s crypto.Seed
	var secrets []*crypto.SignatureSecrets
	var pks []crypto.PublicKey

	var err error
	var addr crypto.Digest

	version := uint8(1)
	threshold := uint8(3)
	txid := multisigTestMessage("test: txid 1000")

	secrets = make([]*crypto.SignatureSecrets, 4)
	for i := 0; i < 4; i++ {
		crypto.RandBytes(s[:])
		secrets[i] = crypto.GenerateSignatureSecrets(s)
	}

	// addr  = hash (... |pk0|pk1|pk2|pk3)
	pks = make([]crypto.PublicKey, 4)
	pks[0] = secrets[0].SignatureVerifier
	pks[1] = secrets[1].SignatureVerifier
	pks[2] = secrets[2].SignatureVerifier
	pks[3] = secrets[3].SignatureVerifier
	addr, err = MultisigAddrGen(version, threshold, pks)
	require.NoError(t, err, "Multisig: unexpected failure generating message digest")

	sigs = make([]MultisigSig, 3)
	sigs[0], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[0])
	require.NoError(t, err, "Multisig: unexpected failure in multisig signing")
	sigs[1], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[1])
	require.NoError(t, err, "Multisig: unexpected failure in multisig signing")
	sigs[2], err = MultisigSign(txid, addr, version, threshold, pks, *secrets[2])
	require.NoError(t, err, "Multisig: unexpected failure in multisig signing")

	msig, err = MultisigAssemble(sigs)
	require.NoError(t, err, "should be able to detect insufficient signatures for assembling")
	msig.Subsigs[1].Sig = crypto.BlankSignature
	err = MultisigVerify(txid, addr, msig)
	require.ErrorIs(t, err, errInvalidNumberOfSignature)

	msig, err = MultisigAssemble(sigs)
	require.NoError(t, err, "should be able to detect insufficient signatures for assembling")
	msig.Subsigs = msig.Subsigs[:len(msig.Subsigs)-1]
	err = MultisigVerify(txid, addr, msig)
	require.ErrorIs(t, err, errInvalidAddress)

}
