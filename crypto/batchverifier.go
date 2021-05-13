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
	"github.com/algorand/go-algorand/logging"
)

// BatchVerifier provides faster implementation for verifing a series of independent signatures.
type BatchVerifier struct {
	messages   [][]byte // contains the messages to be hashed.
	publicKeys []byte   // contains the public keys. Each individual public key is 32 bytes.
	signatures []byte   // contains the signatures keys. Each individual signature is 64 bytes.
	failed     bool     // failed indicates that the verification has failed. This is used by the multisig verification which has few fail cases that precedes the cryptographic validation.
}

const minBatchVerifierAlloc = 16

// MakeBatchVerifier create a BatchVerifier instance, and initialize it using the provided hint.
func MakeBatchVerifier(hint int) *BatchVerifier {
	// preallocate enough storage for the expected usage. We will reallocate as needed.
	if hint < minBatchVerifierAlloc {
		hint = minBatchVerifierAlloc
	}
	return &BatchVerifier{
		messages:   make([][]byte, 0, hint),
		publicKeys: make([]byte, 0, hint*ed25519DonnaPublicKeyLenBytes),
		signatures: make([]byte, 0, hint*ed25519DonnaSignatureLenBytes),
		failed:     false,
	}
}

// Enqueue enqueues a verification of a SignatureVerifier
func (b *BatchVerifier) Enqueue(sigVerifier SignatureVerifier, message Hashable, sig Signature) {
	b.enqueueRaw(sigVerifier, hashRep(message), sig)
}

func (b *BatchVerifier) enqueueRaw(sigVerifier SignatureVerifier, message []byte, sig Signature) {
	// do we need to reallocate ?
	if len(b.messages) == cap(b.messages) {
		b.expand()
	}
	b.messages = append(b.messages, message)
	b.publicKeys = append(b.publicKeys, sigVerifier[:]...)
	b.signatures = append(b.signatures, sig[:]...)
}

// EnqueueMultisig enqueues a verification of a Multisig
func (b *BatchVerifier) EnqueueMultisig(addr Digest, message Hashable, sig MultisigSig) {

	// short circuit: if msig doesn't have subsigs or if Subsigs are empty
	// then terminate (the upper layer should now verify the unisig)
	if (len(sig.Subsigs) == 0 || sig.Subsigs[0] == MultisigSubsig{}) {
		b.failed = true
		return
	}

	// check the address is correct
	addrnew, err := MultisigAddrGenWithSubsigs(sig.Version, sig.Threshold, sig.Subsigs)
	if err != nil || addr != addrnew {
		b.failed = true
		return
	}

	// check that we don't have too many multisig subsigs
	if len(sig.Subsigs) > maxMultisig {
		b.failed = true
		return
	}

	// check that we don't have too few multisig subsigs
	if len(sig.Subsigs) < int(sig.Threshold) {
		b.failed = true
		return
	}

	// checks the number of non-blank signatures is no less than threshold
	var counter uint8
	for _, subsigi := range sig.Subsigs {
		if (subsigi.Sig != Signature{}) {
			counter++
		}
	}
	if counter < sig.Threshold {
		b.failed = true
		return
	}

	// enqueue individual signature verifies
	var verifiedCount int
	for _, subsigi := range sig.Subsigs {
		if (subsigi.Sig != Signature{}) {
			b.Enqueue(subsigi.Key, message, subsigi.Sig)
			verifiedCount++
		}
	}

	// sanity check. if we get here then every non-blank subsig should have
	// been enqueued successfully, and we should have had enough of them
	if verifiedCount < int(sig.Threshold) {
		b.failed = true
		return
	}
}

func (b *BatchVerifier) GetNumberOfSignatures() int {
	return len(b.messages)
}

func (b *BatchVerifier) expand() {
	messages := make([][]byte, len(b.messages), len(b.messages)*2)
	publicKeys := make([]byte, len(b.publicKeys), len(b.publicKeys)*2)
	signatures := make([]byte, len(b.signatures), len(b.signatures)*2)
	copy(messages, b.messages)
	copy(publicKeys, b.publicKeys)
	copy(signatures, b.signatures)
	b.messages = messages
	b.publicKeys = publicKeys
	b.signatures = signatures
}

// Verify verifies that the enqueued signatures are good, returning false if a verification of any
// of them fails.
func (b *BatchVerifier) Verify() bool {
	if len(b.messages) == 0 {
		return false
	}

	////// TODO: remove those methods after testing signatures
	const minSignaturesForBatch = 3
	const batchSize = 64

	if len(b.messages)%batchSize <= 3 {

		var pubKey PublicKey
		var sig Signature

		copy(pubKey[:], b.publicKeys[0:32])
		copy(sig[:], b.signatures[0:64])
		message := make([]byte, len(b.messages[0]))
		copy(message[:], b.messages[0][:])

		for i := 0; i < 4; i++ {
			b.enqueueRaw(pubKey, message, sig)
		}

		if len(b.messages)%batchSize <= 3 {
			logging.Base().Error("OMG!  really really not good!")
		}
	}
	////// ******************
	batchCheck := DoonaBatchVerification(b.messages, b.publicKeys, b.signatures, b.failed)

	////// TODO: remove those methods after testing signatures
	libsoduiomResults := make([]bool, len(b.messages))

	for i, _ := range b.messages {
		var pubKey PublicKey
		var sig Signature
		copy(pubKey[:], b.publicKeys[i*32:((i+1)*32)])
		copy(sig[:], b.signatures[i*64:((i+1)*64)])

		libsoduiomResults[i] = SignatureVerifier(PublicKey(pubKey)).VerifyBytes(b.messages[i], sig)
	}
	libdonnaResults := make([]bool, len(b.messages))

	for i, _ := range b.messages {
		var pubKey PublicKey
		var sig DonnaSignature
		copy(pubKey[:], b.publicKeys[i*ed25519DonnaPublicKeyLenBytes:((i+1)*ed25519DonnaPublicKeyLenBytes)])
		copy(sig[:], b.signatures[i*ed25519DonnaSignatureLenBytes:((i+1)*ed25519DonnaSignatureLenBytes)])

		libdonnaResults[i] = DonnaSignatureVerifier(DonnaPublicKey(pubKey)).VerifyBytes(b.messages[i], sig)
	}

	for i, isValid := range libsoduiomResults {
		var pubKey PublicKey
		copy(pubKey[:], b.publicKeys[i*32:((i+1)*32)])

		if !isValid {
			logging.Base().Infof("VALIDATION FAILED! libsoduiom on key: %v", pubKey)
		}
		//logging.Base().Infof("VALIDATION PASS! libsoduiom on key: %v", pubKey)
	}
	for i, isValid := range libdonnaResults {
		var pubKey PublicKey
		copy(pubKey[:], b.publicKeys[i*ed25519DonnaPublicKeyLenBytes:((i+1)*ed25519DonnaPublicKeyLenBytes)])
		if !isValid {
			logging.Base().Infof("VALIDATION FAILED! libdonna on key: %v", pubKey)
		}
		//logging.Base().Infof("VALIDATION PASS! libdonna on key: %v", pubKey)
	}
	if !batchCheck {
		logging.Base().Infof("VALIDATION FAILED! batch verification on this round")
	}
	//logging.Base().Infof("VALIDATION PASS! batch verification on this round")
	////// ******************
	return batchCheck
}

// VerifySlow verifies that the enqueued signatures are good, returning false if a verification of any
// of them fails. The implementation is the naive implementation and the entries are being iterated.
func (b *BatchVerifier) VerifySlow() bool {
	if b.failed {
		return false
	}

	// iterate and verify each of the signatures.
	var sigVerifier DonnaSignatureVerifier
	var sig DonnaSignature
	for i := 0; i < len(b.messages); i++ {
		copy(sigVerifier[:], b.publicKeys[i*ed25519DonnaPublicKeyLenBytes:])
		copy(sig[:], b.signatures[i*ed25519DonnaSignatureLenBytes:])
		if !sigVerifier.VerifyBytes(b.messages[i][:], sig) {
			return false
		}
	}

	return true
}
