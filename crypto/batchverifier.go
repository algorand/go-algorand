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
	messages   [][]byte                 // contains a slice of messages to be hashed. Each message is varible length
	publicKeys []DonnaSignatureVerifier // contains a slice of public keys. Each individual public key is 32 bytes.
	signatures []DonnaSignature         // contains a slice of signatures keys. Each individual signature is 64 bytes.
	failed     bool                     // failed indicates that the verification has failed. This is used by the multisig verification which has few fail cases that precedes the cryptographic validation.
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
		publicKeys: make([]DonnaSignatureVerifier, 0, hint),
		signatures: make([]DonnaSignature, 0, hint),
		failed:     false,
	}
}

// Enqueue enqueues a verification of a SignatureVerifier
func (b *BatchVerifier) Enqueue(sigVerifier SignatureVerifier, message Hashable, sig Signature) {
	b.enqueueRaw(DonnaSignatureVerifier(sigVerifier), hashRep(message), DonnaSignature(sig))
}

// EnqueueDonnaSignatures enqueues a verification of a DonnaSignatureVerifier
func (b *BatchVerifier) EnqueueDonnaSignatures(sigVerifier DonnaSignatureVerifier, message Hashable, sig DonnaSignature) {
	b.enqueueRaw(sigVerifier, hashRep(message), sig)
}

func (b *BatchVerifier) enqueueRaw(sigVerifier DonnaSignatureVerifier, message []byte, sig DonnaSignature) {
	// do we need to reallocate ?
	if len(b.messages) == cap(b.messages) {
		b.expand()
	}
	b.messages = append(b.messages, message)
	b.publicKeys = append(b.publicKeys, sigVerifier)
	b.signatures = append(b.signatures, sig)
}

func (b *BatchVerifier) expand() {
	messages := make([][]byte, len(b.messages), len(b.messages)*2)
	publicKeys := make([]DonnaSignatureVerifier, len(b.publicKeys), len(b.publicKeys)*2)
	signatures := make([]DonnaSignature, len(b.signatures), len(b.signatures)*2)
	copy(messages, b.messages)
	copy(publicKeys, b.publicKeys)
	copy(signatures, b.signatures)
	b.messages = messages
	b.publicKeys = publicKeys
	b.signatures = signatures
}

// GetNumberOfEnqueuedSignatures returns the number of signatures current enqueue onto the bacth verifier object
func (b *BatchVerifier) GetNumberOfEnqueuedSignatures() int {
	return len(b.messages)
}

// Verify verifies that the enqueued signatures are good, returning false if a verification of any
// of them fails.
func (b *BatchVerifier) Verify() bool {
	if b.GetNumberOfEnqueuedSignatures() == 0 {
		return false
	}

	////// TODO: remove those methods after testing signatures
	const minSignaturesForBatch = 3
	const batchSize = 64

	if b.GetNumberOfEnqueuedSignatures()%batchSize <= 3 {

		message := make([]byte, len(b.messages[0]))
		copy(message[:], b.messages[0][:])

		for i := 0; i < 4; i++ {
			b.enqueueRaw(b.publicKeys[0], message, b.signatures[0])
		}

		if b.GetNumberOfEnqueuedSignatures()%batchSize <= 3 {
			logging.Base().Error("OMG!  really really not good!")
		}
	}
	////// ******************
	batchCheck := DonnaBatchVerification(b.messages, b.publicKeys, b.signatures, b.failed)

	////// TODO: remove those methods after testing signatures
	libsoduiomResults := make([]bool, b.GetNumberOfEnqueuedSignatures())
	for i := range b.messages {
		libsoduiomResults[i] = SignatureVerifier(b.publicKeys[i]).VerifyBytes(b.messages[i], Signature(b.signatures[i]))
	}

	libdonnaResults := make([]bool, b.GetNumberOfEnqueuedSignatures())
	for i := range b.messages {
		libdonnaResults[i] = DonnaSignatureVerifier(b.publicKeys[i]).VerifyBytes(b.messages[i], b.signatures[i])
	}

	for i, isValid := range libsoduiomResults {
		if !isValid {
			logging.Base().Infof("VALIDATION FAILED! libsoduiom on key: %v", b.publicKeys[i])
		}
		//logging.Base().Infof("VALIDATION PASS! libsoduiom on key: %v", pubKey)
	}

	for i, isValid := range libdonnaResults {
		if !isValid {
			logging.Base().Infof("VALIDATION FAILED! libdonna on key: %v", b.publicKeys[i])
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

	for i := range b.messages {
		if !DonnaSignatureVerifier(b.publicKeys[i]).VerifyBytes(b.messages[i], b.signatures[i]) {
			return false
		}
	}
	return true
}
