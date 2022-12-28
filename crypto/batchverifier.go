// Copyright (C) 2019-2023 Algorand, Inc.
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
	"errors"
)

// BatchVerifier enqueues signatures to be validated in batch.
type BatchVerifier struct {
	messages   []Hashable          // contains a slice of messages to be hashed. Each message is varible length
	publicKeys []SignatureVerifier // contains a slice of public keys. Each individual public key is 32 bytes.
	signatures []Signature         // contains a slice of signatures keys. Each individual signature is 64 bytes.
}

const minBatchVerifierAlloc = 16

// Batch verifications errors
var (
	ErrBatchHasFailedSigs = errors.New("At least one signature didn't pass verification")
)


// MakeBatchVerifier creates a BatchVerifier instance.
func MakeBatchVerifier() *BatchVerifier {
	return MakeBatchVerifierWithHint(minBatchVerifierAlloc)
}

// MakeBatchVerifierWithHint creates a BatchVerifier instance. This function pre-allocates
// amount of free space to enqueue signatures without expanding
func MakeBatchVerifierWithHint(hint int) *BatchVerifier {
	// preallocate enough storage for the expected usage. We will reallocate as needed.
	if hint < minBatchVerifierAlloc {
		hint = minBatchVerifierAlloc
	}
	return &BatchVerifier{
		messages:   make([]Hashable, 0, hint),
		publicKeys: make([]SignatureVerifier, 0, hint),
		signatures: make([]Signature, 0, hint),
	}
}

// EnqueueSignature enqueues a signature to be enqueued
func (b *BatchVerifier) EnqueueSignature(sigVerifier SignatureVerifier, message Hashable, sig Signature) {
	// do we need to reallocate ?
	if len(b.messages) == cap(b.messages) {
		b.expand()
	}
	b.messages = append(b.messages, message)
	b.publicKeys = append(b.publicKeys, sigVerifier)
	b.signatures = append(b.signatures, sig)
}

func (b *BatchVerifier) expand() {
	messages := make([]Hashable, len(b.messages), len(b.messages)*2)
	publicKeys := make([]SignatureVerifier, len(b.publicKeys), len(b.publicKeys)*2)
	signatures := make([]Signature, len(b.signatures), len(b.signatures)*2)
	copy(messages, b.messages)
	copy(publicKeys, b.publicKeys)
	copy(signatures, b.signatures)
	b.messages = messages
	b.publicKeys = publicKeys
	b.signatures = signatures
}

// GetNumberOfEnqueuedSignatures returns the number of signatures currently enqueued into the BatchVerifier
func (b *BatchVerifier) GetNumberOfEnqueuedSignatures() int {
	return len(b.messages)
}

// Verify verifies that all the signatures are valid. in that case nil is returned
func (b *BatchVerifier) Verify() error {
	_, err := b.VerifyWithFeedback()
	return err
}

// VerifyWithFeedback verifies that all the signatures are valid.
// if all sigs are valid, nil will be returned for err (failed will have all false)
// if some signatures are invalid, true will be set in failed at the corresponding indexes, and
// ErrBatchVerificationFailed for err
func (b *BatchVerifier) VerifyWithFeedback() (failed []bool, err error) {
	if b.GetNumberOfEnqueuedSignatures() == 0 {
		return nil, nil
	}
	var messages = make([][]byte, b.GetNumberOfEnqueuedSignatures())
	for i := range b.messages {
		messages[i] = HashRep(b.messages[i])
	}
	allValid, failed := batchVerificationImpl(messages, b.publicKeys, b.signatures)
	if allValid {
		return failed, nil
	}
	return failed, ErrBatchHasFailedSigs
}

