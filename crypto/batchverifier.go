// Copyright (C) 2019-2022 Algorand, Inc.
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

// #cgo CFLAGS: -Wall -std=c99
// #cgo darwin,amd64 CFLAGS: -I${SRCDIR}/libs/darwin/amd64/include
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libs/darwin/amd64/lib/libsodium.a
// #cgo darwin,arm64 CFLAGS: -I${SRCDIR}/libs/darwin/arm64/include
// #cgo darwin,arm64 LDFLAGS: ${SRCDIR}/libs/darwin/arm64/lib/libsodium.a
// #cgo linux,amd64 CFLAGS: -I${SRCDIR}/libs/linux/amd64/include
// #cgo linux,amd64 LDFLAGS: ${SRCDIR}/libs/linux/amd64/lib/libsodium.a
// #cgo linux,arm64 CFLAGS: -I${SRCDIR}/libs/linux/arm64/include
// #cgo linux,arm64 LDFLAGS: ${SRCDIR}/libs/linux/arm64/lib/libsodium.a
// #cgo linux,arm CFLAGS: -I${SRCDIR}/libs/linux/arm/include
// #cgo linux,arm LDFLAGS: ${SRCDIR}/libs/linux/arm/lib/libsodium.a
// #cgo windows,amd64 CFLAGS: -I${SRCDIR}/libs/windows/amd64/include
// #cgo windows,amd64 LDFLAGS: ${SRCDIR}/libs/windows/amd64/lib/libsodium.a
// #include <stdint.h>
// #include "sodium.h"
// enum {
//	sizeofPtr = sizeof(void*),
//	sizeofULongLong = sizeof(unsigned long long),
// };
import "C"
import (
	"errors"
	"runtime"
	"unsafe"
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

//export ed25519_randombytes_unsafe
func ed25519_randombytes_unsafe(p unsafe.Pointer, len C.size_t) {
	randBuf := (*[1 << 30]byte)(p)[:len:len]
	RandBytes(randBuf)
}

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

// batchVerificationImpl invokes the ed25519 batch verification algorithm.
// it returns true if all the signatures were authentically signed by the owners
// otherwise, returns false, and sets the indexes of the failed sigs in failed
func batchVerificationImpl(messages [][]byte, publicKeys []SignatureVerifier, signatures []Signature) (allSigsValid bool, failed []bool) {

	numberOfSignatures := len(messages)

	messagesAllocation := C.malloc(C.size_t(C.sizeofPtr * numberOfSignatures))
	messagesLenAllocation := C.malloc(C.size_t(C.sizeofULongLong * numberOfSignatures))
	publicKeysAllocation := C.malloc(C.size_t(C.sizeofPtr * numberOfSignatures))
	signaturesAllocation := C.malloc(C.size_t(C.sizeofPtr * numberOfSignatures))
	valid := C.malloc(C.size_t(C.sizeof_int * numberOfSignatures))

	defer func() {
		// release staging memory
		C.free(messagesAllocation)
		C.free(messagesLenAllocation)
		C.free(publicKeysAllocation)
		C.free(signaturesAllocation)
		C.free(valid)
	}()

	// load all the data pointers into the array pointers.
	for i := 0; i < numberOfSignatures; i++ {
		*(*uintptr)(unsafe.Pointer(uintptr(messagesAllocation) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(&messages[i][0]))
		*(*C.ulonglong)(unsafe.Pointer(uintptr(messagesLenAllocation) + uintptr(i*C.sizeofULongLong))) = C.ulonglong(len(messages[i]))
		*(*uintptr)(unsafe.Pointer(uintptr(publicKeysAllocation) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(&publicKeys[i][0]))
		*(*uintptr)(unsafe.Pointer(uintptr(signaturesAllocation) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(&signatures[i][0]))
	}

	// call the batch verifier
	allValid := C.crypto_sign_ed25519_open_batch(
		(**C.uchar)(unsafe.Pointer(messagesAllocation)),
		(*C.ulonglong)(unsafe.Pointer(messagesLenAllocation)),
		(**C.uchar)(unsafe.Pointer(publicKeysAllocation)),
		(**C.uchar)(unsafe.Pointer(signaturesAllocation)),
		C.size_t(len(messages)),
		(*C.int)(unsafe.Pointer(valid)))

	runtime.KeepAlive(messages)
	runtime.KeepAlive(publicKeys)
	runtime.KeepAlive(signatures)

	failed = make([]bool, numberOfSignatures)
	for i := 0; i < numberOfSignatures; i++ {
		cint := *(*C.int)(unsafe.Pointer(uintptr(valid) + uintptr(i*C.sizeof_int)))
		failed[i] = (cint == 0)
	}
	return allValid == 0, failed
}
