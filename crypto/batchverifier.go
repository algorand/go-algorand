// Copyright (C) 2019-2025 Algorand, Inc.
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
// #cgo darwin,arm64 CFLAGS: -I${SRCDIR}/libs/darwin/arm64/include
// #cgo linux,amd64 CFLAGS: -I${SRCDIR}/libs/linux/amd64/include
// #cgo linux,arm64 CFLAGS: -I${SRCDIR}/libs/linux/arm64/include
// #cgo linux,arm CFLAGS: -I${SRCDIR}/libs/linux/arm/include
// #cgo linux,riscv64 CFLAGS: -I${SRCDIR}/libs/linux/riscv64/include
// #cgo windows,amd64 CFLAGS: -I${SRCDIR}/libs/windows/amd64/include
// #include <stdint.h>
// enum {
//	sizeofPtr = sizeof(void*),
//	sizeofULongLong = sizeof(unsigned long long),
// };
// int ed25519_batch_wrapper(const unsigned char **messages2D,
//                           const unsigned char **publicKeys2D,
//                           const unsigned char **signatures2D,
//                           const unsigned char *messages1D,
//                           const unsigned long long *mlen,
//                           const unsigned char *publicKeys1D,
//                           const unsigned char *signatures1D,
//                           size_t num,
//                           int *valid_p);
import "C"
import (
	"errors"
	"unsafe"
)

// BatchVerifier enqueues signatures to be validated in batch.
type BatchVerifier interface {
	EnqueueSignature(sigVerifier SignatureVerifier, message Hashable, sig Signature)
	GetNumberOfEnqueuedSignatures() int
	Verify() error
	VerifyWithFeedback() (failed []bool, err error)
}

type cgoBatchVerifier struct {
	messages   []Hashable          // contains a slice of messages to be hashed. Each message is varible length
	publicKeys []SignatureVerifier // contains a slice of public keys. Each individual public key is 32 bytes.
	signatures []Signature         // contains a slice of signatures keys. Each individual signature is 64 bytes.
	useSingle  bool
}

// Batch verifications errors
var (
	ErrBatchHasFailedSigs = errors.New("At least one signature didn't pass verification")
)

//export ed25519_randombytes_unsafe
func ed25519_randombytes_unsafe(p unsafe.Pointer, len C.size_t) {
	randBuf := (*[1 << 30]byte)(p)[:len:len]
	RandBytes(randBuf)
}

const minBatchVerifierAlloc = 16
const useSingleVerifierDefault = true

// MakeBatchVerifier creates a BatchVerifier instance with the provided options.
func MakeBatchVerifier() BatchVerifier {
	return MakeBatchVerifierWithHint(minBatchVerifierAlloc)
}

// MakeBatchVerifierWithHint creates a cgoBatchVerifier instance. This function pre-allocates
// amount of free space to enqueue signatures without expanding
func MakeBatchVerifierWithHint(hint int) BatchVerifier {
	// preallocate enough storage for the expected usage. We will reallocate as needed.
	if hint < minBatchVerifierAlloc {
		hint = minBatchVerifierAlloc
	}
	return &cgoBatchVerifier{
		messages:   make([]Hashable, 0, hint),
		publicKeys: make([]SignatureVerifier, 0, hint),
		signatures: make([]Signature, 0, hint),
		useSingle:  useSingleVerifierDefault,
	}
}

// EnqueueSignature enqueues a signature to be enqueued
func (b *cgoBatchVerifier) EnqueueSignature(sigVerifier SignatureVerifier, message Hashable, sig Signature) {
	// do we need to reallocate ?
	if len(b.messages) == cap(b.messages) {
		b.expand()
	}
	b.messages = append(b.messages, message)
	b.publicKeys = append(b.publicKeys, sigVerifier)
	b.signatures = append(b.signatures, sig)
}

func (b *cgoBatchVerifier) expand() {
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
func (b *cgoBatchVerifier) GetNumberOfEnqueuedSignatures() int {
	return len(b.messages)
}

// Verify verifies that all the signatures are valid. in that case nil is returned
func (b *cgoBatchVerifier) Verify() error {
	_, err := b.VerifyWithFeedback()
	return err
}

// VerifyWithFeedback verifies that all the signatures are valid.
// if all sigs are valid, nil will be returned for err (failed will have all false)
// if some signatures are invalid, true will be set in failed at the corresponding indexes, and
// ErrBatchVerificationFailed for err
func (b *cgoBatchVerifier) VerifyWithFeedback() (failed []bool, err error) {
	if len(b.messages) == 0 {
		return nil, nil
	}

	if b.useSingle {
		return b.singleVerify()
	}

	const estimatedMessageSize = 64
	msgLengths := make([]uint64, 0, len(b.messages))
	var messages = make([]byte, 0, len(b.messages)*estimatedMessageSize)

	lenWas := 0
	for i := range b.messages {
		messages = HashRepToBuff(b.messages[i], messages)
		msgLengths = append(msgLengths, uint64(len(messages)-lenWas))
		lenWas = len(messages)
	}
	allValid, failed := cgoBatchVerificationImpl(messages, msgLengths, b.publicKeys, b.signatures)
	if allValid {
		return failed, nil
	}
	return failed, ErrBatchHasFailedSigs
}

func (b *cgoBatchVerifier) singleVerify() (failed []bool, err error) {
	failed = make([]bool, len(b.messages))
	var containsFailed bool

	for i := range b.messages {
		failed[i] = !ed25519Verify(ed25519PublicKey(b.publicKeys[i]), HashRep(b.messages[i]), ed25519Signature(b.signatures[i]))
		if failed[i] {
			containsFailed = true
		}
	}
	if containsFailed {
		return failed, ErrBatchHasFailedSigs
	}
	return failed, nil
}

// cgoBatchVerificationImpl invokes the ed25519 batch verification algorithm.
// it returns true if all the signatures were authentically signed by the owners
// otherwise, returns false, and sets the indexes of the failed sigs in failed
func cgoBatchVerificationImpl(messages []byte, msgLengths []uint64, publicKeys []SignatureVerifier, signatures []Signature) (allSigsValid bool, failed []bool) {

	numberOfSignatures := len(msgLengths)
	valid := make([]C.int, numberOfSignatures)
	messages2D := make([]*C.uchar, numberOfSignatures)
	publicKeys2D := make([]*C.uchar, numberOfSignatures)
	signatures2D := make([]*C.uchar, numberOfSignatures)

	// call the batch verifier
	allValid := C.ed25519_batch_wrapper(
		&messages2D[0], &publicKeys2D[0], &signatures2D[0],
		(*C.uchar)(&messages[0]),
		(*C.ulonglong)(&msgLengths[0]),
		(*C.uchar)(&publicKeys[0][0]),
		(*C.uchar)(&signatures[0][0]),
		C.size_t(numberOfSignatures),
		(*C.int)(&valid[0]))

	failed = make([]bool, numberOfSignatures)
	for i := 0; i < numberOfSignatures; i++ {
		failed[i] = (valid[i] == 0)
	}
	return allValid == 0, failed
}
