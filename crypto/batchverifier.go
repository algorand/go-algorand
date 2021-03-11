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

// #cgo CFLAGS: -Wall -std=c99 -Ied25519-donna
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libs/darwin/amd64/lib/ed25519-donna.o
// #cgo linux,amd64 LDFLAGS: ${SRCDIR}/libs/linux/amd64/lib/ed25519-donna.o
// #cgo linux,arm64 LDFLAGS: ${SRCDIR}/libs/linux/arm64/lib/ed25519-donna.o
// #cgo linux,arm LDFLAGS: ${SRCDIR}/libs/linux/arm/lib/ed25519-donna.o
// #cgo windows,amd64 LDFLAGS: ${SRCDIR}/libs/windows/amd64/lib/ed25519-donna.o
// #include "ed25519-donna/ed25519.h"
// enum {
//	sizeofPtr = sizeof(void*),
// };
import "C"
import (
	"unsafe"
)

//export ed25519_randombytes_unsafe
func ed25519_randombytes_unsafe(p unsafe.Pointer, len C.size_t) {
	RandBytes(C.GoBytes(p, C.int(len)))
}

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
		publicKeys: make([]byte, 0, hint*ed25519PublicKeyLenBytes),
		signatures: make([]byte, 0, hint*ed25519SignatureLenBytes),
		failed:     false,
	}
}

// Enqueue enqueues a verification of a SignatureVerifier
func (b *BatchVerifier) Enqueue(sigVerifier SignatureVerifier, message Hashable, sig Signature) {
	// do we need to reallocate ?
	if len(b.messages) == cap(b.messages) {
		b.expand()
	}
	b.messages = append(b.messages, hashRep(message))
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

// int ed25519_sign_open_batch(const unsigned char **m, size_t *mlen, const unsigned char **pk, const unsigned char **RS, size_t num, int *valid);

// Verify verifies that the enqueued signatures are good, returning false if a verification of any
// of them fails.
func (b *BatchVerifier) Verify() bool {
	if b.failed {
		return false
	}

	// allocate staging memory
	messages := C.malloc(C.ulong(C.sizeofPtr * len(b.messages)))
	messagesLen := C.malloc(C.ulong(C.sizeof_size_t * len(b.messages)))
	publicKeys := C.malloc(C.ulong(C.sizeofPtr * len(b.messages)))
	signatures := C.malloc(C.ulong(C.sizeofPtr * len(b.messages)))
	valid := C.malloc(C.ulong(C.sizeof_int * len(b.messages)))

	preallocatedPublicKeys := unsafe.Pointer(&b.publicKeys[0])
	preallocatedSignatures := unsafe.Pointer(&b.signatures[0])

	// load all the data pointers into the array pointers.
	for i := 0; i < len(b.messages); i++ {
		*(*uintptr)(unsafe.Pointer(uintptr(messages) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(&b.messages[i][0]))
		*(*C.size_t)(unsafe.Pointer(uintptr(messagesLen) + uintptr(i*C.sizeof_size_t))) = C.size_t(len(b.messages[i]))
		*(*uintptr)(unsafe.Pointer(uintptr(publicKeys) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(uintptr(preallocatedPublicKeys) + uintptr(i*ed25519PublicKeyLenBytes)))
		*(*uintptr)(unsafe.Pointer(uintptr(signatures) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(uintptr(preallocatedSignatures) + uintptr(i*ed25519SignatureLenBytes)))
	}

	// call the batch verifier
	allValid := C.ed25519_sign_open_batch(
		(**C.uchar)(unsafe.Pointer(messages)),
		(*C.size_t)(unsafe.Pointer(messagesLen)),
		(**C.uchar)(unsafe.Pointer(publicKeys)),
		(**C.uchar)(unsafe.Pointer(signatures)),
		C.size_t(len(b.messages)),
		(*C.int)(unsafe.Pointer(valid))) == 0

	// release staging memory
	C.free(messages)
	C.free(messagesLen)
	C.free(publicKeys)
	C.free(signatures)
	C.free(valid)

	return allValid
}

// VerifySlow verifies that the enqueued signatures are good, returning false if a verification of any
// of them fails. The implementation is the naive implementation and the entries are being iterated.
func (b *BatchVerifier) VerifySlow() bool {
	if b.failed {
		return false
	}

	// iterate and verify each of the signatures.
	var sigVerifier SignatureVerifier
	var sig Signature
	for i := 0; i < len(b.messages); i++ {
		copy(sigVerifier[:], b.publicKeys[i*ed25519PublicKeyLenBytes:])
		copy(sig[:], b.signatures[i*ed25519SignatureLenBytes:])
		if !sigVerifier.VerifyBytes(b.messages[i][:], sig) {
			return false
		}
	}

	return true
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
