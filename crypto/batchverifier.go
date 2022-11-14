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

//// removed: -Wshorten-64-to-32 -Wsometimes-uninitialized -Wmissing-declarations

// #cgo CFLAGS: -std=c99 -I${SRCDIR}/libsodium-fork/src/libsodium/include/  -I${SRCDIR}/libsodium-fork/src/libsodium/ -I${SRCDIR}/libsodium-fork/src/libsodium/include/sodium/
// #cgo CFLAGS: -g -O2 -pthread -fvisibility=hidden -fPIC -fPIE -fno-strict-aliasing -fstack-protector  -Wno-unknown-warning-option -Wno-unused-parameter  -Wbad-function-cast  -Wdiv-by-zero -Wduplicated-branches -Wduplicated-cond -Wfloat-equal -Wformat=2 -Wlogical-op -Wmaybe-uninitialized -Wmisleading-indentation -Wmissing-declarations  -Wnested-externs -Wno-type-limits -Wno-unknown-pragmas -Wnormalized=id -Wnull-dereference -Wold-style-declaration -Wpointer-arith -Wredundant-decls -Wrestrict  -Wstrict-prototypes -Wswitch-enum -Wwrite-strings
// #cgo CFLAGS:  -DPACKAGE_NAME="libsodium" -DPACKAGE_TARNAME="libsodium" -DPACKAGE_VERSION="1.0.17" -DPACKAGE_STRING="libsodium 1.0.17" -DPACKAGE_BUGREPORT="https://github.com/jedisct1/libsodium/issues" -DPACKAGE_URL="https://github.com/jedisct1/libsodium" -DPACKAGE="libsodium" -DVERSION="1.0.17" -DHAVE_PTHREAD_PRIO_INHERIT=1 -DHAVE_PTHREAD=1 -DHAVE_STDIO_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_STRINGS_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_UNISTD_H=1 -DHAVE_WCHAR_H=1 -DSTDC_HEADERS=1 -D_ALL_SOURCE=1 -D_DARWIN_C_SOURCE=1 -D_GNU_SOURCE=1 -D_HPUX_ALT_XOPEN_SOCKET_API=1 -D_NETBSD_SOURCE=1 -D_OPENBSD_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D__STDC_WANT_IEC_60559_ATTRIBS_EXT__=1 -D__STDC_WANT_IEC_60559_BFP_EXT__=1 -D__STDC_WANT_IEC_60559_DFP_EXT__=1 -D__STDC_WANT_IEC_60559_FUNCS_EXT__=1 -D__STDC_WANT_IEC_60559_TYPES_EXT__=1 -D__STDC_WANT_LIB_EXT2__=1 -D__STDC_WANT_MATH_SPEC_FUNCS__=1 -D_TANDEM_SOURCE=1 -D__EXTENSIONS__=1 -DHAVE_C_VARARRAYS=1 -DHAVE_CATCHABLE_ABRT=1 -DTLS=_Thread_local -DHAVE_DLFCN_H=1 -DLT_OBJDIR=".libs/" -DHAVE_MMINTRIN_H=1 -DHAVE_EMMINTRIN_H=1 -DHAVE_PMMINTRIN_H=1 -DHAVE_TMMINTRIN_H=1 -DHAVE_SMMINTRIN_H=1 -DHAVE_AVXINTRIN_H=1 -DHAVE_AVX2INTRIN_H=1 -DHAVE_AVX512FINTRIN_H=1 -DHAVE_WMMINTRIN_H=1 -DHAVE_RDRAND=1 -DHAVE_SYS_MMAN_H=1 -DNATIVE_LITTLE_ENDIAN=1 -DHAVE_INLINE_ASM=1 -DHAVE_AMD64_ASM=1 -DHAVE_AVX_ASM=1 -DHAVE_TI_MODE=1 -DHAVE_CPUID=1 -DASM_HIDE_SYMBOL=.private_extern -DHAVE_WEAK_SYMBOLS=1 -DCPU_UNALIGNED_ACCESS=1 -DHAVE_ATOMIC_OPS=1 -DHAVE_ALLOCA_H=1 -DHAVE_ALLOCA=1 -DHAVE_ARC4RANDOM=1 -DHAVE_ARC4RANDOM_BUF=1 -DHAVE_MMAP=1 -DHAVE_MLOCK=1 -DHAVE_MADVISE=1 -DHAVE_MPROTECT=1 -DHAVE_NANOSLEEP=1 -DHAVE_POSIX_MEMALIGN=1 -DHAVE_GETPID=1 -DCONFIGURED=1
// #cgo CFLAGS: -maes -mavx -mavx2 -mavx512f   -msse2 -msse3 -msse4.1 -mssse3
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
		failed[i] = cint == 0
	}
	return allValid == 0, failed
}
