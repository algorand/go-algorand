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

import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

// removed: -Wshorten-64-to-32 -Wsometimes-uninitialized -Wmissing-declarations

// #cgo CFLAGS: -std=c99 -I${SRCDIR}/libsodium-fork/src/libsodium/include/  -I${SRCDIR}/libsodium-fork/src/libsodium/ -I${SRCDIR}/libsodium-fork/src/libsodium/include/sodium/
// #cgo CFLAGS: -g -O2 -pthread -fvisibility=hidden -fPIC -fPIE -fno-strict-aliasing -Wno-unused-parameter  -fstack-protector  -Wno-unknown-warning-option -Wbad-function-cast  -Wdiv-by-zero -Wduplicated-branches -Wduplicated-cond -Wfloat-equal -Wformat=2 -Wlogical-op -Wmaybe-uninitialized -Wmisleading-indentation  -Wnested-externs -Wno-type-limits -Wno-unknown-pragmas -Wnormalized=id -Wnull-dereference -Wold-style-declaration -Wpointer-arith -Wredundant-decls -Wrestrict  -Wstrict-prototypes -Wswitch-enum  -Wwrite-strings
// #cgo CFLAGS:  -DPACKAGE_NAME="libsodium" -DPACKAGE_TARNAME="libsodium" -DPACKAGE_VERSION="1.0.17" -DPACKAGE_STRING="libsodium 1.0.17" -DPACKAGE_BUGREPORT="https://github.com/jedisct1/libsodium/issues" -DPACKAGE_URL="https://github.com/jedisct1/libsodium" -DPACKAGE="libsodium" -DVERSION="1.0.17" -DHAVE_PTHREAD_PRIO_INHERIT=1 -DHAVE_PTHREAD=1 -DHAVE_STDIO_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_STRINGS_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_UNISTD_H=1 -DHAVE_WCHAR_H=1 -DSTDC_HEADERS=1 -D_ALL_SOURCE=1 -D_DARWIN_C_SOURCE=1 -D_GNU_SOURCE=1 -D_HPUX_ALT_XOPEN_SOCKET_API=1 -D_NETBSD_SOURCE=1 -D_OPENBSD_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D__STDC_WANT_IEC_60559_ATTRIBS_EXT__=1 -D__STDC_WANT_IEC_60559_BFP_EXT__=1 -D__STDC_WANT_IEC_60559_DFP_EXT__=1 -D__STDC_WANT_IEC_60559_FUNCS_EXT__=1 -D__STDC_WANT_IEC_60559_TYPES_EXT__=1 -D__STDC_WANT_LIB_EXT2__=1 -D__STDC_WANT_MATH_SPEC_FUNCS__=1 -D_TANDEM_SOURCE=1 -D__EXTENSIONS__=1 -DHAVE_C_VARARRAYS=1 -DHAVE_CATCHABLE_ABRT=1 -DTLS=_Thread_local -DHAVE_DLFCN_H=1 -DLT_OBJDIR=".libs/" -DHAVE_MMINTRIN_H=1 -DHAVE_EMMINTRIN_H=1 -DHAVE_PMMINTRIN_H=1 -DHAVE_TMMINTRIN_H=1 -DHAVE_SMMINTRIN_H=1 -DHAVE_AVXINTRIN_H=1 -DHAVE_AVX2INTRIN_H=1 -DHAVE_AVX512FINTRIN_H=1 -DHAVE_WMMINTRIN_H=1 -DHAVE_RDRAND=1 -DHAVE_SYS_MMAN_H=1 -DNATIVE_LITTLE_ENDIAN=1 -DHAVE_INLINE_ASM=1 -DHAVE_AMD64_ASM=1 -DHAVE_AVX_ASM=1 -DHAVE_TI_MODE=1 -DHAVE_CPUID=1 -DASM_HIDE_SYMBOL=.private_extern -DHAVE_WEAK_SYMBOLS=1 -DCPU_UNALIGNED_ACCESS=1 -DHAVE_ATOMIC_OPS=1 -DHAVE_ALLOCA_H=1 -DHAVE_ALLOCA=1 -DHAVE_ARC4RANDOM=1 -DHAVE_ARC4RANDOM_BUF=1 -DHAVE_MMAP=1 -DHAVE_MLOCK=1 -DHAVE_MADVISE=1 -DHAVE_MPROTECT=1 -DHAVE_NANOSLEEP=1 -DHAVE_POSIX_MEMALIGN=1 -DHAVE_GETPID=1 -DCONFIGURED=1
// #cgo CFLAGS: -maes -mavx -mavx2 -mavx512f   -msse2 -msse3 -msse4.1 -mssse3
// #include "sodium.h"
// #include "crypto_hash/sha512/hash_sha512.c"
// #include "crypto_hash/sha512/cp/hash_sha512_cp.c"
// #include "crypto_sign/crypto_sign.c"
// #include "sodium/utils_mini.c"
// #include "crypto_verify/sodium/verify.c"
// #include "crypto_core/ed25519/core_ed25519.c"
// #include "crypto_core/ed25519/ref10/ed25519_ref10.c"
// #include "crypto_sign/ed25519/sign_ed25519.c"
// #include "crypto_sign/ed25519/ref10/open_bv_compat.c"
// #include "crypto_sign/ed25519/ref10/keypair.c"
// #include "crypto_sign/ed25519/ref10/open.c"
// #include "crypto_sign/ed25519/ref10/sign.c"
// #include "crypto_sign/ed25519/ref10/batch.c"
// #include "crypto_vrf/ietfdraft03/convert.c"
// #include "crypto_vrf/ietfdraft03/keypair.c"
// #include "crypto_vrf/ietfdraft03/prove.c"
// #include "crypto_vrf/ietfdraft03/verify.c"
// #include "crypto_vrf/ietfdraft03/vrf.c"
// #include "crypto_vrf/crypto_vrf.c"
// enum {
//	sizeofPtr = sizeof(void*),
//	sizeofULongLong = sizeof(unsigned long long),
// };
import "C"

func init() {
	//if C.sodium_init() < 0 {
	//	logging.Init()
	//	logging.Base().Fatal("failed to initialize libsodium!")
	//}

	// Check sizes of structs
	_ = [C.crypto_sign_ed25519_BYTES]byte(ed25519Signature{})
	_ = [C.crypto_sign_ed25519_PUBLICKEYBYTES]byte(ed25519PublicKey{})
	_ = [C.crypto_sign_ed25519_SECRETKEYBYTES]byte(ed25519PrivateKey{})
	_ = [C.crypto_sign_ed25519_SEEDBYTES]byte(ed25519Seed{})
}

/* Classical signatures */
type ed25519Signature [64]byte
type ed25519PublicKey [32]byte
type ed25519PrivateKey [64]byte
type ed25519Seed [32]byte

func ed25519GenerateKeySeed(seed ed25519Seed) (public ed25519PublicKey, secret ed25519PrivateKey) {
	C.crypto_sign_ed25519_seed_keypair((*C.uchar)(&public[0]), (*C.uchar)(&secret[0]), (*C.uchar)(&seed[0]))
	return
}

func ed25519Sign(secret ed25519PrivateKey, data []byte) (sig ed25519Signature) {
	// &data[0] will make Go panic if msg is zero length
	d := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		d = (*C.uchar)(&data[0])
	}
	// https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures#detached-mode
	C.crypto_sign_ed25519_detached((*C.uchar)(&sig[0]), (*C.ulonglong)(C.NULL), d, C.ulonglong(len(data)), (*C.uchar)(&secret[0]))
	return
}

func ed25519Verify(public ed25519PublicKey, data []byte, sig ed25519Signature) bool {
	// &data[0] will make Go panic if msg is zero length
	d := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		d = (*C.uchar)(&data[0])
	}
	// https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures#detached-mode
	result := C.crypto_sign_ed25519_bv_compatible_verify_detached((*C.uchar)(&sig[0]), d, C.ulonglong(len(data)), (*C.uchar)(&public[0]))
	return result == 0
}

// SecretKeyToPublicKey derives a public key from a secret key. This is very
// efficient since ed25519 private keys literally contain their public key
func SecretKeyToPublicKey(secret PrivateKey) (PublicKey, error) {
	var pk PublicKey
	result := C.crypto_sign_ed25519_sk_to_pk((*C.uchar)(&pk[0]), (*C.uchar)(&secret[0]))
	if result != 0 {
		return pk, fmt.Errorf("failed to extract public key: %d", result)
	}
	return pk, nil
}

// SecretKeyToSeed derives the seed from a secret key. This is very efficient
// since ed25519 private keys literally contain their seed
func SecretKeyToSeed(secret PrivateKey) (Seed, error) {
	var seed Seed
	result := C.crypto_sign_ed25519_sk_to_seed((*C.uchar)(&seed[0]), (*C.uchar)(&secret[0]))
	if result != 0 {
		return seed, fmt.Errorf("failed to extract seed: %d", result)
	}
	return seed, nil
}

// Hash converts a VRF proof to a VRF output without verifying the proof.
// TODO: Consider removing so that we don't accidentally hash an unverified proof
func (proof VrfProof) Hash() (hash VrfOutput, ok bool) {
	ret := C.crypto_vrf_proof_to_hash((*C.uchar)(&hash[0]), (*C.uchar)(&proof[0]))
	return hash, ret == 0
}

func (pk VrfPubkey) verifyBytes(proof VrfProof, msg []byte) (bool, VrfOutput) {
	var out VrfOutput
	// &msg[0] will make Go panic if msg is zero length
	m := (*C.uchar)(C.NULL)
	if len(msg) != 0 {
		m = (*C.uchar)(&msg[0])
	}
	ret := C.crypto_vrf_verify((*C.uchar)(&out[0]), (*C.uchar)(&pk[0]), (*C.uchar)(&proof[0]), (*C.uchar)(m), (C.ulonglong)(len(msg)))
	return ret == 0, out
}

// VrfKeygenFromSeed deterministically generates a VRF keypair from 32 bytes of (secret) entropy.
func VrfKeygenFromSeed(seed [32]byte) (pub VrfPubkey, priv VrfPrivkey) {
	C.crypto_vrf_keypair_from_seed((*C.uchar)(&pub[0]), (*C.uchar)(&priv[0]), (*C.uchar)(&seed[0]))
	return pub, priv
}

// VrfKeygen generates a random VRF keypair.
func VrfKeygen() (pub VrfPubkey, priv VrfPrivkey) {
	C.crypto_vrf_keypair((*C.uchar)(&pub[0]), (*C.uchar)(&priv[0]))
	return pub, priv
}

// Pubkey returns the public key that corresponds to the given private key.
func (sk VrfPrivkey) Pubkey() (pk VrfPubkey) {
	C.crypto_vrf_sk_to_pk((*C.uchar)(&pk[0]), (*C.uchar)(&sk[0]))
	return pk
}

func (sk VrfPrivkey) proveBytes(msg []byte) (proof VrfProof, ok bool) {
	// &msg[0] will make Go panic if msg is zero length
	m := (*C.uchar)(C.NULL)
	if len(msg) != 0 {
		m = (*C.uchar)(&msg[0])
	}
	ret := C.crypto_vrf_prove((*C.uchar)(&proof[0]), (*C.uchar)(&sk[0]), (*C.uchar)(m), (C.ulonglong)(len(msg)))
	return proof, ret == 0
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
