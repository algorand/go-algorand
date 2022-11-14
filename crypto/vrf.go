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

// #cgo CFLAGS: -std=c99 -I${SRCDIR}/libsodium-fork/src/libsodium/include/  -I${SRCDIR}/libsodium-fork/src/libsodium/ -I${SRCDIR}/libsodium-fork/src/libsodium/include/sodium/
// #cgo CFLAGS: -g -O2 -pthread -fvisibility=hidden -fPIC -fPIE -fno-strict-aliasing -fstack-protector  -Wno-unknown-warning-option -Wno-unused-parameter  -Wbad-function-cast  -Wdiv-by-zero -Wduplicated-branches -Wduplicated-cond -Wfloat-equal -Wformat=2 -Wlogical-op -Wmaybe-uninitialized -Wmisleading-indentation -Wmissing-declarations  -Wnested-externs -Wno-type-limits -Wno-unknown-pragmas -Wnormalized=id -Wnull-dereference -Wold-style-declaration -Wpointer-arith -Wredundant-decls -Wrestrict -Wshorten-64-to-32 -Wsometimes-uninitialized -Wstrict-prototypes -Wswitch-enum -Wvariable-decl -Wwrite-strings
// #cgo CFLAGS:  -DPACKAGE_NAME="libsodium" -DPACKAGE_TARNAME="libsodium" -DPACKAGE_VERSION="1.0.17" -DPACKAGE_STRING="libsodium 1.0.17" -DPACKAGE_BUGREPORT="https://github.com/jedisct1/libsodium/issues" -DPACKAGE_URL="https://github.com/jedisct1/libsodium" -DPACKAGE="libsodium" -DVERSION="1.0.17" -DHAVE_PTHREAD_PRIO_INHERIT=1 -DHAVE_PTHREAD=1 -DHAVE_STDIO_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_STRINGS_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_UNISTD_H=1 -DHAVE_WCHAR_H=1 -DSTDC_HEADERS=1 -D_ALL_SOURCE=1 -D_DARWIN_C_SOURCE=1 -D_GNU_SOURCE=1 -D_HPUX_ALT_XOPEN_SOCKET_API=1 -D_NETBSD_SOURCE=1 -D_OPENBSD_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D__STDC_WANT_IEC_60559_ATTRIBS_EXT__=1 -D__STDC_WANT_IEC_60559_BFP_EXT__=1 -D__STDC_WANT_IEC_60559_DFP_EXT__=1 -D__STDC_WANT_IEC_60559_FUNCS_EXT__=1 -D__STDC_WANT_IEC_60559_TYPES_EXT__=1 -D__STDC_WANT_LIB_EXT2__=1 -D__STDC_WANT_MATH_SPEC_FUNCS__=1 -D_TANDEM_SOURCE=1 -D__EXTENSIONS__=1 -DHAVE_C_VARARRAYS=1 -DHAVE_CATCHABLE_ABRT=1 -DTLS=_Thread_local -DHAVE_DLFCN_H=1 -DLT_OBJDIR=".libs/" -DHAVE_MMINTRIN_H=1 -DHAVE_EMMINTRIN_H=1 -DHAVE_PMMINTRIN_H=1 -DHAVE_TMMINTRIN_H=1 -DHAVE_SMMINTRIN_H=1 -DHAVE_AVXINTRIN_H=1 -DHAVE_AVX2INTRIN_H=1 -DHAVE_AVX512FINTRIN_H=1 -DHAVE_WMMINTRIN_H=1 -DHAVE_RDRAND=1 -DHAVE_SYS_MMAN_H=1 -DNATIVE_LITTLE_ENDIAN=1 -DHAVE_INLINE_ASM=1 -DHAVE_AMD64_ASM=1 -DHAVE_AVX_ASM=1 -DHAVE_TI_MODE=1 -DHAVE_CPUID=1 -DASM_HIDE_SYMBOL=.private_extern -DHAVE_WEAK_SYMBOLS=1 -DCPU_UNALIGNED_ACCESS=1 -DHAVE_ATOMIC_OPS=1 -DHAVE_ALLOCA_H=1 -DHAVE_ALLOCA=1 -DHAVE_ARC4RANDOM=1 -DHAVE_ARC4RANDOM_BUF=1 -DHAVE_MMAP=1 -DHAVE_MLOCK=1 -DHAVE_MADVISE=1 -DHAVE_MPROTECT=1 -DHAVE_NANOSLEEP=1 -DHAVE_POSIX_MEMALIGN=1 -DHAVE_GETPID=1 -DCONFIGURED=1
// #cgo CFLAGS: -maes -mavx -mavx2 -mavx512f   -msse2 -msse3 -msse4.1 -mssse3
// #include "sodium.h"
// #include "crypto_vrf/ietfdraft03/convert.c"
// #include "crypto_vrf/ietfdraft03/keypair.c"
// #include "crypto_vrf/ietfdraft03/prove.c"
// #include "crypto_vrf/ietfdraft03/verify.c"
// #include "crypto_vrf/ietfdraft03/vrf.c"
// #include "crypto_vrf/crypto_vrf.c"
import "C"

// func init() {
// 	if C.sodium_init() == -1 {
// 		panic("sodium_init() failed")
// 	}
// }

// deprecated names + wrappers -- TODO remove

// VRFVerifier is a deprecated name for VrfPubkey
type VRFVerifier = VrfPubkey

// VRFProof is a deprecated name for VrfProof
type VRFProof = VrfProof

// VRFSecrets is a wrapper for a VRF keypair. Use *VrfPrivkey instead
type VRFSecrets struct {
	_struct struct{} `codec:""`

	PK VrfPubkey
	SK VrfPrivkey
}

// GenerateVRFSecrets is deprecated, use VrfKeygen or VrfKeygenFromSeed instead
func GenerateVRFSecrets() *VRFSecrets {
	s := new(VRFSecrets)
	s.PK, s.SK = VrfKeygen()
	return s
}

// TODO: Go arrays are copied by value, so any call to e.g. VrfPrivkey.Prove() makes a copy of the secret key that lingers in memory.
// To avoid this, should we instead allocate memory for secret keys here (maybe even in the C heap) and pass around pointers?
// e.g., allocate a privkey with sodium_malloc and have VrfPrivkey be of type unsafe.Pointer?
type (
	// A VrfPrivkey is a private key used for producing VRF proofs.
	// Specifically, we use a 64-byte ed25519 private key (the latter 32-bytes are the precomputed public key)
	VrfPrivkey [64]byte
	// A VrfPubkey is a public key that can be used to verify VRF proofs.
	VrfPubkey [32]byte
	// A VrfProof for a message can be generated with a secret key and verified against a public key, like a signature.
	// Proofs are malleable, however, for a given message and public key, the VRF output that can be computed from a proof is unique.
	VrfProof [80]byte
	// VrfOutput is a 64-byte pseudorandom value that can be computed from a VrfProof.
	// The VRF scheme guarantees that such output will be unique
	VrfOutput [64]byte
)

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

// Prove constructs a VRF Proof for a given Hashable.
// ok will be false if the private key is malformed.
func (sk VrfPrivkey) Prove(message Hashable) (proof VrfProof, ok bool) {
	return sk.proveBytes(HashRep(message))
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

// Verify checks a VRF proof of a given Hashable. If the proof is valid the pseudorandom VrfOutput will be returned.
// For a given public key and message, there are potentially multiple valid proofs.
// However, given a public key and message, all valid proofs will yield the same output.
// Moreover, the output is indistinguishable from random to anyone without the proof or the secret key.
func (pk VrfPubkey) Verify(p VrfProof, message Hashable) (bool, VrfOutput) {
	return pk.verifyBytes(p, HashRep(message))
}
