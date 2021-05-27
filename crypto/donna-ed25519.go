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

// #cgo CFLAGS: -I${SRCDIR}/ed25519-donna/ -Wall -Werror -std=c99 -Wno-incompatible-pointer-types-discards-qualifiers -m64 -O3 -DED25519_REFHASH -DED25519_CUSTOMRANDOM -Wno-macro-redefined
// /*
// 	Public domain by Andrew M. <liquidsun@gmail.com>
//
// 	Ed25519 reference implementation using Ed25519-donna
// */
//
// /* define ED25519_SUFFIX to have it appended to the end of each public function */
// #if !defined(ED25519_SUFFIX)
// #define ED25519_SUFFIX
// #endif
//
// #define ED25519_FN3(fn,suffix) fn##suffix
// #define ED25519_FN2(fn,suffix) ED25519_FN3(fn,suffix)
// #define ED25519_FN(fn)         ED25519_FN2(fn,ED25519_SUFFIX)
//
// #include "ed25519-donna.h"
// #include "ed25519.h"
// #include "ed25519-randombytes.h"
// #include "ed25519-hash.h"
//
// /*
// 	Generates a (extsk[0..31]) and aExt (extsk[32..63])
// */
//
// DONNA_INLINE static void
// ed25519_extsk(hash_512bits extsk, const ed25519_secret_key sk) {
// 	ed25519_hash(extsk, sk, 32);
// 	extsk[0] &= 248;
// 	extsk[31] &= 127;
// 	extsk[31] |= 64;
// }
//
// static void
// ed25519_hram(hash_512bits hram, const ed25519_signature RS, const ed25519_public_key pk, const unsigned char *m, size_t mlen) {
// 	ed25519_hash_context ctx;
// 	ed25519_hash_init(&ctx);
// 	ed25519_hash_update(&ctx, RS, 32);
// 	ed25519_hash_update(&ctx, pk, 32);
// 	ed25519_hash_update(&ctx, m, mlen);
// 	ed25519_hash_final(&ctx, hram);
// }
//
// void
// ED25519_FN(ed25519_publickey) (const ed25519_secret_key sk, ed25519_public_key pk) {
// 	bignum256modm a;
// 	ge25519 ALIGN(16) A;
// 	hash_512bits extsk;
//
// 	/* A = aB */
// 	ed25519_extsk(extsk, sk);
// 	expand256_modm(a, extsk, 32);
// 	ge25519_scalarmult_base_niels(&A, ge25519_niels_base_multiples, a);
// 	ge25519_pack(pk, &A);
// }
//
// void
// ED25519_FN(ed25519_sign) (const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS) {
// 	ed25519_hash_context ctx;
// 	bignum256modm r, S, a;
// 	ge25519 ALIGN(16) R;
// 	hash_512bits extsk, hashr, hram;
//
// 	ed25519_extsk(extsk, sk);
//
// 	/* r = H(aExt[32..64], m) */
// 	ed25519_hash_init(&ctx);
// 	ed25519_hash_update(&ctx, extsk + 32, 32);
// 	ed25519_hash_update(&ctx, m, mlen);
// 	ed25519_hash_final(&ctx, hashr);
// 	expand256_modm(r, hashr, 64);
//
// 	/* R = rB */
// 	ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r);
// 	ge25519_pack(RS, &R);
//
// 	/* S = H(R,A,m).. */
// 	ed25519_hram(hram, RS, pk, m, mlen);
// 	expand256_modm(S, hram, 64);
//
// 	/* S = H(R,A,m)a */
// 	expand256_modm(a, extsk, 32);
// 	mul256_modm(S, S, a);
//
// 	/* S = (r + H(R,A,m)a) */
// 	add256_modm(S, S, r);
//
// 	/* S = (r + H(R,A,m)a) mod L */
// 	contract256_modm(RS + 32, S);
// }
//
// int
// ED25519_FN(ed25519_sign_open) (const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS) {
// 	ge25519 ALIGN(16) R, A;
// 	hash_512bits hash;
// 	bignum256modm hram, S;
// 	unsigned char checkR[32];
//
// 	if ((RS[63] & 224) || !ge25519_unpack_negative_vartime(&A, pk))
// 		return -1;
//
// 	/* hram = H(R,A,m) */
// 	ed25519_hram(hash, RS, pk, m, mlen);
// 	expand256_modm(hram, hash, 64);
//
// 	/* S */
// 	expand256_modm(S, RS + 32, 32);
//
// 	/* SB - H(R,A,m)A */
// 	ge25519_double_scalarmult_vartime(&R, &A, hram, S);
// 	ge25519_pack(checkR, &R);
//
// 	/* check that R = SB - H(R,A,m)A */
// 	return ed25519_verify(RS, checkR, 32) ? 0 : -1;
// }
//
// #include "ed25519-donna-batchverify.h"
//
// /*
// 	Fast Curve25519 basepoint scalar multiplication
// */
//
// void
// ED25519_FN(curved25519_scalarmult_basepoint) (curved25519_key pk, const curved25519_key e) {
// 	curved25519_key ec;
// 	bignum256modm s;
// 	bignum25519 ALIGN(16) yplusz, zminusy;
// 	ge25519 ALIGN(16) p;
// 	size_t i;
//
// 	/* clamp */
// 	for (i = 0; i < 32; i++) ec[i] = e[i];
// 	ec[0] &= 248;
// 	ec[31] &= 127;
// 	ec[31] |= 64;
//
// 	expand_raw256_modm(s, ec);
//
// 	/* scalar * basepoint */
// 	ge25519_scalarmult_base_niels(&p, ge25519_niels_base_multiples, s);
//
// 	/* u = (y + z) / (z - y) */
// 	curve25519_add(yplusz, p.y, p.z);
// 	curve25519_sub(zminusy, p.z, p.y);
// 	curve25519_recip(zminusy, zminusy);
// 	curve25519_mul(yplusz, yplusz, zminusy);
// 	curve25519_contract(pk, yplusz);
//
// }
// enum {
//	sizeofPtr = sizeof(void*),
// };
import "C"
import (
	"unsafe"
)

// DonnaSeed type represents a source of entropy used by the cryptographic functions
type DonnaSeed ed25519DonnaSeed

type ed25519DonnaSignature [64]byte
type ed25519DonnaPublicKey [32]byte
type ed25519DonnaPrivateKey [64]byte
type ed25519DonnaSeed [32]byte

// DonnaPrivateKey epresents a prviate key in the ed25519 donna implementation
type DonnaPrivateKey ed25519DonnaPrivateKey

// DonnaPublicKey represents a public key in the ed25519 donna implementation
type DonnaPublicKey ed25519DonnaPublicKey

func ed25519DonnaGenerateKey() (public ed25519DonnaPublicKey, secret ed25519DonnaPrivateKey) {
	var seed ed25519DonnaSeed
	RandBytes(seed[:])
	return ed25519DonnaGenerateKeySeed(seed)
}

func ed25519DonnaGenerateKeySeed(seed ed25519DonnaSeed) (public ed25519DonnaPublicKey, secret ed25519DonnaPrivateKey) {
	copy(secret[:], seed[:])
	C.ed25519_publickey((*C.uchar)(&secret[0]), (*C.uchar)(&public[0]))
	copy(secret[32:], public[:])
	return
}

func ed25519DonnaSign(secret ed25519DonnaPrivateKey, publicKey ed25519DonnaPublicKey, data []byte) (sig ed25519DonnaSignature) {
	d := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		d = (*C.uchar)(&data[0])
	}
	C.ed25519_sign(d, C.size_t(len(data)), (*C.uchar)(&secret[0]), (*C.uchar)(&publicKey[0]), (*C.uchar)(&sig[0]))

	return
}

func ed25519DonnaVerify(public ed25519DonnaPublicKey, data []byte, sig ed25519DonnaSignature) bool {
	// &data[0] will make Go panic if msg is zero length
	d := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		d = (*C.uchar)(&data[0])
	}

	//int ed25519_sign_open(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS);
	result := C.ed25519_sign_open(d, C.size_t(len(data)), (*C.uchar)(&public[0]), (*C.uchar)(&sig[0]))
	return result == 0
}

// The DonnaSignature is a cryptographic signature. It proves that a message was
// produced by a holder of a cryptographic secret.
// This signature type is used by the ed25519 donna implementation
type DonnaSignature ed25519DonnaSignature

// BlankDonnaSignature is an empty signature structure, containing nothing but zeroes
var BlankDonnaSignature = DonnaSignature{}

// Blank function checks if the signature is all zeros
func (s *DonnaSignature) Blank() bool {
	return (*s) == BlankDonnaSignature
}

// DonnaSignatureVerifier is used to identify the holder of SignatureSecrets
// and verify the authenticity of Signatures.
// This signature type is used by the ed25519 Idonna mplementation
type DonnaSignatureVerifier = DonnaPublicKey

// DonnaSignatureSecrets are used by an entity to produce unforgeable signatures over
// a message.
// This type is used by the ed25519 donna implementation
type DonnaSignatureSecrets struct {
	_struct struct{} `codec:""`

	DonnaSignatureVerifier
	SK ed25519DonnaPrivateKey
}

// GenerateSignatureSecretsDonna creates SignatureSecrets from a source of entropy.
// This function uses the ed25519 donna implementation
func GenerateSignatureSecretsDonna(seed DonnaSeed) *DonnaSignatureSecrets {
	pk0, sk := ed25519DonnaGenerateKeySeed(ed25519DonnaSeed(seed))
	pk := DonnaSignatureVerifier(pk0)
	return &DonnaSignatureSecrets{DonnaSignatureVerifier: pk, SK: sk}
}

// SignBytes signs a message directly, without first hashing.
// Caller is responsible for domain separation.
// This function uses the ed25519 donna implementation
func (s *DonnaSignatureSecrets) SignBytes(message []byte) DonnaSignature {
	return DonnaSignature(ed25519DonnaSign(s.SK, ed25519DonnaPublicKey(s.DonnaSignatureVerifier), message))
}

// Sign produces a cryptographic Signature of a Hashable message, given
// cryptographic secrets.
// This function uses the ed25519 donna implementation
func (s *DonnaSignatureSecrets) Sign(message Hashable) DonnaSignature {
	return s.SignBytes(hashRep(message))
}

// Verify verifies that some holder of a cryptographic secret authentically
// signed a Hashable message.
//
// This function uses the ed25519 donna implementation
func (v DonnaSignatureVerifier) Verify(message Hashable, sig DonnaSignature) bool {
	return v.VerifyBytes(hashRep(message), sig)

}

// VerifyBytes verifies a signature, where the message is not hashed first.
// Caller is responsible for domain separation.
// If the message is a Hashable, Verify() can be used instead.
func (v DonnaSignatureVerifier) VerifyBytes(message []byte, sig DonnaSignature) bool {
	cryptoSigSecretsVerifyBytesTotal.Inc(map[string]string{})
	return ed25519DonnaVerify(ed25519DonnaPublicKey(v), message, ed25519DonnaSignature(sig))
}

// DonnaBatchVerification calls the batch verification implemention in C. it prepares the arguments
// to create a call to C code.
// it returns true if all the signatures were authentically signed by the owners
func DonnaBatchVerification(messages [][]byte, publicKeys []DonnaSignatureVerifier, signatures []DonnaSignature, failed bool) bool {
	if failed {
		return false
	}

	numberOfSignatures := len(messages)

	messagesAllocation := C.malloc(C.size_t(C.sizeofPtr * numberOfSignatures))
	messagesLenAllocation := C.malloc(C.size_t(C.sizeof_size_t * numberOfSignatures))
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
		*(*C.size_t)(unsafe.Pointer(uintptr(messagesLenAllocation) + uintptr(i*C.sizeof_size_t))) = C.size_t(len(messages[i]))
		*(*uintptr)(unsafe.Pointer(uintptr(publicKeysAllocation) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(&publicKeys[i][0]))
		*(*uintptr)(unsafe.Pointer(uintptr(signaturesAllocation) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(&signatures[i][0]))
	}

	// call the batch verifier
	allValid := C.ed25519_sign_open_batch(
		(**C.uchar)(unsafe.Pointer(messagesAllocation)),
		(*C.size_t)(unsafe.Pointer(messagesLenAllocation)),
		(**C.uchar)(unsafe.Pointer(publicKeysAllocation)),
		(**C.uchar)(unsafe.Pointer(signaturesAllocation)),
		C.size_t(len(messages)),
		(*C.int)(unsafe.Pointer(valid)))

	return allValid == 0
}
