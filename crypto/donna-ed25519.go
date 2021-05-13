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
import "unsafe"

type DonnaSeed ed25519DonnaSeed

type ed25519DonnaSignature [64]byte
type ed25519DonnaPublicKey [32]byte
type ed25519DonnaPrivateKey [64]byte
type ed25519DonnaSeed [32]byte

type DonnaPrivateKey ed25519DonnaPrivateKey

type DonnaPublicKey ed25519DonnaPublicKey

const ed25519DonnaPublicKeyLenBytes = 32
const ed25519DonnaSignatureLenBytes = 64

//export ed25519_randombytes_unsafe
func ed25519_randombytes_unsafe(p unsafe.Pointer, len C.size_t) {
	RandBytes(C.GoBytes(p, C.int(len)))
}

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

type DonnaSignature ed25519DonnaSignature

var BlankDonnaSignature = DonnaSignature{}

func (s *DonnaSignature) Blank() bool {
	return (*s) == BlankDonnaSignature
}

type DonnaSignatureVerifier = DonnaPublicKey

type DonnaSignatureSecrets struct {
	_struct struct{} `codec:""`

	DonnaSignatureVerifier
	SK ed25519DonnaPrivateKey
}

func GenerateSignatureSecretsDonna(seed DonnaSeed) *DonnaSignatureSecrets {
	pk0, sk := ed25519DonnaGenerateKeySeed(ed25519DonnaSeed(seed))
	pk := DonnaSignatureVerifier(pk0)
	return &DonnaSignatureSecrets{DonnaSignatureVerifier: pk, SK: sk}
}

func (s *DonnaSignatureSecrets) SignBytes(message []byte) DonnaSignature {
	return DonnaSignature(ed25519DonnaSign(s.SK, ed25519DonnaPublicKey(s.DonnaSignatureVerifier), message))
}

func (s *DonnaSignatureSecrets) Sign(message Hashable) DonnaSignature {
	return s.SignBytes(hashRep(message))
}

func (v DonnaSignatureVerifier) Verify(message Hashable, sig DonnaSignature) bool {
	return v.VerifyBytes(hashRep(message), sig)

}
func (v DonnaSignatureVerifier) VerifyBytes(message []byte, sig DonnaSignature) bool {
	cryptoSigSecretsVerifyBytesTotal.Inc(map[string]string{})
	return ed25519DonnaVerify(ed25519DonnaPublicKey(v), message, ed25519DonnaSignature(sig))
}

func DoonaBatchVerification(messages [][]byte, publicKeys []byte, signatures []byte, failed bool) bool {
	if failed {
		return false
	}

	numberOfSignatures := len(messages)
	// allocate staging memory
	messages_allocation := C.malloc(C.ulong(C.sizeofPtr * numberOfSignatures))
	messagesLen_allocation := C.malloc(C.ulong(C.sizeof_size_t * numberOfSignatures))
	publicKeys_allocation := C.malloc(C.ulong(C.sizeofPtr * numberOfSignatures))
	signatures_allocation := C.malloc(C.ulong(C.sizeofPtr * numberOfSignatures))
	valid := C.malloc(C.ulong(C.sizeof_int * numberOfSignatures))

	defer func() {
		// release staging memory
		C.free(messages_allocation)
		C.free(messagesLen_allocation)
		C.free(publicKeys_allocation)
		C.free(signatures_allocation)
		C.free(valid)
	}()

	preallocatedPublicKeys := unsafe.Pointer(&publicKeys[0])
	preallocatedSignatures := unsafe.Pointer(&signatures[0])

	// load all the data pointers into the array pointers.
	for i := 0; i < numberOfSignatures; i++ {
		*(*uintptr)(unsafe.Pointer(uintptr(messages_allocation) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(&messages[i][0]))
		*(*C.size_t)(unsafe.Pointer(uintptr(messagesLen_allocation) + uintptr(i*C.sizeof_size_t))) = C.size_t(len(messages[i]))
		*(*uintptr)(unsafe.Pointer(uintptr(publicKeys_allocation) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(uintptr(preallocatedPublicKeys) + uintptr(i*ed25519DonnaPublicKeyLenBytes)))
		*(*uintptr)(unsafe.Pointer(uintptr(signatures_allocation) + uintptr(i*C.sizeofPtr))) = uintptr(unsafe.Pointer(uintptr(preallocatedSignatures) + uintptr(i*ed25519DonnaSignatureLenBytes)))
	}

	// call the batch verifier
	allValid := C.ed25519_sign_open_batch(
		(**C.uchar)(unsafe.Pointer(messages_allocation)),
		(*C.size_t)(unsafe.Pointer(messagesLen_allocation)),
		(**C.uchar)(unsafe.Pointer(publicKeys_allocation)),
		(**C.uchar)(unsafe.Pointer(signatures_allocation)),
		C.size_t(len(messages)),
		(*C.int)(unsafe.Pointer(valid))) == 0

	return allValid
}
