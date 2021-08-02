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

//#include "randombytes.h"
// #cgo CFLAGS: -g -Wall
// #cgo darwin,amd64 CFLAGS: -I${SRCDIR}/dillibs
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/dillibs/libdilithium2_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/dillibs/libaes256ctr_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/dillibs/libdilithium2_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/dillibs/libdilithium2aes_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/dillibs/libdilithium3_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/dillibs/libdilithium3aes_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/dillibs/libdilithium5_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/dillibs/libdilithium5aes_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/dillibs/libfips202_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/dillibs/librndbytes.a
//#include <stdlib.h>
//#include "api.h"
import "C"

type (
	dil2Signature  [2420]byte
	dil2PublicKey  [1312]byte
	dil2PrivateKey [2528]byte

	// The following types are what we export. Used as public and private key, and signature type.
	// Their length should conform to the above types.

	//DilithiumPublicKey is the public key
	//msgp:allocbound DilithiumPublicKey
	DilithiumPublicKey []byte
	//DilithiumPrivateKey is the public key
	//msgp:allocbound DilithiumPrivateKey
	DilithiumPrivateKey []byte
	//DilithiumSignature is the public key
	//msgp:allocbound DilithiumSignature
	DilithiumSignature ByteSignature
)

func init() {
	// Check sizes of structs
	_ = [C.pqcrystals_dilithium2_BYTES]byte(dil2Signature{})
	_ = [C.pqcrystals_dilithium2_PUBLICKEYBYTES]byte(dil2PublicKey{})
	_ = [C.pqcrystals_dilithium2_SECRETKEYBYTES]byte(dil2PrivateKey{})
}

// DilithiumSigner is the implementation of Signer for the Dilithium signature scheme.
type DilithiumSigner struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SecretKey DilithiumPrivateKey `codec:"sk"`
	PublicKey DilithiumPublicKey  `codec:"pk"`
}

// NewDilithiumSigner Generates a dilithium Signer.
func NewDilithiumSigner() Signer {
	pk := dil2PublicKey{}
	sk := dil2PrivateKey{}
	C.pqcrystals_dilithium2_ref_keypair((*C.uchar)(&(pk[0])), (*C.uchar)(&(sk[0])))
	return &DilithiumSigner{
		SecretKey: sk[:],
		PublicKey: pk[:],
	}
}

// Sign receives a message and generates a signature over that message.
// the size of the signature should conform with dil2Signature.
func (d *DilithiumSigner) Sign(message Hashable) ByteSignature {
	hs := Hash(hashRep(message))
	return d.SignBytes(hs[:])
}

// SignBytes receives bytes and signs over them.
// the size of the signature should conform with dil2Signature.
func (d *DilithiumSigner) SignBytes(data []byte) ByteSignature {
	cdata := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		cdata = (*C.uchar)(&data[0])
	}
	var sig dil2Signature
	var smlen uint64
	C.pqcrystals_dilithium2_ref((*C.uchar)(&sig[0]), (*C.size_t)(&smlen), (*C.uchar)(cdata), (C.size_t)(len(data)), (*C.uchar)(&(d.SecretKey[0])))
	return sig[:]
}

// GetVerifyingKey Outputs a veryfying key ovject which is serializeable.
func (d *DilithiumSigner) GetVerifyingKey() *VerifyingKey {
	pk := dil2PublicKey{}
	copy(pk[:], d.PublicKey)
	return &VerifyingKey{
		Type: DilithiumType,
		Pack: PackedVerifyingKey{
			DilithiumPublicKey: DilithiumVerifier{
				PublicKey: pk[:]},
		},
	}
}

// DilithiumVerifier implements the type Verifier interface for the dilithium signature scheme.
type DilithiumVerifier struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey DilithiumPublicKey `codec:"k"`
}

// Verify follows dilithium algorithm to verify a signature.
func (d *DilithiumVerifier) Verify(message Hashable, sig ByteSignature) error {
	hs := Hash(hashRep(message))
	return d.VerifyBytes(hs[:], sig)
}

// VerifyBytes follows dilithium algorithm to verify a signature.
func (d *DilithiumVerifier) VerifyBytes(data []byte, sig ByteSignature) error {
	//func dil2Verify(public dil2PublicKey, data []byte, sig dil2Signature) bool {
	// &data[0] will make Go panic if msg is zero length
	cdata := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		cdata = (*C.uchar)(&data[0])
	}

	out := C.pqcrystals_dilithium2_ref_verify((*C.uchar)(&sig[0]), (C.size_t)(len(sig)), (*C.uchar)(cdata), C.size_t(len(data)), (*C.uchar)(&(d.PublicKey[0])))
	if out != 0 {
		return ErrBadSignature
	}
	return nil
}
