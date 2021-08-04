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

package dilibs

//#cgo CFLAGS: -O3
//#include "api.h"
import "C"
import "errors"

type (
	// Dil2Signature is the signature used by the dilithium scheme
	Dil2Signature [2420]byte
	// Dil2PublicKey is the public key used by the dilithium scheme
	Dil2PublicKey [1312]byte
	// Dil2PrivateKey is the private key used by the dilithium scheme
	Dil2PrivateKey [2528]byte
)

func init() {
	// Check sizes of structs
	_ = [C.pqcrystals_dilithium2_BYTES]byte(Dil2Signature{})
	_ = [C.pqcrystals_dilithium2_PUBLICKEYBYTES]byte(Dil2PublicKey{})
	_ = [C.pqcrystals_dilithium2_SECRETKEYBYTES]byte(Dil2PrivateKey{})
}

// DilithiumKeyPair is the implementation of DilithiumKeyPair for the Dilithium signature scheme.
type DilithiumKeyPair struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SecretKey Dil2PrivateKey `codec:"sk"`
	PublicKey Dil2PublicKey  `codec:"pk"`
}

// NewKeys Generates a dilithium DilithiumKeyPair.
func NewKeys() *DilithiumKeyPair {
	pk := Dil2PublicKey{}
	sk := Dil2PrivateKey{}
	C.pqcrystals_dilithium2_ref_keypair((*C.uchar)(&(pk[0])), (*C.uchar)(&(sk[0])))
	return &DilithiumKeyPair{
		SecretKey: sk,
		PublicKey: pk,
	}
}

// SignBytes receives bytes and signs over them.
// the size of the signature should conform with dil2Signature.
func (s *DilithiumKeyPair) SignBytes(data []byte) []byte {
	cdata := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		cdata = (*C.uchar)(&data[0])
	}
	var sig Dil2Signature
	var smlen uint64
	C.pqcrystals_dilithium2_ref((*C.uchar)(&sig[0]), (*C.size_t)(&smlen), (*C.uchar)(cdata), (C.size_t)(len(data)), (*C.uchar)(&(s.SecretKey[0])))
	return sig[:]
}

// ErrBadDilithiumSignature indicates signature isn't valid.
var ErrBadDilithiumSignature = errors.New("bad signature")

// VerifyBytes follows dilithium algorithm to verify a signature.
func (v *Dil2PublicKey) VerifyBytes(data []byte, sig []byte) error {
	cdata := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		cdata = (*C.uchar)(&data[0])
	}

	out := C.pqcrystals_dilithium2_ref_verify((*C.uchar)(&sig[0]), (C.size_t)(len(sig)), (*C.uchar)(cdata), C.size_t(len(data)), (*C.uchar)(&(v[0])))
	if out != 0 {
		return ErrBadDilithiumSignature
	}
	return nil
}
