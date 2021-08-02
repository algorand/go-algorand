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

package dillibs

//#include "randombytes.h"
// #cgo CFLAGS: -g -Wall
// #cgo darwin,amd64 CFLAGS: -I${SRCDIR}/dillibs
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libdilithium2_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libaes256ctr_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libdilithium2_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libdilithium2aes_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libdilithium3_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libdilithium3aes_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libdilithium5_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libdilithium5aes_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libfips202_ref.a
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/librndbytes.a
//#include <stdlib.h>
//#include "api.h"
import "C"

func init() {
	// Check sizes of structs
	_ = [C.pqcrystals_dilithium2_BYTES]byte(dil2Signature{})
	_ = [C.pqcrystals_dilithium2_PUBLICKEYBYTES]byte(dil2PublicKey{})
	_ = [C.pqcrystals_dilithium2_SECRETKEYBYTES]byte(dil2PrivateKey{})
}

// A Seed holds the entropy needed to generate cryptographic keys.
//type Seed ed25519Seed

/* Classical signatures */
type dil2Signature [2420]byte
type dil2PublicKey [1312]byte
type dil2PrivateKey [2528]byte

func dil2GenerateKeys() (public dil2PublicKey, secret dil2PrivateKey) {
	C.pqcrystals_dilithium2_ref_keypair((*C.uchar)(&public[0]), (*C.uchar)(&secret[0]))
	return
}

//
func dil2Sign(secret dil2PrivateKey, data []byte) (sig dil2Signature) {
	// &data[0] will make Go panic if msg is zero length
	d := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		d = (*C.uchar)(&data[0])
	}

	var smlen uint64
	C.pqcrystals_dilithium2_ref((*C.uchar)(&sig[0]), (*C.size_t)(&smlen), (*C.uchar)(d), (C.size_t)(len(data)), (*C.uchar)(&secret[0]))
	return
}

func dil2Verify(public dil2PublicKey, data []byte, sig dil2Signature) bool {
	// &data[0] will make Go panic if msg is zero length
	d := (*C.uchar)(C.NULL)
	if len(data) != 0 {
		d = (*C.uchar)(&data[0])
	}

	result := C.pqcrystals_dilithium2_ref_verify((*C.uchar)(&sig[0]), (C.size_t)(len(sig)), (*C.uchar)(d), C.size_t(len(data)), (*C.uchar)(&public[0]))
	return result == 0
}
