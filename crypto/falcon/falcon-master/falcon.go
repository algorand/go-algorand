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

package cfalcon

// NOTE: cgo go code couldn't compile with the flags: -Wmissing-prototypes and -Wno-unused-paramete

//#cgo CFLAGS:  -Wall -Wextra -Wpedantic -Wredundant-decls -Wshadow -Wvla -Wpointer-arith -Wno-unused-parameter -Wno-overlength-strings  -O3 -fomit-frame-pointer
//#include "deterministic.h"
import "C"
import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// Exporting to be used when attempting to wrap and use this package.
const (
	// SigSize is the size of a falcon signature
	SigSize = C.FALCON_DET1024_SIG_SIZE
	// PublicKeySize is the size of a falcon public key
	PublicKeySize = C.FALCON_DET1024_PUBKEY_SIZE
	// PrivateKeySize is the size of a falcon private key
	PrivateKeySize = C.FALCON_DET1024_PRIVKEY_SIZE
)

const (
	errKeygenFail = "falcon keygen failed error is: %d"
	errSignFail   = "falcon sign failed error is: %d"
	errVerifyFail = "falcon verify failed error is: %d"
)

// ErrBadFalconSignatureTooSmall indicates signature is smaller than expected.
var ErrBadFalconSignatureTooSmall = errors.New("signature too small")

type (
	// FalconSignature is the signature used by the falcon scheme
	FalconSignature [SigSize]byte
	// FalconPublicKey is the public key used by the falcon scheme
	FalconPublicKey [PublicKeySize]byte
	// FalconPrivateKey is the private key used by the falcon scheme
	FalconPrivateKey [PrivateKeySize]byte
)

// GenerateKey Generates a falcon private and public key using a seed.
func GenerateKey(seed []byte) (FalconPrivateKey, FalconPublicKey, error) {
	pk := FalconPublicKey{}
	sk := FalconPrivateKey{}

	seedLen := len(seed)
	seedData := (*C.uchar)(C.NULL)
	if seedLen != 0 {
		seedData = (*C.uchar)(&seed[0])
	}

	retCode := C.falcon_det1024_keygen_with_seed(unsafe.Pointer(&(sk[0])), unsafe.Pointer(&(pk[0])), unsafe.Pointer(seedData), (C.size_t)(seedLen))
	if retCode != 0 {
		return sk, pk, fmt.Errorf(errKeygenFail, int(retCode))
	}
	runtime.KeepAlive(seedData)
	return sk, pk, nil
}

// SignBytes receives bytes and signs them.
func (sk *FalconPrivateKey) SignBytes(data []byte) ([]byte, error) {
	dataLen := len(data)
	cdata := (*C.uchar)(C.NULL)
	if dataLen != 0 {
		cdata = (*C.uchar)(&data[0])
	}
	sig := FalconSignature{}

	retCode := C.falcon_det1024_sign(unsafe.Pointer(&sig[0]), unsafe.Pointer(&(*sk)), unsafe.Pointer(cdata), (C.size_t)(dataLen))
	if retCode != 0 {
		return []byte{}, fmt.Errorf(errSignFail, int(retCode))
	}
	runtime.KeepAlive(data)
	return sig[:], nil
}

// VerifyBytes verifies the signature over a messages using a public key.
func (v *FalconPublicKey) VerifyBytes(data []byte, sig []byte) error {
	sigLen := len(sig)
	if sigLen != SigSize {
		return ErrBadFalconSignatureTooSmall
	}

	dataLen := len(data)
	cdata := (*C.uchar)(C.NULL)
	if dataLen != 0 {
		cdata = (*C.uchar)(&data[0])
	}

	retCode := C.falcon_det1024_verify(unsafe.Pointer(&sig[0]), unsafe.Pointer(&(*v)), unsafe.Pointer(cdata), C.size_t(dataLen))
	if retCode != 0 {
		return fmt.Errorf(errVerifyFail, int(retCode))
	}
	runtime.KeepAlive(data)
	runtime.KeepAlive(sig)
	return nil
}
