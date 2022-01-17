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

import (
	"errors"
)

// invalidSigner is used for cases with the signer is invalid.
// this will return an error while using.
type invalidSigner struct {
}

// invalidVerifier is used for cases with the verifier is invalid.
// this will return an error while using.
type invalidVerifier struct {
}

// NewInvalidSigner Generates invalid Signer.
func NewInvalidSigner() Signer {
	return &invalidSigner{}
}

// Sign returns an empty signature
func (d *invalidSigner) Sign(message Hashable) (ByteSignature, error) {
	return ByteSignature{}, errInvalidVerifier
}

// SignBytes returns an empty signature
func (d *invalidSigner) SignBytes(data []byte) (ByteSignature, error) {
	return ByteSignature{}, errInvalidVerifier
}

// GetVerifyingKey Outputs an invalid verifying key.
func (d *invalidSigner) GetVerifyingKey() *GenericVerifyingKey {
	return &GenericVerifyingKey{
		Type: MaxAlgorithmType,
	}
}

var errInvalidVerifier = errors.New("could not verify signature. verifier is invalid")

// Verify returns an error to signal that the verifier is invalid
func (d *invalidVerifier) Verify(message Hashable, sig ByteSignature) error {
	return errInvalidVerifier
}

// VerifyBytes returns an error to signal that the verifier is invalid
func (d *invalidVerifier) VerifyBytes(data []byte, sig ByteSignature) error {
	return errInvalidVerifier
}

// GetFixedLengthHashableRepresentation returns an empty slice to signal that the verifier is invalid.
func (d *invalidVerifier) GetFixedLengthHashableRepresentation() []byte {
	return []byte{}
}

// GetSignatureFixedLengthHashableRepresentation returns a serialized version of the signature
func (d *invalidVerifier) GetSignatureFixedLengthHashableRepresentation(signature ByteSignature) ([]byte, error) {
	return []byte{}, errInvalidVerifier
}
