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

import (
	"errors"
)

// invalidSinger is used for cases with the signer is invalid.
// this will return an error while using.
type invalidSinger struct {
}

// invalidVerifier is used for cases with the verifier is invalid.
// this will return an error while using.
type invalidVerifier struct {
}

// NewInvalidSinger Generates invalid Signer.
func NewInvalidSinger() Signer {
	return &invalidSinger{}
}

// Sign returns an empty signature
func (d *invalidSinger) Sign(message Hashable) ByteSignature {
	return make([]byte, 0)
}

// SignBytes returns an empty signature
func (d *invalidSinger) SignBytes(data []byte) ByteSignature {
	return make([]byte, 0)
}

// GetVerifyingKey Outputs an invalid verifying key.
func (d *invalidSinger) GetVerifyingKey() *VerifyingKey {
	return &VerifyingKey{
		Type: maxAlgorithmType,
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
