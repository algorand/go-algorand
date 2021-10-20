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

// InvalidSinger is used for cases with the signer is invalid.
// this will return an error while using.
type InvalidSinger struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	EmptyData bool `codec:"e"`

}

// InvalidVerifier is used for cases with the verifier is invalid.
// this will return an error while using.
type InvalidVerifier struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`
	EmptyData bool `codec:"e"`
}

// NewInvalidSinger Generates invalid Signer.
func NewInvalidSinger() Signer {
	return &InvalidSinger{}
}

// Sign returns an empty signature
func (d *InvalidSinger) Sign(message Hashable) ByteSignature {
	return make([]byte, 0)
}

// SignBytes returns an empty signature
func (d *InvalidSinger) SignBytes(data []byte) ByteSignature {
	return make([]byte, 0)
}

// GetVerifyingKey Outputs an invalid verifying key.
func (p *InvalidSinger) GetVerifyingKey() *VerifyingKey {
	return &VerifyingKey{
		Type: maxAlgorithmType,

	}
}

var errInvalidVerifier = errors.New("could not verify signature. verifier is invalid")

// Verify returns an error to signal that the verifier is invalid
func (d *InvalidVerifier) Verify(message Hashable, sig ByteSignature) error {
	return errInvalidVerifier
}

// VerifyBytes returns an error to signal that the verifier is invalid
func (d *InvalidVerifier) VerifyBytes(data []byte, sig ByteSignature) error {
	return errInvalidVerifier
}
