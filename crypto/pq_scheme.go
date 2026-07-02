// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

	"github.com/algorand/go-algorand/protocol"
)

var (
	// ErrPQSchemeNotSupported is returned when a PQScheme is not supported.
	ErrPQSchemeNotSupported = errors.New("pq signature scheme not supported")

	// ErrPQSchemeNotEnabled is returned when a PQScheme is not enabled under the protocol.
	ErrPQSchemeNotEnabled = errors.New("pq signature scheme not enabled")
)

// PQVerifier is the cryptographic behavior of one post-quantum signature
// scheme: its key/signature sizes and signature verification. Scheme identity
// is the protocol.PQScheme tag; fee policy lives in config (see
// config.ConsensusParams.PQSchemeFeeContribution).
type PQVerifier interface {
	PublicKeySize() uint64
	SignatureSize() uint64
	Verify(message Hashable, publicKey, signature []byte) error
}

// LookupPQScheme returns the verifier for a PQ scheme tag.
//
// To add a scheme:
//   - add its protocol.PQScheme tag,
//   - add a case here returning its PQVerifier,
//   - add its config.ConsensusParams.PQSchemeEnabled case and PQSchemeFeeContribution,
//   - add the signing/private-key ops in cmd/algokey,
//   - if it changes the wire bounds, bump data/transactions.PQMaxPublicKeySize /
//     PQMaxSignatureSize and regenerate msgp code.
func LookupPQScheme(s protocol.PQScheme) (PQVerifier, bool) {
	switch s {
	case protocol.PQSchemeFalcon1024:
		return falcon1024{}, true
	// case protocol.PQSchemeFalcon512:
	// 	return falcon512{}, true
	}
	return nil, false
}

// falcon1024 is the PQVerifier for the Falcon-1024 (f1) scheme.
type falcon1024 struct{}

func (falcon1024) PublicKeySize() uint64 { return FalconPublicKeySize }
func (falcon1024) SignatureSize() uint64 { return FalconMaxSignatureSize }
func (falcon1024) Verify(message Hashable, publicKey, signature []byte) error {
	return VerifyFalcon1024(message, publicKey, signature)
}
