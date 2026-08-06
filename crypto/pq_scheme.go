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

// PQVerifier verifies a post-quantum signature for one scheme.
type PQVerifier interface {
	Verify(message Hashable, publicKey, signature []byte) error
}

// MaxPQPublicKeySize and MaxPQSignatureSize are the largest public-key and
// signature sizes over all supported PQ schemes; they are the PQ wire/decode
// bounds (used for msgp allocbounds). Adding a scheme with a larger key or
// signature means growing these; TestPQBoundsCoverFalcon1024 guards against
// undersizing the current schemes.
const (
	MaxPQPublicKeySize = FalconPublicKeySize
	MaxPQSignatureSize = FalconMaxSignatureSize
)

// LookupPQScheme returns the verifier for a PQ scheme tag.
//
// To add a scheme:
//   - add its protocol.PQScheme tag,
//   - add a case here returning its PQVerifier,
//   - add its config.ConsensusParams.PQSchemeEnabled case and PQSchemeFeeContribution,
//   - add the signing/private-key ops in cmd/algokey,
//   - grow MaxPQPublicKeySize/MaxPQSignatureSize if its public key or signature is larger.
func LookupPQScheme(s protocol.PQScheme) (PQVerifier, bool) {
	switch s {
	case protocol.PQSchemeFalcon1024:
		return falcon1024{}, true
		// case protocol.PQSchemeFalcon512:
		// 	return falcon512{}, true
	}
	return nil, false
}

// falcon1024 is the Falcon-1024 (f1) scheme.
type falcon1024 struct{}

func (falcon1024) Verify(message Hashable, publicKey, signature []byte) error {
	return VerifyFalcon1024(message, publicKey, signature)
}
