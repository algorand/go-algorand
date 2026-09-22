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
	"fmt"

	"github.com/algorand/go-algorand/protocol"
)

var (
	// ErrPQSchemeNotSupported is returned when a PQScheme is not supported.
	ErrPQSchemeNotSupported = errors.New("pq signature scheme not supported")

	// ErrPQSchemeNotEnabled is returned when a PQScheme is not enabled under the protocol.
	ErrPQSchemeNotEnabled = errors.New("pq signature scheme not enabled")

	// ErrPQEd25519SigInvalid is returned when Ed25519 signature verification fails.
	ErrPQEd25519SigInvalid = errors.New("invalid ed25519 signature")
)

// PQVerifier verifies a signature for one account authorization scheme.
type PQVerifier interface {
	Verify(message Hashable, publicKey, signature []byte) error
}

// PQBatchPreparer is implemented by schemes verified through the batch
// verifier (Ed25519 only).
type PQBatchPreparer interface {
	BatchPrep(message Hashable, publicKey, signature []byte, batch BatchEnqueuer) error
}

// MaxPQPublicKeySize and MaxPQSignatureSize are the largest public-key and
// signature sizes over all supported PQ schemes; they are the PQ wire/decode
// bounds (used for msgp allocbounds). Adding a scheme with a larger key or
// signature means growing these; TestPQBoundsCoverSchemes guards against
// undersizing the current schemes.
const (
	MaxPQPublicKeySize = max(Falcon1024PublicKeySize, Falcon512PublicKeySize, len(PublicKey{}))
	MaxPQSignatureSize = max(Falcon1024MaxSignatureSize, Falcon512MaxSignatureSize, len(Signature{}))
)

// LookupPQScheme returns the verifier for a PQ scheme tag.
//
// To add a scheme:
//   - add its protocol.PQScheme tag,
//   - add a case here returning its PQVerifier,
//   - add its config.ConsensusParams.PQSchemeEnabled case and PQSchemeFeeContribution,
//   - add the signing/private-key ops in cmd/algokey,
//   - add it to basics_testing.PQTestSchemes,
//   - implement PQBatchPreparer if the scheme is batch-verified,
//   - grow MaxPQPublicKeySize/MaxPQSignatureSize if its public key or signature is larger.
func LookupPQScheme(s protocol.PQScheme) (PQVerifier, bool) {
	switch s {
	case protocol.PQSchemeFalcon1024:
		return falcon1024{}, true
	case protocol.PQSchemeFalcon512:
		return falcon512{}, true
	case protocol.PQSchemeEd25519:
		return ed25519Scheme{}, true
	}
	return nil, false
}

// falcon1024 is the Falcon-1024 (f1) scheme.
type falcon1024 struct{}

func (falcon1024) Verify(message Hashable, publicKey, signature []byte) error {
	return VerifyFalcon1024(message, publicKey, signature)
}

// falcon512 is the Falcon-512 (f5) scheme.
type falcon512 struct{}

func (falcon512) Verify(message Hashable, publicKey, signature []byte) error {
	return VerifyFalcon512(message, publicKey, signature)
}

// ed25519Scheme is the classical Ed25519 (ed) scheme.
type ed25519Scheme struct{}

func (ed25519Scheme) Verify(message Hashable, publicKey, signature []byte) error {
	verifier, sig, err := parseEd25519Signature(publicKey, signature)
	if err != nil {
		return err
	}
	if !verifier.Verify(message, sig) {
		return ErrPQEd25519SigInvalid
	}
	return nil
}

func (ed25519Scheme) BatchPrep(message Hashable, publicKey, signature []byte, batch BatchEnqueuer) error {
	verifier, sig, err := parseEd25519Signature(publicKey, signature)
	if err != nil {
		return err
	}
	batch.EnqueueSignature(verifier, message, sig)
	return nil
}

func parseEd25519Signature(publicKey, signature []byte) (SignatureVerifier, Signature, error) {
	if len(publicKey) != len(PublicKey{}) {
		return SignatureVerifier{}, Signature{}, fmt.Errorf("%w: public key size %d, want %d", ErrPQEd25519SigInvalid, len(publicKey), len(PublicKey{}))
	}
	if len(signature) != len(Signature{}) {
		return SignatureVerifier{}, Signature{}, fmt.Errorf("%w: signature size %d, want %d", ErrPQEd25519SigInvalid, len(signature), len(Signature{}))
	}
	return SignatureVerifier(publicKey), Signature(signature), nil
}
