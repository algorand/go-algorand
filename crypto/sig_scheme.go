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
)

// ErrSigInvalid is returned, wrapped with the scheme name, when a signature
// or the public key it is checked against is invalid.
var ErrSigInvalid = errors.New("invalid signature")

// SigSchemeVerifier verifies a signature for one account authorization scheme. The
// implementations here know only how to check bytes; which schemes exist, when
// they are enabled, what they cost, and how large their keys and signatures may
// be on the wire is decided by transactions.HashedKeySig.
type SigSchemeVerifier interface {
	Verify(message Hashable, publicKey, signature []byte) error
}

// SigSchemeBatchPreparer is implemented by schemes verified through the batch
// verifier (Ed25519 only).
type SigSchemeBatchPreparer interface {
	BatchPrep(message Hashable, publicKey, signature []byte, batch BatchEnqueuer) error
}

// Falcon1024SchemeVerifier verifies Falcon-1024 signatures.
type Falcon1024SchemeVerifier struct{}

// Verify implements SigSchemeVerifier.
func (Falcon1024SchemeVerifier) Verify(message Hashable, publicKey, signature []byte) error {
	return VerifyFalcon1024(message, publicKey, signature)
}

// Falcon512SchemeVerifier verifies Falcon-512 signatures.
type Falcon512SchemeVerifier struct{}

// Verify implements SigSchemeVerifier.
func (Falcon512SchemeVerifier) Verify(message Hashable, publicKey, signature []byte) error {
	return VerifyFalcon512(message, publicKey, signature)
}

// Ed25519SchemeVerifier verifies classical Ed25519 signatures carried in a HashedKeySig.
type Ed25519SchemeVerifier struct{}

// Verify implements SigSchemeVerifier.
func (Ed25519SchemeVerifier) Verify(message Hashable, publicKey, signature []byte) error {
	verifier, sig, err := parseEd25519Signature(publicKey, signature)
	if err != nil {
		return err
	}
	if !verifier.Verify(message, sig) {
		return fmt.Errorf("ed25519 %w", ErrSigInvalid)
	}
	return nil
}

// BatchPrep implements SigSchemeBatchPreparer.
func (Ed25519SchemeVerifier) BatchPrep(message Hashable, publicKey, signature []byte, batch BatchEnqueuer) error {
	verifier, sig, err := parseEd25519Signature(publicKey, signature)
	if err != nil {
		return err
	}
	batch.EnqueueSignature(verifier, message, sig)
	return nil
}

func parseEd25519Signature(publicKey, signature []byte) (SignatureVerifier, Signature, error) {
	if len(publicKey) != len(PublicKey{}) {
		return SignatureVerifier{}, Signature{}, fmt.Errorf("ed25519 %w: public key size %d, want %d", ErrSigInvalid, len(publicKey), len(PublicKey{}))
	}
	if len(signature) != len(Signature{}) {
		return SignatureVerifier{}, Signature{}, fmt.Errorf("ed25519 %w: signature size %d, want %d", ErrSigInvalid, len(signature), len(Signature{}))
	}
	return SignatureVerifier(publicKey), Signature(signature), nil
}
