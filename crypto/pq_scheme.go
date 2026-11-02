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

// PQVerifier verifies a signature for one account authorization scheme. The
// implementations here know only how to check bytes; which schemes exist, when
// they are enabled, what they cost, and how large their keys and signatures may
// be on the wire is decided by transactions.PQSig.
type PQVerifier interface {
	Verify(message Hashable, publicKey, signature []byte) error
}

// PQBatchPreparer is implemented by schemes verified through the batch
// verifier (Ed25519 only).
type PQBatchPreparer interface {
	BatchPrep(message Hashable, publicKey, signature []byte, batch BatchEnqueuer) error
}

// PQFalcon1024 verifies Falcon-1024 signatures.
type PQFalcon1024 struct{}

// Verify implements PQVerifier.
func (PQFalcon1024) Verify(message Hashable, publicKey, signature []byte) error {
	return VerifyFalcon1024(message, publicKey, signature)
}

// PQFalcon512 verifies Falcon-512 signatures.
type PQFalcon512 struct{}

// Verify implements PQVerifier.
func (PQFalcon512) Verify(message Hashable, publicKey, signature []byte) error {
	return VerifyFalcon512(message, publicKey, signature)
}

// PQEd25519 verifies classical Ed25519 signatures carried in a PQSig.
type PQEd25519 struct{}

// Verify implements PQVerifier.
func (PQEd25519) Verify(message Hashable, publicKey, signature []byte) error {
	verifier, sig, err := parseEd25519Signature(publicKey, signature)
	if err != nil {
		return err
	}
	if !verifier.Verify(message, sig) {
		return fmt.Errorf("ed25519 %w", ErrSigInvalid)
	}
	return nil
}

// BatchPrep implements PQBatchPreparer.
func (PQEd25519) BatchPrep(message Hashable, publicKey, signature []byte, batch BatchEnqueuer) error {
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
