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

package transactions

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

var (
	// Scheme-independent errors
	errPQSigBlank              = errors.New("pq signature is blank")
	errPQSigEmpty              = errors.New("pq signature is empty")
	errPQSignatureSize         = errors.New("pq signature has invalid size")
	errPQSigAuthorizerMismatch = errors.New("pq signature authorizer mismatch")

	// Scheme-specific errors
	errFalcon1024SigInvalid = errors.New("invalid deterministic falcon-1024 signature")
)

const (
	// PQMaxPublicKeySize bounds PQ public keys before scheme dispatch.
	PQMaxPublicKeySize = crypto.FalconPublicKeySize

	// PQMaxSignatureSize bounds PQ signatures before scheme dispatch.
	PQMaxSignatureSize = crypto.FalconMaxSignatureSize
)

// PQSig is a post-quantum transaction authorization proof.
type PQSig struct {
	_struct struct{} `codec:",omitempty"`

	Scheme    basics.PQScheme      `codec:"sch"`
	Salt      basics.PQAddressSalt `codec:"slt"`
	PublicKey []byte               `codec:"pk,allocbound=PQMaxPublicKeySize"`
	Signature []byte               `codec:"sig,allocbound=PQMaxSignatureSize"`
}

// Blank returns true if the PQ authorization envelope is absent.
func (p *PQSig) Blank() bool {
	if p == nil {
		return true
	}

	var zeroScheme basics.PQScheme
	var zeroSalt basics.PQAddressSalt

	return p.Scheme == zeroScheme &&
		p.Salt == zeroSalt &&
		len(p.PublicKey) == 0 &&
		len(p.Signature) == 0
}

// Equal compares two PQSig values, treating nil and blank proofs as equivalent.
func (p *PQSig) Equal(other *PQSig) bool {
	if p == nil || other == nil {
		return p.Blank() && other.Blank()
	}

	return p.Scheme == other.Scheme &&
		p.Salt == other.Salt &&
		bytes.Equal(p.PublicKey, other.PublicKey) &&
		bytes.Equal(p.Signature, other.Signature)
}

// AuthorizerAddress returns the authorizer address for the PQSig.
func (p *PQSig) AuthorizerAddress() basics.Address {
	return basics.PQAddress(p.Scheme, p.Salt, p.PublicKey)
}

// Falcon1024PublicKey returns the Falcon-1024 public key carried by PQSig.
func (p *PQSig) Falcon1024PublicKey() (crypto.FalconPublicKey, error) {
	if p.Scheme != basics.PQSchemeFalcon1024() {
		return crypto.FalconPublicKey{}, fmt.Errorf("%w: got %s, want %s", basics.ErrPQSchemeNotSupported, p.Scheme, basics.PQSchemeFalcon1024())
	}

	err := p.Scheme.ValidatePublicKey(p.PublicKey)
	if err != nil {
		return crypto.FalconPublicKey{}, err
	}

	var pk crypto.FalconPublicKey
	copy(pk[:], p.PublicKey)
	return pk, nil
}

// Falcon1024Signature returns the Deterministic Falcon-1024 signature carried by PQSig.
func (p *PQSig) Falcon1024Signature() (crypto.FalconSignature, error) {
	if p.Scheme != basics.PQSchemeFalcon1024() {
		return crypto.FalconSignature{}, fmt.Errorf("%w: got %s, want %s", basics.ErrPQSchemeNotSupported, p.Scheme, basics.PQSchemeFalcon1024())
	}

	if len(p.Signature) == 0 || len(p.Signature) > crypto.FalconMaxSignatureSize {
		return nil, fmt.Errorf("%w: got %d, want 1..%d", errPQSignatureSize, len(p.Signature), crypto.FalconMaxSignatureSize)
	}
	return p.Signature, nil
}

// Verify validates that p is a post-quantum authorization proof for txn and
// authorizer. It verifies that the carried scheme is supported; then it validates
// the authorizer address from the carried scheme, address salt, and public key and
// verifies the scheme-specific signature over the unsigned transaction.
func (p *PQSig) Verify(txn Transaction, authorizer basics.Address) error {
	// Scheme-independent verification
	if p.Blank() {
		return errPQSigBlank
	}

	if len(p.Signature) == 0 {
		return errPQSigEmpty
	}

	pqAuthorizer := p.AuthorizerAddress()
	if pqAuthorizer != authorizer {
		return fmt.Errorf("%w: derived %s, expected %s", errPQSigAuthorizerMismatch, pqAuthorizer, authorizer)
	}

	// Scheme-specific verification
	switch p.Scheme {
	case basics.PQSchemeFalcon1024():
		pk, err := p.Falcon1024PublicKey()
		if err != nil {
			return err
		}

		sig, err := p.Falcon1024Signature()
		if err != nil {
			return err
		}

		fv := crypto.FalconVerifier{PublicKey: pk}
		if err := fv.Verify(txn, sig); err != nil {
			return fmt.Errorf("%w: %w", errFalcon1024SigInvalid, err)
		}
		return nil

	default:
		// Defensive: this should only be reachable if IsSupported is updated
		// without adding the corresponding verification implementation here.
		return basics.ErrPQSchemeNotSupported
	}
}
