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

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errPQSigBlank              = errors.New("pq signature is blank")
	errPQSigEmpty              = errors.New("pq signature is empty")
	errPQSigAuthorizerMismatch = errors.New("pq signature authorizer mismatch")
)

// PQSig is a scheme-tagged transaction authorization proof. Its public key and
// signature are wire/decode-bounded by crypto.MaxPQPublicKeySize and
// crypto.MaxPQSignatureSize (the largest sizes over all supported PQSig schemes),
// which feed msgp allocation bounds and therefore PQSigMaxSize, SignedTxnMaxSize,
// and the SignedTxn wire bound.
type PQSig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Scheme    protocol.PQScheme    `codec:"sch"`
	Salt      basics.PQAddressSalt `codec:"slt"`
	PublicKey []byte               `codec:"pk,allocbound=crypto.MaxPQPublicKeySize"`
	Signature []byte               `codec:"sig,allocbound=crypto.MaxPQSignatureSize"`
}

// Blank returns true if the PQ authorization envelope is absent.
func (p PQSig) Blank() bool {
	var zeroScheme protocol.PQScheme
	var zeroSalt basics.PQAddressSalt

	return p.Scheme == zeroScheme &&
		p.Salt == zeroSalt &&
		len(p.PublicKey) == 0 &&
		len(p.Signature) == 0
}

// Equal compares two PQSig values.
func (p PQSig) Equal(other PQSig) bool {
	return p.Scheme == other.Scheme &&
		p.Salt == other.Salt &&
		bytes.Equal(p.PublicKey, other.PublicKey) &&
		bytes.Equal(p.Signature, other.Signature)
}

// Address returns the authorizer address for the PQSig.
func (p PQSig) Address() basics.Address {
	return basics.PQAddress(p.Scheme, p.Salt, p.PublicKey)
}

func (p PQSig) validateScheme(proto config.ConsensusParams) (crypto.PQVerifier, error) {
	if p.Blank() {
		return nil, errPQSigBlank
	}

	verifier, ok := crypto.LookupPQScheme(p.Scheme)
	if !ok {
		return nil, crypto.ErrPQSchemeNotSupported
	}

	if !proto.PQSchemeEnabled(p.Scheme) {
		return nil, crypto.ErrPQSchemeNotEnabled
	}

	return verifier, nil
}

// ValidateScheme validates that the PQSig carries a known scheme enabled under
// proto. It does not validate public-key-derived authorizers or signature bytes.
func (p PQSig) ValidateScheme(proto config.ConsensusParams) error {
	_, err := p.validateScheme(proto)
	return err
}

// validateEnvelope validates the stateless consensus-relevant PQ authorization
// envelope, excluding the signature bytes. It returns the scheme verifier so that
// Verify can dispatch the scheme-specific signature check without a second
// registry lookup.
func (p PQSig) validateEnvelope(proto config.ConsensusParams, authorizer basics.Address) (crypto.PQVerifier, error) {
	verifier, err := p.validateScheme(proto)
	if err != nil {
		return nil, err
	}

	pqAuthorizer := p.Address()
	if pqAuthorizer != authorizer {
		return nil, fmt.Errorf("%w: derived %s, expected %s", errPQSigAuthorizerMismatch, pqAuthorizer, authorizer)
	}

	return verifier, nil
}

// ValidateEnvelope validates the stateless consensus-relevant PQ authorization
// envelope: the proof is not blank, the carried scheme is known and enabled
// under proto, and the derived PQ address matches authorizer. It does NOT
// verify the public key or signature bytes (and applies no API admission
// policy); callers that require a real authorization proof must also require
// a non-empty Signature or call Verify.
func (p PQSig) ValidateEnvelope(proto config.ConsensusParams, authorizer basics.Address) error {
	_, err := p.validateEnvelope(proto, authorizer)
	return err
}

// validateForVerification validates the envelope and requires a non-empty signature.
func (p PQSig) validateForVerification(proto config.ConsensusParams, authorizer basics.Address) (crypto.PQVerifier, error) {
	verifier, err := p.validateEnvelope(proto, authorizer)
	if err != nil {
		return nil, err
	}
	if len(p.Signature) == 0 {
		return nil, errPQSigEmpty
	}
	return verifier, nil
}

// Verify validates that p is an authorization proof for
// message and authorizer under proto. It verifies that the carried scheme is
// supported by the consensus parameters; then it validates the authorization
// envelope and verifies the scheme-specific signature over message.
func (p PQSig) Verify(proto config.ConsensusParams, message crypto.Hashable, authorizer basics.Address) error {
	verifier, err := p.validateForVerification(proto, authorizer)
	if err != nil {
		return err
	}
	return verifier.Verify(message, p.PublicKey, p.Signature)
}

// BatchPrep validates p like Verify, then enqueues the signature into batch when
// the scheme is a crypto.PQBatchPreparer, or verifies it in place otherwise.
// Enqueued signatures are only checked when the batch is verified.
func (p PQSig) BatchPrep(proto config.ConsensusParams, message crypto.Hashable, authorizer basics.Address, batch crypto.BatchEnqueuer) error {
	verifier, err := p.validateForVerification(proto, authorizer)
	if err != nil {
		return err
	}
	if preparer, ok := verifier.(crypto.PQBatchPreparer); ok {
		return preparer.BatchPrep(message, p.PublicKey, p.Signature, batch)
	}
	return verifier.Verify(message, p.PublicKey, p.Signature)
}

// Batched reports whether p's scheme supports batch verification.
func (p PQSig) Batched() bool {
	verifier, ok := crypto.LookupPQScheme(p.Scheme)
	if !ok {
		return false
	}
	_, ok = verifier.(crypto.PQBatchPreparer)
	return ok
}
