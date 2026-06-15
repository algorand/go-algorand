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

// PQMaxPublicKeySize and PQMaxSignatureSize are explicit wire/decode bounds
// for PQ public keys and signatures before scheme dispatch. They feed msgp
// allocation bounds and therefore PQSigMaxSize, SignedTxnMaxSize, and the
// SignedTxn wire bound. Enabling a larger PQ scheme requires intentionally
// bumping these constants and regenerating msgp code.
const (
	// PQMaxPublicKeySize bounds PQ public keys before scheme dispatch.
	PQMaxPublicKeySize = crypto.FalconPublicKeySize

	// PQMaxSignatureSize bounds PQ signatures before scheme dispatch.
	PQMaxSignatureSize = crypto.FalconMaxSignatureSize
)

// PQSig is a post-quantum transaction authorization proof.
type PQSig struct {
	_struct struct{} `codec:",omitempty"`

	Scheme    protocol.PQScheme    `codec:"sch"`
	Salt      basics.PQAddressSalt `codec:"slt"`
	PublicKey []byte               `codec:"pk,allocbound=PQMaxPublicKeySize"`
	Signature []byte               `codec:"sig,allocbound=PQMaxSignatureSize"`
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

// AuthorizerAddress returns the authorizer address for the PQSig.
func (p PQSig) AuthorizerAddress() basics.Address {
	return basics.PQAddress(p.Scheme, p.Salt, p.PublicKey)
}

// validateEnvelope validates the stateless consensus-relevant PQ authorization
// envelope, excluding the signature bytes. It returns the scheme spec so that
// Verify can dispatch the scheme-specific signature check without a second
// registry lookup.
func (p PQSig) validateEnvelope(proto config.ConsensusParams, authorizer basics.Address) (basics.PQSchemeSpec, error) {
	if p.Blank() {
		return basics.PQSchemeSpec{}, errPQSigBlank
	}

	scheme, ok := basics.LookupPQScheme(p.Scheme)
	if !ok {
		return basics.PQSchemeSpec{}, basics.ErrPQSchemeNotSupported
	}

	if !proto.PQSchemeEnabled(p.Scheme) {
		return basics.PQSchemeSpec{}, basics.ErrPQSchemeNotEnabled
	}

	if err := scheme.ValidatePublicKey(p.PublicKey); err != nil {
		return basics.PQSchemeSpec{}, err
	}

	pqAuthorizer := p.AuthorizerAddress()
	if pqAuthorizer != authorizer {
		return basics.PQSchemeSpec{}, fmt.Errorf("%w: derived %s, expected %s", errPQSigAuthorizerMismatch, pqAuthorizer, authorizer)
	}

	return scheme, nil
}

// ValidateEnvelope validates the stateless consensus-relevant PQ authorization
// envelope: the proof is not blank, the carried scheme is known and enabled
// under proto, the public key is well-formed for that scheme, and the derived
// PQ address matches authorizer. It does NOT verify the signature bytes (and
// applies no API admission policy); callers that require a real authorization
// proof must also require a non-empty Signature or call Verify.
func (p PQSig) ValidateEnvelope(proto config.ConsensusParams, authorizer basics.Address) error {
	_, err := p.validateEnvelope(proto, authorizer)
	return err
}

// Verify validates that p is a post-quantum authorization proof for txn and
// authorizer under proto. It verifies that the carried scheme is supported by
// the consensus parameters; then it validates the authorization envelope and
// verifies the scheme-specific signature over the unsigned transaction.
func (p PQSig) Verify(proto config.ConsensusParams, txn Transaction, authorizer basics.Address) error {
	scheme, err := p.validateEnvelope(proto, authorizer)
	if err != nil {
		return err
	}

	if len(p.Signature) == 0 {
		return errPQSigEmpty
	}

	return scheme.Verify(txn, p.PublicKey, p.Signature)
}
