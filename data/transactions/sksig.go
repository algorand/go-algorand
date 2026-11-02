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
	errSaltedKeySigBlank              = errors.New("salted-key signature is blank")
	errSaltedKeySigEmpty              = errors.New("salted-key signature is empty")
	errSaltedKeySigAuthorizerMismatch = errors.New("salted-key signature authorizer mismatch")
	errSaltedKeySigTooLarge           = errors.New("salted-key signature field too large for scheme")

	// errLogicSigNotEvaluated is returned when an ls-scheme SaltedKeySig reaches
	// signature verification. Reaching it means a caller took the generic salted-key
	// signature verification path for a logic signature instead of evaluating its program.
	errLogicSigNotEvaluated = errors.New("logic signature must be verified by evaluating its program, not by checking signature bytes")
)

// SaltedKeySig is a scheme-tagged transaction authorization proof. Its public key and
// signature are wire/decode-bounded by maxSigSchemePublicKeySize and
// maxSigSchemeSignatureSize (the largest sizes over all schemes in sigSchemes), which
// feed msgp allocation bounds and therefore SaltedKeySigMaxSize, SignedTxnMaxSize, and the SignedTxn wire bound.
type SaltedKeySig struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Scheme    protocol.SigScheme `codec:"sch"`
	Salt      basics.AddressSalt `codec:"slt"`
	PublicKey []byte             `codec:"pk,allocbound=maxSigSchemePublicKeySize()"`
	Signature []byte             `codec:"sig,allocbound=maxSigSchemeSignatureSize()"`
}

// Blank returns true if the salted-key signature envelope is absent.
func (p SaltedKeySig) Blank() bool {
	var zeroScheme protocol.SigScheme
	var zeroSalt basics.AddressSalt

	return p.Scheme == zeroScheme &&
		p.Salt == zeroSalt &&
		len(p.PublicKey) == 0 &&
		len(p.Signature) == 0
}

// Equal compares two SaltedKeySig values.
func (p SaltedKeySig) Equal(other SaltedKeySig) bool {
	return p.Scheme == other.Scheme &&
		p.Salt == other.Salt &&
		bytes.Equal(p.PublicKey, other.PublicKey) &&
		bytes.Equal(p.Signature, other.Signature)
}

// Address returns the authorizer address for the SaltedKeySig.
func (p SaltedKeySig) Address() basics.Address {
	return basics.SaltedAddress(p.Scheme, p.Salt, p.PublicKey)
}

// IsLogicSig reports whether p authorizes by evaluating a program rather than
// by verifying signature bytes. Callers that verify a SaltedKeySig must ask this
// first: the ls scheme has no SigSchemeVerifier, so Verify and BatchPrep refuse it.
func (p SaltedKeySig) IsLogicSig() bool {
	return p.Scheme == protocol.SigSchemeLogicSig
}

// Lsig returns the logic signature an ls-scheme SaltedKeySig carries: the program
// stands in for the public key, and its encoded arguments for the signature.
// Returning a LogicSig lets a program authorizing from a SaltedKeySig be measured and
// evaluated exactly like one in SignedTxn.Lsig.
func (p SaltedKeySig) Lsig() (LogicSig, error) {
	args, err := DecodeLogicSigArgs(p.Signature)
	if err != nil {
		return LogicSig{}, err
	}
	return LogicSig{Logic: p.PublicKey, Args: args}, nil
}

func (p SaltedKeySig) validateScheme(proto config.ConsensusParams) (sigScheme, error) {
	if p.Blank() {
		return sigScheme{}, errSaltedKeySigBlank
	}

	scheme, ok := sigSchemes[p.Scheme]
	if !ok {
		return sigScheme{}, ErrSigSchemeNotSupported
	}

	if !scheme.enabled(proto) {
		return sigScheme{}, ErrSigSchemeNotEnabled
	}

	return scheme, nil
}

// ValidateScheme validates that the SaltedKeySig carries a known scheme enabled under
// proto. It does not validate public-key-derived authorizers or signature bytes.
func (p SaltedKeySig) ValidateScheme(proto config.ConsensusParams) error {
	_, err := p.validateScheme(proto)
	return err
}

// validateEnvelope validates the stateless consensus-relevant salted-key signature
// envelope, excluding the signature bytes. It returns the scheme verifier so that
// Verify can dispatch the scheme-specific signature check without a second
// registry lookup.
func (p SaltedKeySig) validateEnvelope(proto config.ConsensusParams, authorizer basics.Address) (crypto.SigSchemeVerifier, error) {
	scheme, err := p.validateScheme(proto)
	if err != nil {
		return nil, err
	}

	// The wire bounds are the largest over all schemes, so a smaller scheme's
	// fields must be held to its own limits here.
	if pkMax := scheme.maxPublicKeySize(); len(p.PublicKey) > pkMax {
		return nil, fmt.Errorf("%w: public key size %d, max %d", errSaltedKeySigTooLarge, len(p.PublicKey), pkMax)
	}
	if sigMax := scheme.maxSignatureSize(); len(p.Signature) > sigMax {
		return nil, fmt.Errorf("%w: signature size %d, max %d", errSaltedKeySigTooLarge, len(p.Signature), sigMax)
	}

	derivedAuthorizer := p.Address()
	if derivedAuthorizer != authorizer {
		return nil, fmt.Errorf("%w: derived %s, expected %s", errSaltedKeySigAuthorizerMismatch, derivedAuthorizer, authorizer)
	}

	return scheme.verifier, nil
}

// ValidateEnvelope validates the stateless consensus-relevant salted-key signature
// envelope: the proof is not blank, the carried scheme is known and enabled
// under proto, its public key and signature fit the scheme's size limits, and
// the derived salted address matches authorizer. It does NOT
// verify the public key or signature bytes (and applies no API admission
// policy); callers that require a real authorization proof must also require
// a non-empty Signature or call Verify.
func (p SaltedKeySig) ValidateEnvelope(proto config.ConsensusParams, authorizer basics.Address) error {
	_, err := p.validateEnvelope(proto, authorizer)
	return err
}

// validateForVerification validates the envelope and requires a non-empty
// signature from a scheme that is verified by checking signature bytes.
func (p SaltedKeySig) validateForVerification(proto config.ConsensusParams, authorizer basics.Address) (crypto.SigSchemeVerifier, error) {
	verifier, err := p.validateEnvelope(proto, authorizer)
	if err != nil {
		return nil, err
	}
	if verifier == nil {
		return nil, errLogicSigNotEvaluated
	}
	if len(p.Signature) == 0 {
		return nil, errSaltedKeySigEmpty
	}
	return verifier, nil
}

// Verify validates that p is an authorization proof for
// message and authorizer under proto. It verifies that the carried scheme is
// supported by the consensus parameters; then it validates the authorization
// envelope and verifies the scheme-specific signature over message.
func (p SaltedKeySig) Verify(proto config.ConsensusParams, message crypto.Hashable, authorizer basics.Address) error {
	verifier, err := p.validateForVerification(proto, authorizer)
	if err != nil {
		return err
	}
	return verifier.Verify(message, p.PublicKey, p.Signature)
}

// BatchPrep validates p like Verify, then enqueues the signature into batch when
// the scheme is a crypto.SigSchemeBatchPreparer, or verifies it in place otherwise.
// Enqueued signatures are only checked when the batch is verified.
func (p SaltedKeySig) BatchPrep(proto config.ConsensusParams, message crypto.Hashable, authorizer basics.Address, batch crypto.BatchEnqueuer) error {
	verifier, err := p.validateForVerification(proto, authorizer)
	if err != nil {
		return err
	}
	if preparer, ok := verifier.(crypto.SigSchemeBatchPreparer); ok {
		return preparer.BatchPrep(message, p.PublicKey, p.Signature, batch)
	}
	return verifier.Verify(message, p.PublicKey, p.Signature)
}

// Batched reports whether p's scheme supports batch verification.
func (p SaltedKeySig) Batched() bool {
	scheme, ok := sigSchemes[p.Scheme]
	if !ok {
		return false
	}
	_, ok = scheme.verifier.(crypto.SigSchemeBatchPreparer)
	return ok
}
