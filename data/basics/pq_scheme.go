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

package basics

import (
	"errors"
	"fmt"
	"slices"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

var (
	// ErrPQSchemeNotSupported is returned when a PQScheme is not supported.
	ErrPQSchemeNotSupported = errors.New("pq signature scheme not supported")

	// ErrPQSchemeNotEnabled is returned when a PQScheme is not enabled under the protocol.
	ErrPQSchemeNotEnabled = errors.New("pq signature scheme not enabled")

	// ErrPQFalcon1024SigInvalid is returned when Falcon-1024 signature verification fails.
	ErrPQFalcon1024SigInvalid = errors.New("invalid falcon-1024 signature")
)

// PQSchemeSpec.FeeContribution is the additional fee factor charged for transactions
// authorized with a post-quantum scheme. It is expressed as a fixed-point multiple
// of the basic min fee, with 1e6 meaning one basic min fee.
//
// Once a PQ scheme activates, repricing must use a new constant and a new consensus gate.
const (
	PQSchemeFalcon512FeeContribution  Micros = 1e6 // should stay below the Falcon-1024 contribution
	PQSchemeFalcon1024FeeContribution Micros = 2e6
)

// PQSchemeConsensusParams is the consensus-parameter surface needed by PQ scheme gates.
type PQSchemeConsensusParams interface {
	PQSchemeEnabled(protocol.PQScheme) bool
}

// PQSchemeSpec describes the behavior for one PQ signature scheme.
//
//msgp:ignore PQSchemeSpec
type PQSchemeSpec struct {
	Enabled           func(PQSchemeConsensusParams) bool
	PublicKeySize     uint64
	SignatureSize     uint64
	FeeContribution   Micros
	ValidatePublicKey func([]byte) error
	Verify            func(crypto.Hashable, []byte, []byte) error
}

// pqSchemeSpecs is the registry for supported PQ signature schemes.
// To add a scheme:
// - Add the protocol.PQScheme tag,
// - Add the consensus flag and config.ConsensusParams.PQSchemeEnabled case,
// - Add the registry entry here,
// - Add the signing/private-key ops in cmd/algokey's pqSchemeOpsByScheme.
var pqSchemeSpecs = map[protocol.PQScheme]PQSchemeSpec{
	protocol.PQSchemeFalcon1024: {
		Enabled:           pqSchemeEnabled(protocol.PQSchemeFalcon1024),
		PublicKeySize:     crypto.FalconPublicKeySize,
		SignatureSize:     crypto.FalconMaxSignatureSize,
		FeeContribution:   PQSchemeFalcon1024FeeContribution,
		ValidatePublicKey: validateFalcon1024PublicKey,
		Verify:            verifyFalcon1024,
	},
	// protocol.PQSchemeFalcon512: {
	// 	Enabled:           pqSchemeEnabled(protocol.PQSchemeFalcon512),
	// 	PublicKeySize:     crypto.Falcon512PublicKeySize,
	// 	SignatureSize:     crypto.Falcon512MaxSignatureSize,
	// 	FeeContribution:   PQSchemeFalcon512FeeContribution,
	// 	ValidatePublicKey: validateFalcon512PublicKey,
	// 	Verify:            verifyFalcon512,
	// },
}

func init() {
	if err := validatePQSchemeSpecs(pqSchemeSpecs); err != nil {
		panic(err)
	}
}

func validatePQSchemeSpecs(specs map[protocol.PQScheme]PQSchemeSpec) error {
	for scheme, spec := range specs {
		if spec.Enabled == nil {
			return fmt.Errorf("pq scheme %q has nil Enabled", scheme)
		}
		if spec.ValidatePublicKey == nil {
			return fmt.Errorf("pq scheme %q has nil ValidatePublicKey", scheme)
		}
		if spec.Verify == nil {
			return fmt.Errorf("pq scheme %q has nil Verify", scheme)
		}
		if spec.PublicKeySize == 0 {
			return fmt.Errorf("pq scheme %q has zero public key size", scheme)
		}
		if spec.SignatureSize == 0 {
			return fmt.Errorf("pq scheme %q has zero signature size", scheme)
		}
		if spec.FeeContribution == 0 {
			return fmt.Errorf("pq scheme %q has zero fee contribution", scheme)
		}
	}
	return nil
}

// LookupPQScheme returns the scheme description for s.
func LookupPQScheme(s protocol.PQScheme) (PQSchemeSpec, bool) {
	scheme, ok := pqSchemeSpecs[s]
	return scheme, ok
}

// SupportedPQSchemes returns the scheme tags in the PQ scheme registry, sorted
// for deterministic iteration.
func SupportedPQSchemes() []protocol.PQScheme {
	schemes := make([]protocol.PQScheme, 0, len(pqSchemeSpecs))
	for scheme := range pqSchemeSpecs {
		schemes = append(schemes, scheme)
	}
	slices.Sort(schemes)
	return schemes
}

// ValidatePQPublicKey checks that a public key is valid for the scheme.
func ValidatePQPublicKey(s protocol.PQScheme, publicKey []byte) error {
	scheme, ok := LookupPQScheme(s)
	if !ok {
		return ErrPQSchemeNotSupported
	}
	return scheme.ValidatePublicKey(publicKey)
}

// MaxPQPublicKeySize returns the largest public key size supported PQ schemes.
func MaxPQPublicKeySize() uint64 {
	var maxSize uint64
	for _, scheme := range pqSchemeSpecs {
		if scheme.PublicKeySize > maxSize {
			maxSize = scheme.PublicKeySize
		}
	}
	return maxSize
}

// MaxPQSignatureSize returns the largest signature size supported PQ schemes.
func MaxPQSignatureSize() uint64 {
	var maxSize uint64
	for _, scheme := range pqSchemeSpecs {
		if scheme.SignatureSize > maxSize {
			maxSize = scheme.SignatureSize
		}
	}
	return maxSize
}

func pqSchemeEnabled(s protocol.PQScheme) func(PQSchemeConsensusParams) bool {
	return func(params PQSchemeConsensusParams) bool {
		return params.PQSchemeEnabled(s)
	}
}

// Falcon-1024 helpers

func validateFalcon1024PublicKey(publicKey []byte) error {
	_, err := crypto.FalconPublicKeyFromBytes(publicKey)
	return err
}

func verifyFalcon1024(message crypto.Hashable, publicKey []byte, signature []byte) error {
	pk, err := crypto.FalconPublicKeyFromBytes(publicKey)
	if err != nil {
		return err
	}

	sig, err := crypto.FalconSignatureFromBytes(signature)
	if err != nil {
		return err
	}

	fv := crypto.FalconVerifier{PublicKey: pk}
	if err := fv.Verify(message, sig); err != nil {
		return fmt.Errorf("%w: %w", ErrPQFalcon1024SigInvalid, err)
	}
	return nil
}

// Falcon-512 helpers

// TODO: func validateFalcon512PublicKey(publicKey []byte) error {...}

// TODO: func verifyFalcon512(message crypto.Hashable, publicKey []byte, signature []byte) error {...}
