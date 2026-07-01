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

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/protocol"
)

var (
	// ErrPQSchemeNotSupported is returned when a PQScheme is not supported.
	ErrPQSchemeNotSupported = errors.New("pq signature scheme not supported")

	// ErrPQSchemeNotEnabled is returned when a PQScheme is not enabled under the protocol.
	ErrPQSchemeNotEnabled = errors.New("pq signature scheme not enabled")
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

// PQSchemeSpec describes the behavior for one PQ signature scheme.
//
//msgp:ignore PQSchemeSpec
type PQSchemeSpec struct {
	PublicKeySize   uint64
	SignatureSize   uint64
	FeeContribution Micros
	Verify          func(crypto.Hashable, []byte, []byte) error
}

// pqSchemeSpecs is the registry for supported PQ signature schemes.
// To add a scheme:
//   - Add the protocol.PQScheme tag,
//   - Add the consensus flag and config.ConsensusParams.PQSchemeEnabled case,
//   - Add the registry entry here,
//   - Add the signing/private-key ops in cmd/algokey's pqSchemeOpsByScheme.
//   - If the scheme changes MaxPQPublicKeySize or MaxPQSignatureSize,
//     regenerate msgp code.
var pqSchemeSpecs = map[protocol.PQScheme]PQSchemeSpec{
	protocol.PQSchemeFalcon1024: {
		PublicKeySize:   crypto.FalconPublicKeySize,
		SignatureSize:   crypto.FalconMaxSignatureSize,
		FeeContribution: PQSchemeFalcon1024FeeContribution,
		Verify:          crypto.VerifyFalcon1024,
	},
	// protocol.PQSchemeFalcon512: {
	// 	PublicKeySize:   crypto.Falcon512PublicKeySize,
	// 	SignatureSize:   crypto.Falcon512MaxSignatureSize,
	// 	FeeContribution: PQSchemeFalcon512FeeContribution,
	// 	Verify:          crypto.VerifyFalcon512,
	// },
}

// LookupPQScheme returns the scheme description for s.
func LookupPQScheme(s protocol.PQScheme) (PQSchemeSpec, bool) {
	scheme, ok := pqSchemeSpecs[s]
	return scheme, ok
}

// MaxPQPublicKeySize returns the largest public-key size in the PQ scheme registry.
func MaxPQPublicKeySize() uint64 {
	var m uint64
	for _, scheme := range pqSchemeSpecs {
		m = max(m, scheme.PublicKeySize)
	}
	return m
}

// MaxPQSignatureSize returns the largest signature size in the PQ scheme registry.
func MaxPQSignatureSize() uint64 {
	var m uint64
	for _, scheme := range pqSchemeSpecs {
		m = max(m, scheme.SignatureSize)
	}
	return m
}
