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

package testing

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
)

// FalconSigner adapts one PQ scheme's concrete signer (crypto.Falcon1024Signer
// or crypto.Falcon512Signer) to a byte-oriented API so tests can treat both
// schemes uniformly.
type FalconSigner interface {
	Sign(message crypto.Hashable) ([]byte, error)
	SignBytes(data []byte) ([]byte, error)
	Verify(message crypto.Hashable, sig []byte) error
	VerifyBytes(data []byte, sig []byte) error
	PublicKey() []byte
}

type falcon1024Signer struct{ crypto.Falcon1024Signer }

func (s falcon1024Signer) Sign(message crypto.Hashable) ([]byte, error) {
	return s.Falcon1024Signer.Sign(message)
}
func (s falcon1024Signer) SignBytes(data []byte) ([]byte, error) {
	return s.Falcon1024Signer.SignBytes(data)
}
func (s falcon1024Signer) Verify(message crypto.Hashable, sig []byte) error {
	return s.GetVerifyingKey().Verify(message, sig)
}
func (s falcon1024Signer) VerifyBytes(data []byte, sig []byte) error {
	return s.GetVerifyingKey().VerifyBytes(data, sig)
}
func (s falcon1024Signer) PublicKey() []byte {
	return slices.Clone(s.Falcon1024Signer.PublicKey[:])
}

type falcon512Signer struct{ crypto.Falcon512Signer }

func (s falcon512Signer) Sign(message crypto.Hashable) ([]byte, error) {
	return s.Falcon512Signer.Sign(message)
}
func (s falcon512Signer) SignBytes(data []byte) ([]byte, error) {
	return s.Falcon512Signer.SignBytes(data)
}
func (s falcon512Signer) Verify(message crypto.Hashable, sig []byte) error {
	return s.GetVerifyingKey().Verify(message, sig)
}
func (s falcon512Signer) VerifyBytes(data []byte, sig []byte) error {
	return s.GetVerifyingKey().VerifyBytes(data, sig)
}
func (s falcon512Signer) PublicKey() []byte {
	return slices.Clone(s.Falcon512Signer.PublicKey[:])
}

// PQTestScheme carries one PQ scheme's test metadata.
type PQTestScheme struct {
	// Name is a human-readable scheme name, suitable for subtest names.
	Name             string
	Scheme           protocol.PQScheme
	ErrSigInvalid    error
	MaxSignatureSize int
}

// PQTestSchemes lists the supported PQ schemes with their test metadata, for
// tests that exercise every scheme.
var PQTestSchemes = []PQTestScheme{
	{
		Name:             "falcon-1024",
		Scheme:           protocol.PQSchemeFalcon1024,
		ErrSigInvalid:    crypto.ErrPQFalcon1024SigInvalid,
		MaxSignatureSize: crypto.Falcon1024MaxSignatureSize,
	},
	{
		Name:             "falcon-512",
		Scheme:           protocol.PQSchemeFalcon512,
		ErrSigInvalid:    crypto.ErrPQFalcon512SigInvalid,
		MaxSignatureSize: crypto.Falcon512MaxSignatureSize,
	},
}

// PQTestSchemeInfo returns the PQTestSchemes entry for scheme, failing the
// test on an unknown scheme.
func PQTestSchemeInfo(t testing.TB, scheme protocol.PQScheme) PQTestScheme {
	t.Helper()

	for _, tc := range PQTestSchemes {
		if tc.Scheme == scheme {
			return tc
		}
	}
	t.Fatalf("unknown scheme %s", scheme)
	return PQTestScheme{}
}

// RandomPQTestScheme randomly picks one of PQTestSchemes.
func RandomPQTestScheme() PQTestScheme {
	var selector [1]byte
	crypto.RandBytes(selector[:])
	return PQTestSchemes[int(selector[0])%len(PQTestSchemes)]
}

// MakeFalconSigner builds a wrapped Falcon signer for the given scheme from a
// deterministic seed.
func MakeFalconSigner(t testing.TB, firstSeedByte byte, scheme protocol.PQScheme) FalconSigner {
	t.Helper()

	var seed crypto.FalconSeed
	seed[0] = firstSeedByte
	switch scheme {
	case protocol.PQSchemeFalcon1024:
		signer, err := crypto.GenerateFalcon1024Signer(seed)
		require.NoError(t, err)
		return falcon1024Signer{signer}
	case protocol.PQSchemeFalcon512:
		signer, err := crypto.GenerateFalcon512Signer(seed)
		require.NoError(t, err)
		return falcon512Signer{signer}
	}
	t.Fatalf("unknown scheme %s", scheme)
	return nil
}

// PQTestAccount is a PQ-addressed test account: a wrapped signer plus its
// canonical PQ address derivation.
type PQTestAccount struct {
	Signer    FalconSigner
	Scheme    protocol.PQScheme
	Address   basics.Address
	Salt      basics.PQAddressSalt
	PublicKey []byte
}

// MakePQTestAccount builds a PQTestAccount for the given scheme from a
// deterministic seed, deriving the canonical salt and address for its public
// key.
func MakePQTestAccount(t testing.TB, firstSeedByte byte, scheme protocol.PQScheme) PQTestAccount {
	t.Helper()

	signer := MakeFalconSigner(t, firstSeedByte, scheme)
	publicKey := signer.PublicKey()
	salt, address, err := basics.CanonicalPQAddressSalt(scheme, publicKey)
	require.NoError(t, err)

	return PQTestAccount{
		Signer:    signer,
		Scheme:    scheme,
		Address:   address,
		Salt:      salt,
		PublicKey: publicKey,
	}
}
