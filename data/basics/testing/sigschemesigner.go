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

// SigSchemeSigner adapts a signature scheme's concrete signer to a byte-oriented API so tests
// can treat all schemes uniformly.
type SigSchemeSigner interface {
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

type ed25519Signer struct{ *crypto.SignatureSecrets }

func (s ed25519Signer) Sign(message crypto.Hashable) ([]byte, error) {
	sig := s.SignatureSecrets.Sign(message)
	return sig[:], nil
}
func (s ed25519Signer) SignBytes(data []byte) ([]byte, error) {
	sig := s.SignatureSecrets.SignBytes(data)
	return sig[:], nil
}
func (s ed25519Signer) Verify(message crypto.Hashable, sig []byte) error {
	return crypto.Ed25519SchemeVerifier{}.Verify(message, s.PublicKey(), sig)
}
func (s ed25519Signer) VerifyBytes(data []byte, sig []byte) error {
	if len(sig) != len(crypto.Signature{}) || !s.SignatureVerifier.VerifyBytes(data, crypto.Signature(sig)) {
		return crypto.ErrSigInvalid
	}
	return nil
}
func (s ed25519Signer) PublicKey() []byte {
	return slices.Clone(s.SignatureVerifier[:])
}

// SigSchemeTest carries one signature scheme's test metadata.
type SigSchemeTest struct {
	// Name is a human-readable scheme name, suitable for subtest names.
	Name   string
	Scheme protocol.SigScheme
}

// SigSchemeTests lists the supported signature schemes with their test metadata, for
// tests that exercise every scheme. It leaves out ls, which has no key to sign with.
var SigSchemeTests = []SigSchemeTest{
	{
		Name:   "falcon-1024",
		Scheme: protocol.SigSchemeFalcon1024,
	},
	{
		Name:   "falcon-512",
		Scheme: protocol.SigSchemeFalcon512,
	},
	{
		Name:   "ed25519",
		Scheme: protocol.SigSchemeEd25519,
	},
}

// SigSchemeTestInfo returns the SigSchemeTests entry for scheme, failing the
// test on an unknown scheme.
func SigSchemeTestInfo(t testing.TB, scheme protocol.SigScheme) SigSchemeTest {
	t.Helper()

	for _, tc := range SigSchemeTests {
		if tc.Scheme == scheme {
			return tc
		}
	}
	t.Fatalf("unknown scheme %s", scheme)
	return SigSchemeTest{}
}

// RandomSigSchemeTest randomly picks one of SigSchemeTests.
func RandomSigSchemeTest() SigSchemeTest {
	var selector [1]byte
	crypto.RandBytes(selector[:])
	return SigSchemeTests[int(selector[0])%len(SigSchemeTests)]
}

// MakeSigSchemeSigner builds a wrapped signer for the given scheme from a
// deterministic seed.
func MakeSigSchemeSigner(t testing.TB, firstSeedByte byte, scheme protocol.SigScheme) SigSchemeSigner {
	t.Helper()

	var seed crypto.FalconSeed
	seed[0] = firstSeedByte
	switch scheme {
	case protocol.SigSchemeFalcon1024:
		signer, err := crypto.GenerateFalcon1024Signer(seed)
		require.NoError(t, err)
		return falcon1024Signer{signer}
	case protocol.SigSchemeFalcon512:
		signer, err := crypto.GenerateFalcon512Signer(seed)
		require.NoError(t, err)
		return falcon512Signer{signer}
	case protocol.SigSchemeEd25519:
		return ed25519Signer{crypto.GenerateSignatureSecrets(crypto.Seed{firstSeedByte})}
	}
	t.Fatalf("unknown scheme %s", scheme)
	return nil
}

// HashedKeySigTestAccount is a test account authorized through HashedKeySig: a wrapped signer plus its
// canonical salted address derivation.
type HashedKeySigTestAccount struct {
	Signer    SigSchemeSigner
	Scheme    protocol.SigScheme
	Address   basics.Address
	Salt      basics.AddressSalt
	PublicKey []byte
}

// MakeHashedKeySigTestAccount builds a HashedKeySigTestAccount for the given scheme from a
// deterministic seed, deriving the canonical salt and address for its public
// key.
func MakeHashedKeySigTestAccount(t testing.TB, firstSeedByte byte, scheme protocol.SigScheme) HashedKeySigTestAccount {
	t.Helper()

	signer := MakeSigSchemeSigner(t, firstSeedByte, scheme)
	publicKey := signer.PublicKey()
	salt, address, err := basics.CanonicalAddressSalt(scheme, publicKey)
	require.NoError(t, err)

	return HashedKeySigTestAccount{
		Signer:    signer,
		Scheme:    scheme,
		Address:   address,
		Salt:      salt,
		PublicKey: publicKey,
	}
}
