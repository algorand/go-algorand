// Copyright (C) 2019-2021 Algorand, Inc.
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

// GeneratePlaceHolderKey is responsible for creating some unknown key
func GeneratePlaceHolderKey(seed Seed) *PlaceHolderKey {
	return &PlaceHolderKey{
		Sec: *GenerateSignatureSecrets(seed),
	}
}

// PlaceHolderKey represents an unknown key
// the struct implements Signer
type PlaceHolderKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sec SignatureSecrets `codec:"sec"`
}

// PlaceHolderPublicKey represents an unknown public key
// the struct implements Verifier
type PlaceHolderPublicKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SignatureVerifier `codec:"sigVerifier"`
}

// Sign - Signs a Hashable message
func (p *PlaceHolderKey) Sign(message Hashable) ByteSignature {
	sig := p.Sec.Sign(message)
	return sig[:]
}

// SignBytes - Signs a a slice of bytes
func (p *PlaceHolderKey) SignBytes(message []byte) ByteSignature {
	sig := p.Sec.SignBytes(message)
	return sig[:]
}

// GetVerifyingKey outputs a representation of a public key. that implements Verifier
func (p *PlaceHolderKey) GetVerifyingKey() VerifyingKey {
	return VerifyingKey{
		Type: PlaceHolderType,
		Pack: PackedVerifyingKey{PlaceHolderPublicKey: PlaceHolderPublicKey{SignatureVerifier: p.Sec.SignatureVerifier}},
	}
}

// Verify that a signature match to a specific message
func (p *PlaceHolderPublicKey) Verify(message Hashable, sig ByteSignature) error {
	if !p.SignatureVerifier.Verify(message, byteSigToSignatureType(sig)) {
		return ErrBadSignature
	}
	return nil
}

// VerifyBytes checks that a signature match to a specific byte message
func (p *PlaceHolderPublicKey) VerifyBytes(message []byte, sig ByteSignature) error {
	if !p.SignatureVerifier.VerifyBytes(message, byteSigToSignatureType(sig)) {
		return ErrBadSignature
	}
	return nil
}

func byteSigToSignatureType(sig ByteSignature) Signature {
	var scopy Signature
	copy(scopy[:], sig)
	return scopy
}
