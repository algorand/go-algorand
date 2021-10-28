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

// GenerateEd25519Key is responsible for creating some unknown key
func GenerateEd25519Key(seed Seed) *Ed25519Key {
	return &Ed25519Key{
		Sec: *GenerateSignatureSecrets(seed),
	}
}

// Ed25519Key represents an unknown key
// the struct implements Signer
type Ed25519Key struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Sec SignatureSecrets `codec:"sec"`
}

// Ed25519PublicKey represents an unknown public key
// the struct implements Verifier
type Ed25519PublicKey struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	SignatureVerifier `codec:"sigVerifier"`
}

// Sign - Signs a Hashable message
func (p *Ed25519Key) Sign(message Hashable) ByteSignature {
	sig := p.Sec.Sign(message)
	return sig[:]
}

// SignBytes - Signs a a slice of bytes
func (p *Ed25519Key) SignBytes(message []byte) ByteSignature {
	sig := p.Sec.SignBytes(message)
	return sig[:]
}

// GetVerifyingKey outputs a representation of a public key. that implements Verifier
func (p *Ed25519Key) GetVerifyingKey() *GenericVerifyingKey {
	return &GenericVerifyingKey{
		Type:             Ed25519Type,
		Ed25519PublicKey: Ed25519PublicKey{SignatureVerifier: p.Sec.SignatureVerifier},
	}
}

// Verify that a signature match to a specific message
func (p *Ed25519PublicKey) Verify(message Hashable, sig ByteSignature) error {
	if !p.SignatureVerifier.Verify(message, byteSigToSignatureType(sig)) {
		return ErrBadSignature
	}
	return nil
}

// VerifyBytes checks that a signature match to a specific byte message
func (p *Ed25519PublicKey) VerifyBytes(message []byte, sig ByteSignature) error {
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
