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

import "github.com/algorand/go-algorand/crypto/internal/dilibs"

// Exporting signature, publicKey, secretKey.
type (
	//DilithiumPublicKey is the public key
	//msgp:allocbound DilithiumPublicKey
	DilithiumPublicKey []byte
	//DilithiumPrivateKey is the private key
	//msgp:allocbound DilithiumPrivateKey
	DilithiumPrivateKey []byte
	//DilithiumSignature is the exported signature
	//msgp:allocbound DilithiumSignature
	DilithiumSignature ByteSignature
)

// DilithiumSigner is the implementation of Signer for the Dilithium signature scheme.
type DilithiumSigner struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Keypair dilibs.DilithiumKeyPair `codec:"kys"`
}

// NewDilithiumSigner Generates a dilithium Signer.
func NewDilithiumSigner() Signer {
	return &DilithiumSigner{
		Keypair: *dilibs.NewKeys(),
	}
}

// Sign receives a message and generates a signature over that message.
// the size of the signature should conform with dil2Signature.
func (d *DilithiumSigner) Sign(message Hashable) ByteSignature {
	hs := Hash(hashRep(message))
	return d.SignBytes(hs[:])
}

// SignBytes receives bytes and signs over them.
// the size of the signature should conform with dil2Signature.
func (d *DilithiumSigner) SignBytes(data []byte) ByteSignature {
	return d.Keypair.SignBytes(data)
}

// GetVerifyingKey Outputs a veryfying key ovject which is serializeable.
func (d *DilithiumSigner) GetVerifyingKey() *VerifyingKey {
	return &VerifyingKey{
		Type: DilithiumType,
		Pack: PackedVerifyingKey{
			DilithiumPublicKey: DilithiumVerifier{
				PublicKey: d.Keypair.PublicKey,
			},
		},
	}
}

// DilithiumVerifier implements the type Verifier interface for the dilithium signature scheme.
type DilithiumVerifier struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey dilibs.Dil2PublicKey `codec:"k"`
}

// Verify follows dilithium algorithm to verify a signature.
func (d *DilithiumVerifier) Verify(message Hashable, sig ByteSignature) error {
	hs := Hash(hashRep(message))
	return d.VerifyBytes(hs[:], sig)
}

// VerifyBytes follows dilithium algorithm to verify a signature.
func (d *DilithiumVerifier) VerifyBytes(data []byte, sig ByteSignature) error {
	return d.PublicKey.VerifyBytes(data, sig)
}
