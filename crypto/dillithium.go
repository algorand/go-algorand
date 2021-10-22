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

import cdilithium "github.com/algorand/dilithium/ref"

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

	// DPublicKey is a wrapper for cdilithium.DilPublicKey (used for packing)
	DPublicKey [cdilithium.PublicKeySize]byte //cdilithium.DilPublicKey
	// DSecretKey is a wrapper for cdilithium.DilPrivateKe (used for packing)
	DSecretKey [cdilithium.PrivateKeySize]byte //cdilithium.DilPrivateKe
)

// DilithiumSigner is the implementation of Signer for the Dilithium signature scheme.
type DilithiumSigner struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey DPublicKey `codec:"pk"`
	SecretKey DSecretKey `codec:"sk"`
}

// NewDilithiumSigner Generates a dilithium Signer.
func NewDilithiumSigner() Signer {
	sk, pk := cdilithium.NewKeys()
	return &DilithiumSigner{
		PublicKey: DPublicKey(pk),
		SecretKey: DSecretKey(sk),
	}
}

// Sign receives a message and generates a signature over that message.
// the size of the signature should conform with cdilithium.SigSize.
func (d *DilithiumSigner) Sign(message Hashable) ByteSignature {
	hs := Hash(HashRep(message))
	return d.SignBytes(hs[:])
}

// SignBytes receives bytes and signs over them.
// the size of the signature should conform with cdilithium.SigSize.
func (d *DilithiumSigner) SignBytes(data []byte) ByteSignature {
	return (*cdilithium.DilPrivateKey)(&d.SecretKey).SignBytes(data)
}

// GetVerifyingKey Outputs a verifying key object which is serializable.
func (d *DilithiumSigner) GetVerifyingKey() *VerifyingKey {
	return &VerifyingKey{
		Type: DilithiumType,
		Pack: PackedVerifyingKey{
			DilithiumPublicKey: DilithiumVerifier{
				PublicKey: d.PublicKey,
			},
		},
	}
}

// DilithiumVerifier implements the type Verifier interface for the dilithium signature scheme.
type DilithiumVerifier struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey DPublicKey `codec:"k"`
}

// Verify follows dilithium algorithm to verify a signature.
func (d *DilithiumVerifier) Verify(message Hashable, sig ByteSignature) error {
	hs := Hash(HashRep(message))
	return d.VerifyBytes(hs[:], sig)
}

// VerifyBytes follows dilithium algorithm to verify a signature.
func (d *DilithiumVerifier) VerifyBytes(data []byte, sig ByteSignature) error {
	return (*cdilithium.DilPublicKey)(&d.PublicKey).VerifyBytes(data, sig)
}
