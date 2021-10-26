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

import "C"
import (
	cparalithium "github.com/algoidan/paralithium/ref"
)

// Exporting signature, publicKey, secretKey.
type (
	//ParalithiumPublicKey holds the public data for the paralithium signature scheme
	//msgp:allocbound ParalithiumPublicKey
	ParalithiumPublicKey []byte
	//ParalithiumPrivateKey is the private key
	//msgp:allocbound ParalithiumPrivateKey
	ParalithiumPrivateKey []byte
	//ParalithiumSignature is the exported signature
	//msgp:allocbound ParalithiumSignature
	ParalithiumSignature ByteSignature

	// PPublicKey is a wrapper for cparalithium.ParalithiumPublicKey (used for packing)
	PPublicKey [cparalithium.PublicKeySize]byte
	// PSecretKey is a wrapper for cparalithium.ParalithiumPrivateKey (used for packing)
	PSecretKey [cparalithium.PrivateKeySize]byte
)

// AlgorandParalithiumSeed - this value is used to generate the public/secret keys.
// it can be found on the first 32 bytes of the publickey. This value will be a constant
// in the SNARK prover.
var AlgorandParalithiumSeed = [cparalithium.SeedSize]byte{'A', 'l', 'g', 'o', 'r', 'a', 'n', 'd', ' ', 'P', 'a', 'r', 'a', 'l', 'i', 't', 'h', 'i', 'u', 'm', ' ', 'v', '0', '1', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// ParalithiumSigner is the implementation of Signer for the Paralithium signature scheme.
type ParalithiumSigner struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey PPublicKey `codec:"pk"`
	SecretKey PSecretKey `codec:"sk"`
}

// Consider supply RandBytes() from go-algorand as the random function. This would be relevant when we use NewKeys function

// GenerateParalithiumSigner Generates a dilithium Signer.
func GenerateParalithiumSigner() Signer {
	sk, pk := cparalithium.NewKeysWithRho(cparalithium.ParalithiumSeed(AlgorandParalithiumSeed))
	return &ParalithiumSigner{
		PublicKey: PPublicKey(pk),
		SecretKey: PSecretKey(sk),
	}
}

// Sign receives a message and generates a signature over that message.
// the size of the signature should conform with cparalithium.SigSize.
func (d *ParalithiumSigner) Sign(message Hashable) ByteSignature {
	hs := Hash(HashRep(message))
	return d.SignBytes(hs[:])
}

// SignBytes receives bytes and signs over them.
// the size of the signature should conform with cparalithium.SigSize.
func (d *ParalithiumSigner) SignBytes(data []byte) ByteSignature {
	return (*cparalithium.ParalithiumPrivateKey)(&d.SecretKey).SignBytes(data)
}

// GetVerifyingKey Outputs a verifying key object which is serializable.
func (d *ParalithiumSigner) GetVerifyingKey() *VerifyingKey {
	return &VerifyingKey{
		Type: ParalithiumType,
		Pack: PackedVerifyingKey{
			ParalithiumPublicKey: ParalithiumVerifier{
				PublicKey: d.PublicKey,
			},
		},
	}
}

// ParalithiumVerifier implements the type Verifier interface for the paralithium signature scheme.
type ParalithiumVerifier struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey PPublicKey `codec:"k"`
}

// Verify follows paralithium algorithm to verify a signature.
func (d *ParalithiumVerifier) Verify(message Hashable, sig ByteSignature) error {
	hs := Hash(HashRep(message))
	return d.VerifyBytes(hs[:], sig)
}

// VerifyBytes follows paralithium algorithm to verify a signature.
func (d *ParalithiumVerifier) VerifyBytes(data []byte, sig ByteSignature) error {
	if err := (*cparalithium.ParalithiumPublicKey)(&d.PublicKey).VerifyRho(AlgorandParalithiumSeed); err != nil {
		return err
	}
	return (*cparalithium.ParalithiumPublicKey)(&d.PublicKey).VerifyBytes(data, sig)
}
