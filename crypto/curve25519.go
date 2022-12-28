// Copyright (C) 2019-2023 Algorand, Inc.
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

import (
	"github.com/algorand/go-algorand/util/metrics"
)

// TODO: Remove metrics from crypto package
var cryptoVRFGenerateTotal = metrics.MakeCounter(metrics.CryptoVRFGenerateTotal)
var cryptoVRFProveTotal = metrics.MakeCounter(metrics.CryptoVRFProveTotal)
var cryptoVRFHashTotal = metrics.MakeCounter(metrics.CryptoVRFHashTotal)
var cryptoVRFVerifyTotal = metrics.MakeCounter(metrics.CryptoVRFVerifyTotal)
var cryptoGenSigSecretsTotal = metrics.MakeCounter(metrics.CryptoGenSigSecretsTotal)
var cryptoSigSecretsSignTotal = metrics.MakeCounter(metrics.CryptoSigSecretsSignTotal)
var cryptoSigSecretsSignBytesTotal = metrics.MakeCounter(metrics.CryptoSigSecretsSignBytesTotal)
var cryptoSigSecretsVerifyTotal = metrics.MakeCounter(metrics.CryptoSigSecretsVerifyTotal)
var cryptoSigSecretsVerifyBytesTotal = metrics.MakeCounter(metrics.CryptoSigSecretsVerifyBytesTotal)

const masterDerivationKeyLenBytes = 32

// A Seed holds the entropy needed to generate cryptographic keys.
type Seed ed25519Seed

// /* Classical signatures */
// type ed25519Signature [64]byte
// type ed25519PublicKey [32]byte
// type ed25519PrivateKey [64]byte
// type ed25519Seed [32]byte

// MasterDerivationKey is used to derive ed25519 keys for use in wallets
type MasterDerivationKey [masterDerivationKeyLenBytes]byte

// PrivateKey is an exported ed25519PrivateKey
type PrivateKey ed25519PrivateKey

// PublicKey is an exported ed25519PublicKey
type PublicKey ed25519PublicKey

func ed25519GenerateKey() (public ed25519PublicKey, secret ed25519PrivateKey) {
	var seed ed25519Seed
	RandBytes(seed[:])
	return ed25519GenerateKeySeed(seed)
}

func ed25519GenerateKeyRNG(rng RNG) (public ed25519PublicKey, secret ed25519PrivateKey) {
	var seed ed25519Seed
	rng.RandBytes(seed[:])
	return ed25519GenerateKeySeed(seed)
}

// A Signature is a cryptographic signature. It proves that a message was
// produced by a holder of a cryptographic secret.
type Signature ed25519Signature

// BlankSignature is an empty signature structure, containing nothing but zeroes
var BlankSignature = Signature{}

// Blank tests to see if the given signature contains only zeros
func (s *Signature) Blank() bool {
	return (*s) == BlankSignature
}

// A SignatureVerifier is used to identify the holder of SignatureSecrets
// and verify the authenticity of Signatures.
type SignatureVerifier = PublicKey

// SignatureSecrets are used by an entity to produce unforgeable signatures over
// a message.
type SignatureSecrets struct {
	_struct struct{} `codec:""`

	SignatureVerifier
	SK ed25519PrivateKey
}

// SecretKeyToSignatureSecrets converts a private key into a SignatureSecrets and
// returns a pointer
func SecretKeyToSignatureSecrets(sk PrivateKey) (secrets *SignatureSecrets, err error) {
	pk, err := SecretKeyToPublicKey(sk)
	if err != nil {
		return
	}
	secrets = &SignatureSecrets{
		SignatureVerifier: SignatureVerifier(pk),
		SK:                ed25519PrivateKey(sk),
	}
	return
}

// GenerateSignatureSecrets creates SignatureSecrets from a source of entropy.
func GenerateSignatureSecrets(seed Seed) *SignatureSecrets {
	pk0, sk := ed25519GenerateKeySeed(ed25519Seed(seed))
	pk := SignatureVerifier(pk0)
	cryptoGenSigSecretsTotal.Inc(nil)
	return &SignatureSecrets{SignatureVerifier: pk, SK: sk}
}

// Sign produces a cryptographic Signature of a Hashable message, given
// cryptographic secrets.
func (s *SignatureSecrets) Sign(message Hashable) Signature {
	cryptoSigSecretsSignTotal.Inc(nil)
	return s.SignBytes(HashRep(message))
}

// SignBytes signs a message directly, without first hashing.
// Caller is responsible for domain separation.
func (s *SignatureSecrets) SignBytes(message []byte) Signature {
	cryptoSigSecretsSignBytesTotal.Inc(nil)
	return Signature(ed25519Sign(ed25519PrivateKey(s.SK), message))
}

// Verify verifies that some holder of a cryptographic secret authentically
// signed a Hashable message.
//
// It returns true if this is the case; otherwise, it returns false.
//
func (v SignatureVerifier) Verify(message Hashable, sig Signature) bool {
	cryptoSigSecretsVerifyTotal.Inc(nil)
	return ed25519Verify(ed25519PublicKey(v), HashRep(message), ed25519Signature(sig))
}

// VerifyBytes verifies a signature, where the message is not hashed first.
// Caller is responsible for domain separation.
// If the message is a Hashable, Verify() can be used instead.
func (v SignatureVerifier) VerifyBytes(message []byte, sig Signature) bool {
	cryptoSigSecretsVerifyBytesTotal.Inc(nil)
	return ed25519Verify(ed25519PublicKey(v), message, ed25519Signature(sig))
}
