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

package main

import (
	"fmt"
	"strings"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const (
	sigSchemeFalcon1024Name = "falcon-1024"
	sigSchemeFalcon512Name  = "falcon-512"
	sigSchemeEd25519Name    = "ed25519"
)

// sigSchemeOps holds the signing-side, private-key operations for one signature
// scheme. The consensus-relevant scheme behavior (verification, enablement,
// fees, sizes) lives in the scheme table in data/transactions.
type sigSchemeOps interface {
	deriveSigning(seed crypto.Digest) (saltedSigningMaterial, error)
	sign(privateKey []byte, message crypto.Hashable) ([]byte, error)
	publicKeySize() uint64
	privateKeySize() uint64
}

var sigSchemeOpsByScheme = map[protocol.SigScheme]sigSchemeOps{
	protocol.SigSchemeFalcon1024: falcon1024Ops{},
	protocol.SigSchemeFalcon512:  falcon512Ops{},
	protocol.SigSchemeEd25519:    ed25519Ops{},
}

type falcon1024Ops struct{}
type falcon512Ops struct{}
type ed25519Ops struct{}

func parseSigScheme(value string) (protocol.SigScheme, error) {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, sigSchemeFalcon1024Name) {
		return protocol.SigSchemeFalcon1024, nil
	}
	if strings.EqualFold(value, sigSchemeFalcon512Name) {
		return protocol.SigSchemeFalcon512, nil
	}
	if strings.EqualFold(value, sigSchemeEd25519Name) {
		return protocol.SigSchemeEd25519, nil
	}

	var scheme protocol.SigScheme
	if len(value) != len(scheme) {
		return protocol.SigScheme{}, fmt.Errorf("%w: %q", transactions.ErrSigSchemeNotSupported, value)
	}
	copy(scheme[:], value)
	return scheme, nil
}

func formatSigScheme(scheme protocol.SigScheme) string {
	if scheme == protocol.SigSchemeFalcon1024 {
		return sigSchemeFalcon1024Name
	}
	if scheme == protocol.SigSchemeFalcon512 {
		return sigSchemeFalcon512Name
	}
	if scheme == protocol.SigSchemeEd25519 {
		return sigSchemeEd25519Name
	}
	return scheme.String()
}

func generateSaltedSigningMaterial(scheme protocol.SigScheme, rng crypto.RNG) (crypto.Seed, saltedSigningMaterial, error) {
	var entropy crypto.Seed
	rng.RandBytes(entropy[:])

	signing, err := deriveSaltedSigningMaterialFromEntropy(scheme, entropy)
	return entropy, signing, err
}

func deriveSaltedSigningMaterialFromEntropy(scheme protocol.SigScheme, entropy crypto.Seed) (saltedSigningMaterial, error) {
	ops, ok := sigSchemeOpsByScheme[scheme]
	if !ok {
		return saltedSigningMaterial{}, fmt.Errorf("%w: %q", transactions.ErrSigSchemeNotSupported, scheme)
	}

	seed := deriveSigSchemeKeySeed(scheme, entropy)
	return ops.deriveSigning(seed)
}

// deriveSigSchemeKeySeed maps mnemonic-sized entropy to a scheme-specific keygen
// seed: SHA512_256(PQK || scheme[2] || entropy[32]).
func deriveSigSchemeKeySeed(scheme protocol.SigScheme, entropy crypto.Seed) crypto.Digest {
	input := make([]byte, 0, len(protocol.PostQuantumKey)+len(scheme)+len(entropy))
	input = append(input, string(protocol.PostQuantumKey)...)
	input = append(input, scheme[:]...)
	input = append(input, entropy[:]...)

	return crypto.Hash(input)
}

func (falcon1024Ops) deriveSigning(seed crypto.Digest) (saltedSigningMaterial, error) {
	signer, err := crypto.GenerateFalcon1024Signer(crypto.FalconSeed(seed))
	if err != nil {
		return saltedSigningMaterial{}, err
	}

	publicKey := signer.PublicKey[:]
	privateKey := signer.PrivateKey[:]
	salt, _, err := basics.CanonicalAddressSalt(protocol.SigSchemeFalcon1024, publicKey)
	if err != nil {
		return saltedSigningMaterial{}, err
	}

	return saltedSigningMaterial{
		Public: saltedPublicMaterial{
			Scheme:    protocol.SigSchemeFalcon1024,
			Salt:      salt,
			PublicKey: publicKey,
		},
		PrivateKey: privateKey,
	}, nil
}

func (falcon1024Ops) publicKeySize() uint64 { return crypto.Falcon1024PublicKeySize }

func (falcon1024Ops) privateKeySize() uint64 { return crypto.Falcon1024PrivateKeySize }

func (falcon1024Ops) sign(privateKey []byte, message crypto.Hashable) ([]byte, error) {
	var sk crypto.Falcon1024PrivateKey
	if len(privateKey) != len(sk) {
		return nil, fmt.Errorf("%w: got private key size %d, want %d", errSaltedKeyMalformed, len(privateKey), len(sk))
	}
	copy(sk[:], privateKey)

	signer := crypto.Falcon1024Signer{PrivateKey: sk}
	return signer.Sign(message)
}

func (falcon512Ops) deriveSigning(seed crypto.Digest) (saltedSigningMaterial, error) {
	signer, err := crypto.GenerateFalcon512Signer(crypto.FalconSeed(seed))
	if err != nil {
		return saltedSigningMaterial{}, err
	}

	publicKey := signer.PublicKey[:]
	privateKey := signer.PrivateKey[:]
	salt, _, err := basics.CanonicalAddressSalt(protocol.SigSchemeFalcon512, publicKey)
	if err != nil {
		return saltedSigningMaterial{}, err
	}

	return saltedSigningMaterial{
		Public: saltedPublicMaterial{
			Scheme:    protocol.SigSchemeFalcon512,
			Salt:      salt,
			PublicKey: publicKey,
		},
		PrivateKey: privateKey,
	}, nil
}

func (falcon512Ops) publicKeySize() uint64 { return crypto.Falcon512PublicKeySize }

func (falcon512Ops) privateKeySize() uint64 { return crypto.Falcon512PrivateKeySize }

func (falcon512Ops) sign(privateKey []byte, message crypto.Hashable) ([]byte, error) {
	var sk crypto.Falcon512PrivateKey
	if len(privateKey) != len(sk) {
		return nil, fmt.Errorf("%w: got private key size %d, want %d", errSaltedKeyMalformed, len(privateKey), len(sk))
	}
	copy(sk[:], privateKey)

	signer := crypto.Falcon512Signer{PrivateKey: sk}
	return signer.Sign(message)
}

func (ed25519Ops) deriveSigning(seed crypto.Digest) (saltedSigningMaterial, error) {
	signer := crypto.GenerateSignatureSecrets(crypto.Seed(seed))
	publicKey := signer.SignatureVerifier[:]
	privateKey := signer.SK[:]
	salt, _, err := basics.CanonicalAddressSalt(protocol.SigSchemeEd25519, publicKey)
	if err != nil {
		return saltedSigningMaterial{}, err
	}

	return saltedSigningMaterial{
		Public: saltedPublicMaterial{
			Scheme:    protocol.SigSchemeEd25519,
			Salt:      salt,
			PublicKey: publicKey,
		},
		PrivateKey: privateKey,
	}, nil
}

func (ed25519Ops) publicKeySize() uint64 { return uint64(len(crypto.PublicKey{})) }

func (ed25519Ops) privateKeySize() uint64 { return uint64(len(crypto.PrivateKey{})) }

func (ed25519Ops) sign(privateKey []byte, message crypto.Hashable) ([]byte, error) {
	var sk crypto.PrivateKey
	if len(privateKey) != len(sk) {
		return nil, fmt.Errorf("%w: got private key size %d, want %d", errSaltedKeyMalformed, len(privateKey), len(sk))
	}
	copy(sk[:], privateKey)

	signer, err := crypto.SecretKeyToSignatureSecrets(sk)
	if err != nil {
		return nil, err
	}
	sig := signer.Sign(message)
	return sig[:], nil
}
