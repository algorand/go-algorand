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
	"slices"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const pqKeyEntropySize = crypto.DigestSize

// pqSchemeOps holds the signing-side, private-key operations for one PQ
// scheme. The consensus-relevant scheme behavior (public key validation,
// signature verification, sizes, fees) lives in the basics PQ scheme registry;
// see basics.LookupPQScheme.
type pqSchemeOps struct {
	deriveSigning func([]byte) (pqSigningMaterial, error)
	signTxn       func([]byte, transactions.Transaction) ([]byte, error)
}

var pqSchemeOpsByScheme = map[protocol.PQScheme]pqSchemeOps{
	protocol.PQSchemeFalcon1024: {
		deriveSigning: deriveFalcon1024SigningMaterial,
		signTxn:       signFalcon1024Txn,
	},
}

func parsePQScheme(value string) (protocol.PQScheme, error) {
	var scheme protocol.PQScheme
	if len(value) != len(scheme) {
		return protocol.PQScheme{}, fmt.Errorf("%w: %q", basics.ErrPQSchemeNotSupported, value)
	}
	copy(scheme[:], value)
	return scheme, nil
}

func generatePQRoot(scheme protocol.PQScheme, rng crypto.RNG) (pqRootMaterial, error) {
	var entropy crypto.Seed
	rng.RandBytes(entropy[:])

	return rootMaterialFromEntropy(scheme, entropy)
}

func rootMaterialFromEntropy(scheme protocol.PQScheme, entropy crypto.Seed) (pqRootMaterial, error) {
	signing, err := derivePQSigningMaterialFromEntropy(scheme, entropy[:])
	if err != nil {
		return pqRootMaterial{}, err
	}

	return pqRootMaterial{
		scheme:  scheme,
		entropy: entropy,
		public:  signing.public,
	}, nil
}

func derivePQSigningMaterialFromEntropy(scheme protocol.PQScheme, entropy []byte) (pqSigningMaterial, error) {
	ops, ok := pqSchemeOpsByScheme[scheme]
	if !ok {
		return pqSigningMaterial{}, fmt.Errorf("%w: %q", basics.ErrPQSchemeNotSupported, scheme)
	}

	seed, err := derivePQKeySeed(scheme, entropy)
	if err != nil {
		return pqSigningMaterial{}, err
	}

	return ops.deriveSigning(seed[:])
}

// derivePQKeySeed maps mnemonic-sized entropy to a scheme-specific PQ keygen
// seed: SHA512_256(PQK || scheme[2] || entropy[32]).
func derivePQKeySeed(scheme protocol.PQScheme, entropy []byte) (crypto.Digest, error) {
	if len(entropy) != pqKeyEntropySize {
		return crypto.Digest{}, fmt.Errorf("%w: got entropy size %d, want %d", errPQKeyDerivation, len(entropy), pqKeyEntropySize)
	}

	input := make([]byte, 0, len(protocol.PostQuantumKey)+len(scheme)+len(entropy))
	input = append(input, string(protocol.PostQuantumKey)...)
	input = append(input, scheme[:]...)
	input = append(input, entropy...)

	return crypto.Hash(input), nil
}

func deriveFalcon1024SigningMaterial(seed []byte) (pqSigningMaterial, error) {
	signer, err := crypto.GenerateFalconSignerFromVarLenSeed(seed)
	if err != nil {
		return pqSigningMaterial{}, err
	}

	publicKey := slices.Clone(signer.PublicKey[:])
	privateKey := slices.Clone(signer.PrivateKey[:])
	public, err := canonicalPublicMaterialFromKey(protocol.PQSchemeFalcon1024, publicKey)
	if err != nil {
		return pqSigningMaterial{}, err
	}

	return pqSigningMaterial{
		public:  public,
		private: privateKey,
	}, nil
}

func falconPrivateKeyFromBytes(privateKey []byte) (crypto.FalconPrivateKey, error) {
	var sk crypto.FalconPrivateKey
	if len(privateKey) != len(sk) {
		return crypto.FalconPrivateKey{}, fmt.Errorf("%w: got private key size %d, want %d", errPQKeyMalformed, len(privateKey), len(sk))
	}
	copy(sk[:], privateKey)
	return sk, nil
}

func signFalcon1024Txn(privateKey []byte, txn transactions.Transaction) ([]byte, error) {
	sk, err := falconPrivateKeyFromBytes(privateKey)
	if err != nil {
		return nil, err
	}

	signer := crypto.FalconSigner{PrivateKey: sk}
	sig, err := signer.Sign(txn)
	if err != nil {
		return nil, err
	}
	return slices.Clone(sig), nil
}
