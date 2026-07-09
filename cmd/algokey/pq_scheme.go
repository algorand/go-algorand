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
	"strings"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const pqSchemeFalcon1024Name = "falcon-1024"

// pqSchemeOps holds the signing-side, private-key operations for one PQ
// scheme. The consensus-relevant scheme behavior (signature verification,
// sizes) lives in crypto.LookupPQScheme, and fee policy in
// config.ConsensusParams.PQSchemeFeeContribution.
type pqSchemeOps interface {
	deriveSigning(seed crypto.Digest) (pqSigningMaterial, error)
	signTxn(privateKey []byte, txn transactions.Transaction) ([]byte, error)
	publicKeySize() uint64
}

var pqSchemeOpsByScheme = map[protocol.PQScheme]pqSchemeOps{
	protocol.PQSchemeFalcon1024: falcon1024Ops{},
}

type falcon1024Ops struct{}

func parsePQScheme(value string) (protocol.PQScheme, error) {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, pqSchemeFalcon1024Name) {
		return protocol.PQSchemeFalcon1024, nil
	}

	var scheme protocol.PQScheme
	if len(value) != len(scheme) {
		return protocol.PQScheme{}, fmt.Errorf("%w: %q", crypto.ErrPQSchemeNotSupported, value)
	}
	copy(scheme[:], value)
	return scheme, nil
}

func formatPQScheme(scheme protocol.PQScheme) string {
	if scheme == protocol.PQSchemeFalcon1024 {
		return pqSchemeFalcon1024Name
	}
	return scheme.String()
}

func generatePQSigningMaterial(scheme protocol.PQScheme, rng crypto.RNG) (crypto.Seed, pqSigningMaterial, error) {
	var entropy crypto.Seed
	rng.RandBytes(entropy[:])

	signing, err := derivePQSigningMaterialFromEntropy(scheme, entropy)
	return entropy, signing, err
}

func derivePQSigningMaterialFromEntropy(scheme protocol.PQScheme, entropy crypto.Seed) (pqSigningMaterial, error) {
	ops, ok := pqSchemeOpsByScheme[scheme]
	if !ok {
		return pqSigningMaterial{}, fmt.Errorf("%w: %q", crypto.ErrPQSchemeNotSupported, scheme)
	}

	seed := derivePQKeySeed(scheme, entropy)
	return ops.deriveSigning(seed)
}

// derivePQKeySeed maps mnemonic-sized entropy to a scheme-specific PQ keygen
// seed: SHA512_256(PQK || scheme[2] || entropy[32]).
func derivePQKeySeed(scheme protocol.PQScheme, entropy crypto.Seed) crypto.Digest {
	input := make([]byte, 0, len(protocol.PostQuantumKey)+len(scheme)+len(entropy))
	input = append(input, string(protocol.PostQuantumKey)...)
	input = append(input, scheme[:]...)
	input = append(input, entropy[:]...)

	return crypto.Hash(input)
}

func (falcon1024Ops) deriveSigning(seed crypto.Digest) (pqSigningMaterial, error) {
	signer, err := crypto.GenerateFalconSigner(crypto.FalconSeed(seed))
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
		Public:     public,
		PrivateKey: privateKey,
	}, nil
}

func (falcon1024Ops) publicKeySize() uint64 { return crypto.FalconPublicKeySize }

func (falcon1024Ops) signTxn(privateKey []byte, txn transactions.Transaction) ([]byte, error) {
	var sk crypto.FalconPrivateKey
	if len(privateKey) != len(sk) {
		return nil, fmt.Errorf("%w: got private key size %d, want %d", errPQKeyMalformed, len(privateKey), len(sk))
	}
	copy(sk[:], privateKey)

	signer := crypto.FalconSigner{PrivateKey: sk}
	return signer.Sign(txn)
}
