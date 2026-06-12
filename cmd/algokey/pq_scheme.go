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
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

var errPQPrivateKeyMismatch = errors.New("pq public/private key pair mismatch")

// pqSchemeOps holds the signing-side, private-key operations for one PQ
// scheme. The consensus-relevant scheme behavior (public key validation,
// signature verification, sizes, fees) lives in the basics PQ scheme registry;
// see basics.LookupPQScheme.
type pqSchemeOps struct {
	displayName     string
	privateKeySize  uint64
	generate        func(crypto.RNG) (pqKeyMaterial, error)
	signTxn         func([]byte, transactions.Transaction) ([]byte, error)
	validateKeyPair func([]byte, []byte) error
}

var pqSchemeOpsByScheme = map[protocol.PQScheme]pqSchemeOps{
	protocol.PQSchemeFalcon1024: {
		displayName:     "Falcon-1024",
		privateKeySize:  crypto.FalconPrivateKeySize,
		generate:        generateFalcon1024Key,
		signTxn:         signFalcon1024Txn,
		validateKeyPair: validateFalcon1024KeyPair,
	},
}

func lookupPQScheme(scheme protocol.PQScheme) (basics.PQSchemeSpec, error) {
	spec, ok := basics.LookupPQScheme(scheme)
	if !ok {
		return basics.PQSchemeSpec{}, fmt.Errorf("%w: %q", basics.ErrPQSchemeNotSupported, scheme)
	}
	return spec, nil
}

func opsForPQScheme(scheme protocol.PQScheme) (pqSchemeOps, error) {
	ops, ok := pqSchemeOpsByScheme[scheme]
	if !ok {
		return pqSchemeOps{}, fmt.Errorf("%w: %q", basics.ErrPQSchemeNotSupported, scheme)
	}
	return ops, nil
}

func generateFalcon1024Key(rng crypto.RNG) (pqKeyMaterial, error) {
	var seed crypto.FalconSeed
	rng.RandBytes(seed[:])
	defer zeroBytes(seed[:])

	signer, err := crypto.GenerateFalconSigner(seed)
	if err != nil {
		return pqKeyMaterial{}, err
	}
	defer zeroBytes(signer.PrivateKey[:])

	publicKey := append([]byte(nil), signer.PublicKey[:]...)
	privateKey := append([]byte(nil), signer.PrivateKey[:]...)
	salt, addr, err := basics.CanonicalPQAddressSalt(protocol.PQSchemeFalcon1024, publicKey)
	if err != nil {
		zeroBytes(privateKey)
		return pqKeyMaterial{}, err
	}

	return pqKeyMaterial{
		scheme:           protocol.PQSchemeFalcon1024,
		publicKey:        publicKey,
		privateKey:       privateKey,
		canonicalSalt:    salt,
		canonicalAddress: addr,
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
	defer zeroBytes(sk[:])

	signer := crypto.FalconSigner{PrivateKey: sk}
	defer zeroBytes(signer.PrivateKey[:])
	sig, err := signer.Sign(txn)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
}

func validateFalcon1024KeyPair(publicKey []byte, privateKey []byte) error {
	pk, err := crypto.FalconPublicKeyFromBytes(publicKey)
	if err != nil {
		return err
	}
	sk, err := falconPrivateKeyFromBytes(privateKey)
	if err != nil {
		return err
	}
	defer zeroBytes(sk[:])

	signer := crypto.FalconSigner{
		PublicKey:  pk,
		PrivateKey: sk,
	}
	defer zeroBytes(signer.PrivateKey[:])
	challenge := []byte("algokey-pq-keyfile-self-check")
	sig, err := signer.SignBytes(challenge)
	if err != nil {
		return err
	}

	verifier := crypto.FalconVerifier{PublicKey: pk}
	if err = verifier.VerifyBytes(challenge, sig); err != nil {
		return fmt.Errorf("%w: %w", errPQPrivateKeyMismatch, err)
	}
	return nil
}
