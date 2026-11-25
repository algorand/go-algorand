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

package crypto

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/algorand/go-algorand/crypto/secp256k1"
)

// Sizes of secp256k1 and secp256r1 keys and signatures.
const (
	// ECDSAPrivateKeySize is the size of a private key: the scalar, big-endian.
	ECDSAPrivateKeySize = 32
	// ECDSAPublicKeySize is the size of a public key in SEC 1 compressed form.
	ECDSAPublicKeySize = 33
	// ECDSASignatureSize is the size of a signature: R then S, each 32 bytes,
	// big-endian.
	ECDSASignatureSize = 64
)

var secp256r1 = elliptic.P256()
var secp256r1HalfOrder = new(big.Int).Rsh(secp256r1.Params().N, 1)

// verifySecp256k1 checks an ECDSA signature of SHA-256(HashRep(message)) on
// secp256k1. publicKey is a SEC 1 compressed point. signature is R || S in
// lower-S form: S is at most half the group order.
func verifySecp256k1(message Hashable, publicKey, signature []byte) error {
	// secp256k1.VerifySignature would take a 65-byte uncompressed key too.
	if len(publicKey) != ECDSAPublicKeySize {
		return fmt.Errorf("secp256k1 %w: public key size %d, want %d", ErrSigInvalid, len(publicKey), ECDSAPublicKeySize)
	}
	digest := sha256.Sum256(HashRep(message))
	// VerifySignature rejects a signature of another size, or with S above
	// half the order.
	if !secp256k1.VerifySignature(publicKey, digest[:], signature) {
		return fmt.Errorf("secp256k1 %w", ErrSigInvalid)
	}
	return nil
}

// verifySecp256r1 is verifySecp256k1 on secp256r1 (NIST P-256).
func verifySecp256r1(message Hashable, publicKey, signature []byte) error {
	// R and S are told apart by position, so the size has to be exact.
	if len(signature) != ECDSASignatureSize {
		return fmt.Errorf("secp256r1 %w: signature size %d, want %d", ErrSigInvalid, len(signature), ECDSASignatureSize)
	}
	r := new(big.Int).SetBytes(signature[:ECDSASignatureSize/2])
	s := new(big.Int).SetBytes(signature[ECDSASignatureSize/2:])
	// ecdsa.Verify accepts S above half the order too.
	if s.Cmp(secp256r1HalfOrder) > 0 {
		return fmt.Errorf("secp256r1 %w: signature is not in lower-S form", ErrSigInvalid)
	}
	// UnmarshalCompressed rejects a key of another size.
	x, y := elliptic.UnmarshalCompressed(secp256r1, publicKey)
	if x == nil {
		return fmt.Errorf("secp256r1 %w: malformed public key", ErrSigInvalid)
	}
	digest := sha256.Sum256(HashRep(message))
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: secp256r1, X: x, Y: y}, digest[:], r, s) {
		return fmt.Errorf("secp256r1 %w", ErrSigInvalid)
	}
	return nil
}

// Secp256k1PublicKey returns the compressed public key of a secp256k1 private
// key, a scalar from 1 to the group order minus 1.
func Secp256k1PublicKey(privateKey []byte) ([]byte, error) {
	var x, y *big.Int
	if len(privateKey) == ECDSAPrivateKeySize {
		x, y = secp256k1.S256().ScalarBaseMult(privateKey)
	}
	if x == nil {
		return nil, fmt.Errorf("secp256k1: %w", secp256k1.ErrInvalidKey)
	}
	return secp256k1.CompressPubkey(x, y), nil
}

// SignSecp256k1 signs message as Secp256k1SchemeVerifier expects. The signature
// is deterministic (RFC 6979).
func SignSecp256k1(privateKey []byte, message Hashable) ([]byte, error) {
	digest := sha256.Sum256(HashRep(message))
	sig, err := secp256k1.Sign(digest[:], privateKey)
	if err != nil {
		return nil, fmt.Errorf("secp256k1: %w", err)
	}
	// Sign appends a recovery id, which the scheme does not carry.
	return sig[:ECDSASignatureSize], nil
}

// Secp256r1PublicKey returns the compressed public key of a secp256r1 private
// key, a scalar from 1 to the group order minus 1.
func Secp256r1PublicKey(privateKey []byte) ([]byte, error) {
	key, err := ecdsa.ParseRawPrivateKey(secp256r1, privateKey)
	if err != nil {
		return nil, fmt.Errorf("secp256r1: %w", err)
	}
	return elliptic.MarshalCompressed(secp256r1, key.X, key.Y), nil
}

// SignSecp256r1 signs message as Secp256r1SchemeVerifier expects. The signature
// is deterministic (RFC 6979).
func SignSecp256r1(privateKey []byte, message Hashable) ([]byte, error) {
	key, err := ecdsa.ParseRawPrivateKey(secp256r1, privateKey)
	if err != nil {
		return nil, fmt.Errorf("secp256r1: %w", err)
	}
	digest := sha256.Sum256(HashRep(message))
	// A nil random source selects RFC 6979.
	der, err := key.Sign(nil, digest[:], stdcrypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("secp256r1: %w", err)
	}
	var sig struct{ R, S *big.Int }
	if _, err = asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("secp256r1: %w", err)
	}
	if sig.S.Cmp(secp256r1HalfOrder) > 0 {
		sig.S.Sub(secp256r1.Params().N, sig.S)
	}
	signature := make([]byte, ECDSASignatureSize)
	sig.R.FillBytes(signature[:ECDSASignatureSize/2])
	sig.S.FillBytes(signature[ECDSASignatureSize/2:])
	return signature, nil
}
