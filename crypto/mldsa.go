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
	"crypto/mldsa"
	"fmt"
)

func init() {
	// Built against the FIPS 140-3 Go Cryptographic Module v1.0.0
	// (GOFIPS140=v1.0.0), crypto/mldsa is a stub that rejects every key and
	// signature, so the node would reject ML-DSA signatures the network
	// accepts, both in SaltedKeySigs and in the AVM's mldsa_verify. Refuse to
	// start instead. A working crypto/mldsa accepts any correctly sized
	// public key.
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		if _, err := mldsa.NewPublicKey(params, make([]byte, params.PublicKeySize())); err != nil {
			panic(fmt.Sprintf("crypto: %v", err))
		}
	}
}

// verifyMLDSA checks a pure ML-DSA signature of HashRep(message) with an
// empty context. Every correctly sized public key decodes, and its encoding
// is unique, so only the lengths can make a key malformed.
func verifyMLDSA(params mldsa.Parameters, message Hashable, publicKey, signature []byte) error {
	if len(publicKey) != params.PublicKeySize() {
		return fmt.Errorf("%v %w: public key size %d, want %d", params, ErrSigInvalid, len(publicKey), params.PublicKeySize())
	}
	if len(signature) != params.SignatureSize() {
		return fmt.Errorf("%v %w: signature size %d, want %d", params, ErrSigInvalid, len(signature), params.SignatureSize())
	}
	pk, err := mldsa.NewPublicKey(params, publicKey)
	if err != nil {
		return fmt.Errorf("%v %w: %w", params, ErrSigInvalid, err)
	}
	if err := mldsa.Verify(pk, HashRep(message), signature, nil); err != nil {
		return fmt.Errorf("%v %w: %w", params, ErrSigInvalid, err)
	}
	return nil
}
