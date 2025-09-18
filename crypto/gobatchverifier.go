// Copyright (C) 2019-2025 Algorand, Inc.
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
	"bytes"

	"github.com/hdevalence/ed25519consensus"
)

// ed25519ConsensusVerifySingle performs single signature verification using ed25519consensus,
// with additional checks to reject non-canonical encodings and small-order public keys.
func ed25519ConsensusVerifySingle(publicKey [32]byte, message []byte, signature [64]byte) bool {
	// Check for non-canonical public key or R (first 32 bytes of signature), and reject small-order public keys
	if !isCanonicalPoint(publicKey) || !isCanonicalPoint([32]byte(signature[:32])) || hasSmallOrder(publicKey) {
		return false
	}

	return ed25519consensus.Verify(publicKey[:], message, signature[:])
}

type ed25519ConsensusVerifyEntry struct {
	msgHashRep   []byte
	publicKey    SignatureVerifier
	signature    Signature
	failedChecks bool
}

type ed25519ConsensusBatchVerifier struct {
	entries      []ed25519ConsensusVerifyEntry // used in VerifyWithFeedback to identify failed signatures
	failedChecks bool                          // true if any entry failed non-canonical or small-order checks
	bv           ed25519consensus.BatchVerifier
}

func makeEd25519ConsensusBatchVerifier(hint int) BatchVerifier {
	if hint <= 0 {
		hint = minBatchVerifierAlloc
	}
	return &ed25519ConsensusBatchVerifier{
		entries: make([]ed25519ConsensusVerifyEntry, 0, hint),
		bv:      ed25519consensus.NewPreallocatedBatchVerifier(hint),
	}
}

func (b *ed25519ConsensusBatchVerifier) EnqueueSignature(sigVerifier SignatureVerifier, message Hashable, sig Signature) {
	msgHashRep := HashRep(message)
	failedChecks := !isCanonicalPoint(sigVerifier) || !isCanonicalPoint([32]byte(sig[:32])) || hasSmallOrder(sigVerifier)

	entry := ed25519ConsensusVerifyEntry{
		msgHashRep:   msgHashRep,
		publicKey:    sigVerifier,
		signature:    sig,
		failedChecks: failedChecks,
	}
	b.entries = append(b.entries, entry)

	if failedChecks {
		b.failedChecks = true
	} else {
		b.bv.Add(sigVerifier[:], msgHashRep, sig[:])
	}
}

func (b *ed25519ConsensusBatchVerifier) GetNumberOfEnqueuedSignatures() int {
	return len(b.entries)
}

func (b *ed25519ConsensusBatchVerifier) Verify() error {
	if len(b.entries) == 0 {
		return nil
	}

	// Fail if any pre-checks failed or if batch verification fails
	if b.failedChecks || !b.bv.Verify() {
		return ErrBatchHasFailedSigs
	}
	return nil
}

func (b *ed25519ConsensusBatchVerifier) VerifyWithFeedback() (failed []bool, err error) {
	if len(b.entries) == 0 {
		return nil, nil
	}

	if !b.failedChecks && b.bv.Verify() {
		return nil, nil
	}

	failed = make([]bool, len(b.entries))
	for i := range b.entries {
		if b.entries[i].failedChecks {
			failed[i] = true
		} else {
			failed[i] = !ed25519ConsensusVerifySingle(b.entries[i].publicKey, b.entries[i].msgHashRep, b.entries[i].signature)
		}
	}

	return failed, ErrBatchHasFailedSigs
}

// Check that Y is canonical, using the succeed-fast algorithm from
// the "Taming the many EdDSAs" paper.
func isCanonicalY(p [32]byte) bool {
	if p[0] < 237 {
		return true
	}
	for i := 1; i < 31; i++ {
		if p[i] != 255 {
			return true
		}
	}
	return (p[31] | 128) != 255
}

// isCanonicalPoint is a variable-time check that returns true if the
// 32-byte ed25519 point encoding is canonical.
func isCanonicalPoint(p [32]byte) bool {
	if !isCanonicalY(p) {
		return false
	}

	// Test for the two cases with a non-canonical sign bit not caught by the
	// non-canonical y-coordinate check above. They are points number 9 and 10
	// from Table 1 of the "Taming the many EdDSAs" paper.
	if p == [32]byte{ // (−0, 1)
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
	} || p == [32]byte{ // (-0, 2^255-20)
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	} {
		return false
	}

	return true
}

// from libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c ge25519_has_small_order
var smallOrderPoints = [][32]byte{
	/* 0 (order 4) */ {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	/* 1 (order 1) */ {
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	/* 2707385501144840649318225287225658788936804267575313519463743609750303402022
	   (order 8) */{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4,
		0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6,
		0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
	/* 55188659117513257062467267217118295137698188065244968500265048394206261417927
	   (order 8) */{
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
		0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
		0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
	/* p-1 (order 2) */ {
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	/* p (=0, order 4) */ {
		0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	/* p+1 (=1, order 1) */ {
		0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

// hasSmallOrder checks if a point is in the small-order blacklist.
// Based on libsodium ge25519_has_small_order, but this version is variable-time.
func hasSmallOrder(p [32]byte) bool {
	for _, point := range smallOrderPoints {
		if !bytes.Equal(p[:31], point[:31]) {
			continue
		}
		// For the last byte, ignore the sign bit (bit 7)
		if (p[31] & 0x7f) == point[31] {
			return true
		}
	}
	return false
}
