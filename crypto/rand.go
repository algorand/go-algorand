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
	"crypto/rand"
	"encoding/binary"

	"github.com/davidlazar/go-crypto/drbg"

	"github.com/algorand/go-algorand/logging"
)

// RNG represents a randomness source.  This could be either a system-wide
// randomness source (like what gets exposed by crypto/rand), or a PRNG that
// we use for testing.
type RNG interface {
	RandBytes([]byte)
}

// PRNG is a pseudo-random implementation of RNG, used for deterministic testing.
type PRNG struct {
	d *drbg.DRBG
}

// SystemRNG implements the RNG interface using the system-wide randomness
// source (from Go's crypto/rand).
var SystemRNG = &systemRNG{}

type systemRNG struct{}

// RandUint64 returns a random 64-bit unsigned integer
func RandUint64() uint64 {
	var eightbytes [8]byte
	_, err := rand.Read(eightbytes[:])
	if err != nil {
		logging.Base().Fatal("cannot read random number")
	}
	return binary.LittleEndian.Uint64(eightbytes[:])
}

// RandUint63 returns a random 64-bit unsigned integer which can be stored in a 64-bit signed integer without any data loss.
func RandUint63() uint64 {
	// use the RandUint64() function and clear the highest bit.
	return RandUint64() & ((1 << 63) - 1)
}

// RandBytes fills the provided structure with a set of random bytes
func RandBytes(buf []byte) {
	_, err := rand.Read(buf)
	if err != nil {
		logging.Base().Fatal("cannot read random bytes")
	}
}

// MakePRNG creates a new PRNG from an initial seed.  The implementation is
// based on HMAC_DRBG.  All random bytes from the PRNG will be determined by
// the initial seed value. Used by test code only.
func MakePRNG(seed []byte) *PRNG {
	return &PRNG{
		d: drbg.New(seed),
	}
}

// RandBytes implements the RNG interface for the PRNG. Used by test code only.
func (prng *PRNG) RandBytes(buf []byte) {
	n, err := prng.d.Read(buf)
	if err != nil {
		logging.Base().Panicf("PRNG.RandBytes: %v", err)
	}

	if n != len(buf) {
		logging.Base().Panicf("PRNG.RandBytes: short read: %v != %v", n, len(buf))
	}
}

// System-wide RNG
func (rng *systemRNG) RandBytes(buf []byte) {
	RandBytes(buf)
}
