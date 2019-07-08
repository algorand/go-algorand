// Copyright (C) 2019 Algorand, Inc.
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

package basics

import (
	"bytes"
	"encoding/base32"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
)

type (
	// Address is a unique identifier corresponding to ownership of money
	Address crypto.Digest
)

const (
	checksumLength = 4
)

// GetChecksum returns the checksum as []byte
// Checksum in Algorand are the last 4 bytes of the shortAddress Hash. H(Address)[28:]
func (addr Address) GetChecksum() []byte {
	shortAddressHash := crypto.Hash(addr[:])
	checksum := shortAddressHash[len(shortAddressHash)-checksumLength:]
	return checksum
}

// GetUserAddress returns the human-readable, checksummed version of the address
func (addr Address) GetUserAddress() string {
	return addr.String()
}

// UnmarshalChecksumAddress tries to unmarshal the checksummed address string.
func UnmarshalChecksumAddress(address string) (Address, error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(address)
	if err != nil {
		return Address{}, fmt.Errorf("failed to decode address %s to base 32", address)
	}
	var short Address
	if len(decoded) < len(short) {
		return Address{}, fmt.Errorf("decoded bad addr: %s", address)
	}

	copy(short[:], decoded[:len(short)])
	incomingchecksum := decoded[len(decoded)-checksumLength:]

	calculatedchecksum := short.GetChecksum()
	isValid := bytes.Equal(incomingchecksum, calculatedchecksum)

	if !isValid {
		return Address{}, fmt.Errorf("address %s is malformed, checksum verification failed", address)
	}

	// Validate that we had a canonical string representation
	if short.String() != address {
		return Address{}, fmt.Errorf("address %s is non-canonical", address)
	}

	return short, nil
}

// String returns a string representation of Address
func (addr Address) String() string {
	var addrWithChecksum []byte
	addrWithChecksum = append(addr[:], addr.GetChecksum()...)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(addrWithChecksum)
}

// MarshalText returns the address string as an array of bytes
func (addr Address) MarshalText() ([]byte, error) {
	return []byte(addr.String()), nil
}

// UnmarshalText initializes the Address from an array of bytes.
func (addr *Address) UnmarshalText(text []byte) error {
	address, err := UnmarshalChecksumAddress(string(text))
	if err == nil {
		*addr = address
		return nil
	}
	return err
}
