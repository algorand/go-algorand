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

package main

import (
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

// DigestChecksummed is an encoding of a crypto.Digest using
// basics.ChecksumAddress.
type DigestChecksummed crypto.Digest

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (d *DigestChecksummed) UnmarshalText(text []byte) error {
	res, err := basics.UnmarshalChecksumAddress(string(text))
	if err != nil {
		return err
	}

	*d = DigestChecksummed(res)
	return nil
}

// MarshalText implements the encoding.TextMarshaler interface
func (d DigestChecksummed) MarshalText() (text []byte, err error) {
	checksumAddr := basics.Address(d)
	return []byte(checksumAddr.String()), nil
}
