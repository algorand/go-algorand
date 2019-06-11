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

package client

import (
	"encoding/base64"

	"github.com/algorand/go-algorand/data/basics"
)

// BytesBase64 is a base64-encoded binary blob (i.e., []byte), for
// use with text encodings like JSON.
type BytesBase64 []byte

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (b *BytesBase64) UnmarshalText(text []byte) error {
	res, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	*b = BytesBase64(res)
	return nil
}

// MarshalText implements the encoding.TextMarshaler interface
func (b BytesBase64) MarshalText() (text []byte, err error) {
	return []byte(base64.StdEncoding.EncodeToString(b[:])), nil
}

// ChecksumAddress is a checksummed address, for use with text encodings
// like JSON.
type ChecksumAddress basics.Address

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (a *ChecksumAddress) UnmarshalText(text []byte) error {
	addr, err := basics.UnmarshalChecksumAddress(string(text))
	if err != nil {
		return err
	}

	*a = ChecksumAddress(addr)
	return nil
}

// MarshalText implements the encoding.TextMarshaler interface
func (a ChecksumAddress) MarshalText() (text []byte, err error) {
	addr := basics.Address(a)
	return []byte(addr.GetChecksumAddress().String()), nil
}
