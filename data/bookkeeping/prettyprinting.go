// Copyright (C) 2019-2021 Algorand, Inc.
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

package bookkeeping

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
)

func (b BlockHash) String() string {
	return fmt.Sprintf("blk-%v", crypto.Digest(b))
}

// MarshalText returns the BlockHash string as an array of bytes
func (b BlockHash) MarshalText() ([]byte, error) {
	return []byte(b.String()), nil
}

// UnmarshalText initializes the BlockHash from an array of bytes.
func (b *BlockHash) UnmarshalText(text []byte) error {
	if len(text) < 4 || !bytes.Equal(text[0:4], []byte("blk-")) {
		return errors.New("unrecognized blockhash format")
	}
	d, err := crypto.DigestFromString(string(text[4:]))
	*b = BlockHash(d)
	return err
}

func (b Block) String() string {
	return fmt.Sprintf("Block(hash = %v, %v txns)", b.Hash(), len(b.Payset))
}
