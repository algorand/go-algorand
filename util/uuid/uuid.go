// Copyright (C) 2019-2024 Algorand, Inc.
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

package uuid

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// New generates a new random UUID string.
// The UUID string generated using this method conform to
// version 4, variant 1.
func New() string {
	var buffer [16]byte
	_, err := rand.Read(buffer[:])
	if err != nil {
		panic(fmt.Errorf("unable to randomize buffer in uuid.New() : %w", err))
	}
	// select version 4.
	buffer[6] = 0x40 | (buffer[6] & 0xf)
	// select variant 1
	buffer[8] = 0x80 | (buffer[8] & 0x3f)
	return hex.EncodeToString(buffer[:4]) + "-" +
		hex.EncodeToString(buffer[4:6]) + "-" +
		hex.EncodeToString(buffer[6:8]) + "-" +
		hex.EncodeToString(buffer[8:10]) + "-" +
		hex.EncodeToString(buffer[10:])
}
