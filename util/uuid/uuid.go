// Copyright (C) 2019-2022 Algorand, Inc.
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
	"fmt"
)

// New generates a new random UUID string.
// The UUID string generated using this method does not conform to the UUID spec and
// contains completly random bytes.
func New() string {
	var buffer [16]byte
	rand.Read(buffer[:])
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", int64(buffer[0])+int64(buffer[1])<<8+int64(buffer[2])<<16+int64(buffer[3])<<24,
		int64(buffer[4])+int64(buffer[5])<<8,
		int64(buffer[6])+int64(buffer[7])<<8,
		int64(buffer[8])+int64(buffer[9])<<8,
		int64(buffer[10])+int64(buffer[11])<<8+int64(buffer[12])<<16+int64(buffer[13])<<24+int64(buffer[14])<<32+int64(buffer[15])<<40)
}
