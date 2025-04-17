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

package vpack

const defaultCompressCapacity = 1024

type compressWriter interface {
	writeVaruint(fieldNameIdx uint8, b []byte) error
	writeBin32(fieldNameIdx uint8, b [32]byte)
	writeBin64(fieldNameIdx uint8, b [64]byte)
	writeBin80(fieldNameIdx uint8, b [80]byte)
}
