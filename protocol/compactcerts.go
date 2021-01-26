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

package protocol

// A single Algorand chain can support multiple types of compact certs,
// reflecting different hash functions, signature schemes, and frequency
// parameters.

// CompactCertType identifies a particular configuration of compact certs.
type CompactCertType uint64

const (
	// CompactCertBasic is our initial compact cert setup, using Ed25519
	// ephemeral-key signatures and SHA512/256 hashes.
	CompactCertBasic CompactCertType = 0

	// NumCompactCertTypes is the max number of types of compact certs
	// that we support.  This is used as an allocation bound for a map
	// containing different compact cert types in msgpack encoding.
	NumCompactCertTypes int = 1
)

// SortCompactCertType implements sorting by CompactCertType keys for
// canonical encoding of maps in msgpack format.
//msgp:ignore SortCompactCertType
//msgp:sort CompactCertType SortCompactCertType
type SortCompactCertType []CompactCertType

func (a SortCompactCertType) Len() int           { return len(a) }
func (a SortCompactCertType) Less(i, j int) bool { return a[i] < a[j] }
func (a SortCompactCertType) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
