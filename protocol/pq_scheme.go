// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

// PQScheme is a 2-byte ASCII identifier of a scheme for deriving and authorizing
// a post-quantum account address. For a scheme built on a PQ-DSA, the first byte
// is conventionally the DSA family and the second a version or variant
// identifier. Not every scheme is a DSA: see PQSchemeLogicSig.
//
//msgp:test ignore PQScheme
type PQScheme [2]byte

func (s PQScheme) String() string {
	return string(s[:])
}

// Supported post-quantum account schemes.
var (
	// PQSchemeFalcon1024 - f1: Falcon-1024 using a deterministic signing profile.
	PQSchemeFalcon1024 = PQScheme{'f', '1'}

	// PQSchemeFalcon512 - f2: Falcon-512 using a deterministic signing profile.
	PQSchemeFalcon512 = PQScheme{'f', '2'} // reserved, not used

	// PQSchemeLogicSig - ls: a LogicSig account. The program bytes take the place
	// of the public key, so the account address commits to the program, and the
	// salt selects among the addresses a single program can have. Authorization is
	// the program's own evaluation rather than a signature check, so this scheme
	// has no crypto.PQVerifier and never appears in crypto.LookupPQScheme.
	PQSchemeLogicSig = PQScheme{'l', 's'}
)
