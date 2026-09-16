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

// PQScheme is a 2-byte ASCII identifier of an account authorization scheme.
// Conventionally, the first byte identifies the DSA family, and the second
// identifies the version or variant.
//
//msgp:test ignore PQScheme
type PQScheme [2]byte

func (s PQScheme) String() string {
	return string(s[:])
}

// Supported account authorization schemes.
var (
	// PQSchemeEd25519 - ed: classical Ed25519 with a hashed-address profile.
	PQSchemeEd25519 = PQScheme{'e', 'd'}

	// PQSchemeFalcon1024 - f1: Falcon-1024 using a deterministic signing profile.
	PQSchemeFalcon1024 = PQScheme{'f', '1'}

	// PQSchemeFalcon512 - f5: Falcon-512 using a deterministic signing profile.
	PQSchemeFalcon512 = PQScheme{'f', '5'}
)
