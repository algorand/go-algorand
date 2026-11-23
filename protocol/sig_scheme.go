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

// SigScheme is a 2-byte ASCII identifier of an account authorization scheme.
// Conventionally, the first byte identifies the DSA family, and the second
// identifies the version or variant.
//
//msgp:test ignore SigScheme
type SigScheme [2]byte

func (s SigScheme) String() string {
	return string(s[:])
}

// Supported account authorization schemes.
var (
	// SigSchemeEd25519 - ed: classical Ed25519 with a salted-address profile.
	SigSchemeEd25519 = SigScheme{'e', 'd'}

	// SigSchemeFalcon1024 - f1: Falcon-1024 using a deterministic signing profile.
	SigSchemeFalcon1024 = SigScheme{'f', '1'}

	// SigSchemeFalcon512 - f5: Falcon-512 using a deterministic signing profile.
	SigSchemeFalcon512 = SigScheme{'f', '5'}

	// SigSchemeLogicSig - ls: a LogicSig account. The program bytes take the place
	// of the public key, so the account address commits to the program, and the
	// salt selects among the addresses a single program can have. Authorization is
	// the program's own evaluation rather than a signature check.
	SigSchemeLogicSig = SigScheme{'l', 's'}
)
