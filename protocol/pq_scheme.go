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

// PQSchemeSize is the consensus byte length of a post-quantum signature scheme tag.
const PQSchemeSize = 2

// PQScheme is a 2-byte ASCII identifier of a post-quantum account authorization scheme.
// Conventionally, the first byte is the PQ-DSA family and the second byte is a version
// or variant identifier.
type PQScheme string

//msgp:allocbound PQScheme PQSchemeSize

// Supported post-quantum signature schemes.
const (
	// PQSchemeFalcon1024 - f1: Deterministic Falcon-1024.
	PQSchemeFalcon1024 PQScheme = "f1"
)
