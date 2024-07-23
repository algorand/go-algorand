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

package protocol

// A single Algorand chain can support multiple types of stateproofs,
// reflecting different hash functions, signature schemes, and frequency
// parameters.

// StateProofType identifies a particular configuration of state proofs.
type StateProofType uint64

const (
	// StateProofBasic is our initial state proof setup. using falcon keys and subset-sum hash
	StateProofBasic StateProofType = 0

	// NumStateProofTypes is the max number of types of state proofs
	// that we support.  This is used as an allocation bound for a map
	// containing different stateproof types in msgpack encoding.
	NumStateProofTypes int = 1
)

// SortStateProofType implements sorting by StateProofType keys for
// canonical encoding of maps in msgpack format.
//
//msgp:ignore SortStateProofType
//msgp:sort StateProofType SortStateProofType
type SortStateProofType []StateProofType

func (a SortStateProofType) Len() int           { return len(a) }
func (a SortStateProofType) Less(i, j int) bool { return a[i] < a[j] }
func (a SortStateProofType) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
