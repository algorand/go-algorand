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

package agreement

import (
	"bytes"

	"github.com/algorand/go-algorand/data/basics"
)

// These types are defined to satisfy SortInterface used by

// SortAddress is re-exported from basics.Address since the interface is already defined there
//
//msgp:sort basics.Address SortAddress
type SortAddress = basics.SortAddress

// SortUint64 is re-exported from basics since the interface is already defined there
// canonical encoding of maps in msgpack format.
type SortUint64 = basics.SortUint64

// SortStep defines SortInterface used by msgp to consistently sort maps with this type as key.
//
//msgp:ignore SortStep
//msgp:sort step SortStep
type SortStep []step

func (a SortStep) Len() int           { return len(a) }
func (a SortStep) Less(i, j int) bool { return a[i] < a[j] }
func (a SortStep) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// SortPeriod defines SortInterface used by msgp to consistently sort maps with this type as key.
//
//msgp:ignore SortPeriod
//msgp:sort period SortPeriod
type SortPeriod []period

func (a SortPeriod) Len() int           { return len(a) }
func (a SortPeriod) Less(i, j int) bool { return a[i] < a[j] }
func (a SortPeriod) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// SortRound defines SortInterface used by msgp to consistently sort maps with this type as key.
// note, for type aliases the base type is used for the interface
//
//msgp:ignore SortRound
//msgp:sort basics.Round SortRound
type SortRound []basics.Round

func (a SortRound) Len() int           { return len(a) }
func (a SortRound) Less(i, j int) bool { return a[i] < a[j] }
func (a SortRound) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// SortProposalValue defines SortInterface used by msgp to consistently sort maps with this type as key.
//
//msgp:ignore SortProposalValue
//msgp:sort proposalValue SortProposalValue
type SortProposalValue []proposalValue

func (a SortProposalValue) Len() int { return len(a) }
func (a SortProposalValue) Less(i, j int) bool {
	if a[i].OriginalPeriod != a[j].OriginalPeriod {
		return a[i].OriginalPeriod < a[j].OriginalPeriod
	}
	cmp := bytes.Compare(a[i].OriginalProposer[:], a[j].OriginalProposer[:])
	if cmp != 0 {
		return cmp < 0
	}
	cmp = bytes.Compare(a[i].BlockDigest[:], a[j].BlockDigest[:])
	if cmp != 0 {
		return cmp < 0
	}
	cmp = bytes.Compare(a[i].EncodingDigest[:], a[j].EncodingDigest[:])
	return cmp < 0
}

func (a SortProposalValue) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
