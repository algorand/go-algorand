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

package config

import (
	"github.com/algorand/go-algorand/data/basics"
)

/* Functions that simplify the ways that ConsensusParams affect minimum balance
   requirements. */

// MinBalanceReq computes the minimum balance requirements for an account based on
// some consensus parameters. MinBalance should correspond roughly to how much
// storage the account is allowed to store on disk.
func (proto *ConsensusParams) MinBalanceReq(u basics.AccountData) basics.MicroAlgos {
	return MinBalance(
		proto,
		uint64(len(u.Assets)),
		u.TotalAppSchema,
		uint64(len(u.AppParams)), uint64(len(u.AppLocalStates)),
		uint64(u.TotalExtraAppPages),
		u.TotalBoxes, u.TotalBoxBytes,
	)
}

// MinBalance computes the minimum balance requirements for an account based on
// some consensus parameters. MinBalance should correspond roughly to how much
// storage the account is allowed to store on disk.
func MinBalance(
	proto *ConsensusParams,
	totalAssets uint64,
	totalAppSchema basics.StateSchema,
	totalAppParams uint64, totalAppLocalStates uint64,
	totalExtraAppPages uint64,
	totalBoxes uint64, totalBoxBytes uint64,
) basics.MicroAlgos {
	var min uint64

	// First, base MinBalance
	min = proto.MinBalance

	// MinBalance for each Asset
	assetCost := basics.MulSaturate(proto.MinBalance, totalAssets)
	min = basics.AddSaturate(min, assetCost)

	// Base MinBalance for each created application
	appCreationCost := basics.MulSaturate(proto.AppFlatParamsMinBalance, totalAppParams)
	min = basics.AddSaturate(min, appCreationCost)

	// Base MinBalance for each opted in application
	appOptInCost := basics.MulSaturate(proto.AppFlatOptInMinBalance, totalAppLocalStates)
	min = basics.AddSaturate(min, appOptInCost)

	// MinBalance for state usage measured by LocalStateSchemas and
	// GlobalStateSchemas
	schemaCost := proto.MinBalanceForSchema(totalAppSchema)
	min = basics.AddSaturate(min, schemaCost.Raw)

	// MinBalance for each extra app program page
	extraAppProgramLenCost := basics.MulSaturate(proto.AppFlatParamsMinBalance, totalExtraAppPages)
	min = basics.AddSaturate(min, extraAppProgramLenCost)

	// Base MinBalance for each created box
	boxBaseCost := basics.MulSaturate(proto.BoxFlatMinBalance, totalBoxes)
	min = basics.AddSaturate(min, boxBaseCost)

	// Per byte MinBalance for boxes
	boxByteCost := basics.MulSaturate(proto.BoxByteMinBalance, totalBoxBytes)
	min = basics.AddSaturate(min, boxByteCost)

	return basics.MicroAlgos{Raw: min}
}

// MinBalanceForSchema computes the minimum balance requirement for a
// StateSchema based on the consensus parameters
func (proto *ConsensusParams) MinBalanceForSchema(sm basics.StateSchema) basics.MicroAlgos {
	// Flat cost for each key/value pair
	flatCost := basics.MulSaturate(proto.SchemaMinBalancePerEntry, sm.NumEntries())

	// Cost for uints
	uintCost := basics.MulSaturate(proto.SchemaUintMinBalance, sm.NumUint)

	// Cost for byte slices
	bytesCost := basics.MulSaturate(proto.SchemaBytesMinBalance, sm.NumByteSlice)

	// Sum the separate costs
	var min uint64
	min = basics.AddSaturate(min, flatCost)
	min = basics.AddSaturate(min, uintCost)
	min = basics.AddSaturate(min, bytesCost)

	return basics.MicroAlgos{Raw: min}
}
