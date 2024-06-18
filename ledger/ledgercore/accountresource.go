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

package ledgercore

import (
	"github.com/algorand/go-algorand/data/basics"
)

// AccountResource used to retrieve a generic resource information from the data tier
type AccountResource struct {
	AssetParams   *basics.AssetParams
	AssetHolding  *basics.AssetHolding
	AppLocalState *basics.AppLocalState
	AppParams     *basics.AppParams
}

// AssetResource used to retrieve a generic asset resource information from the data tier
type AssetResource struct {
	AssetParams  *basics.AssetParams
	AssetHolding *basics.AssetHolding
}

// AssetResourceWithIDs is used to retrieve a asset resource information from the data tier,
// inclusive of the asset ID and creator address
type AssetResourceWithIDs struct {
	AssetResource
	AssetID basics.AssetIndex
	Creator basics.Address
}

// AppResource used to retrieve a generic app resource information from the data tier
type AppResource struct {
	AppLocalState *basics.AppLocalState
	AppParams     *basics.AppParams
}

// AssignAccountResourceToAccountData assigns the Asset/App params/holdings contained
// in the AccountResource to the given basics.AccountData, creating maps if necessary.
// Returns true if the AccountResource contained a new or updated resource,
// and false if the AccountResource contained no changes (indicating the resource was deleted).
func AssignAccountResourceToAccountData(cindex basics.CreatableIndex, resource AccountResource, ad *basics.AccountData) (assigned bool) {
	if resource.AssetParams != nil {
		if ad.AssetParams == nil {
			ad.AssetParams = make(map[basics.AssetIndex]basics.AssetParams)
		}
		ad.AssetParams[basics.AssetIndex(cindex)] = *resource.AssetParams
		assigned = true
	}
	if resource.AssetHolding != nil {
		if ad.Assets == nil {
			ad.Assets = make(map[basics.AssetIndex]basics.AssetHolding)
		}
		ad.Assets[basics.AssetIndex(cindex)] = *resource.AssetHolding
		assigned = true
	}
	if resource.AppParams != nil {
		if ad.AppParams == nil {
			ad.AppParams = make(map[basics.AppIndex]basics.AppParams)
		}
		ad.AppParams[basics.AppIndex(cindex)] = *resource.AppParams
		assigned = true
	}
	if resource.AppLocalState != nil {
		if ad.AppLocalStates == nil {
			ad.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
		}
		ad.AppLocalStates[basics.AppIndex(cindex)] = *resource.AppLocalState
		assigned = true
	}
	return
}
