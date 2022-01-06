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

package ledgercore

import (
	"github.com/algorand/go-algorand/data/basics"
)

// AccountResource used to retrieve a generic resource information from the data tier
type AccountResource struct {
	CreatableIndex basics.CreatableIndex
	CreatableType  basics.CreatableType

	AssetParams   *basics.AssetParams
	AssetHolding  *basics.AssetHolding
	AppLocalState *basics.AppLocalState
	AppParams     *basics.AppParams
}

// AssignAccountData assigned the Asset/App params/holdings contained in the AccountResource
// to the given basics.AccountData, creating maps if necessary.
func (r *AccountResource) AssignAccountData(ad *basics.AccountData) {
	switch r.CreatableType {
	case basics.AssetCreatable:
		if r.AssetParams != nil {
			if ad.AssetParams == nil {
				ad.AssetParams = make(map[basics.AssetIndex]basics.AssetParams)
			}
			ad.AssetParams[basics.AssetIndex(r.CreatableIndex)] = *r.AssetParams
		}
		if r.AssetHolding != nil {
			if ad.Assets == nil {
				ad.Assets = make(map[basics.AssetIndex]basics.AssetHolding)
			}
			ad.Assets[basics.AssetIndex(r.CreatableIndex)] = *r.AssetHolding
		}
	case basics.AppCreatable:
		if r.AppParams != nil {
			if ad.AppParams == nil {
				ad.AppParams = make(map[basics.AppIndex]basics.AppParams)
			}
			ad.AppParams[basics.AppIndex(r.CreatableIndex)] = *r.AppParams
		}
		if r.AppLocalState != nil {
			if ad.AppLocalStates == nil {
				ad.AppLocalStates = make(map[basics.AppIndex]basics.AppLocalState)
			}
			ad.AppLocalStates[basics.AppIndex(r.CreatableIndex)] = *r.AppLocalState
		}
	}
}
