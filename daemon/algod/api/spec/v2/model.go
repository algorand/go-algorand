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

// Package v2 defines models exposed by algod rest api
package v2

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// AccountAssetModel is returned by AccountAssetInformation when msgpack format is specified
type AccountAssetModel struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	AssetParams  *basics.AssetParams  `codec:"asset-params"`
	AssetHolding *basics.AssetHolding `codec:"asset-holding"`
}

// AccountApplicationModel is returned by AccountApplicationInformation when msgpack format is specified
type AccountApplicationModel struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	AppLocalState *basics.AppLocalState `codec:"app-local-state"`
	AppParams     *basics.AppParams     `codec:"app-params"`
}

// AssetResourceToAccountAssetModel converts AssetResource to AccountAssetModel
func AssetResourceToAccountAssetModel(resource ledgercore.AssetResource) AccountAssetModel {
	return AccountAssetModel{
		AssetParams:  resource.AssetParams,
		AssetHolding: resource.AssetHolding,
	}
}

// AppResourceToAccountApplicationModel converts AppResource to AccountApplicationModel
func AppResourceToAccountApplicationModel(resource ledgercore.AppResource) AccountApplicationModel {
	return AccountApplicationModel{
		AppParams:     resource.AppParams,
		AppLocalState: resource.AppLocalState,
	}
}
