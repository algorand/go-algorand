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

// CloneAssetHoldings allocates the map of basics.AssetHolding if it is nil, and return a copy.
func CloneAssetHoldings(m map[basics.AssetIndex]basics.AssetHolding) map[basics.AssetIndex]basics.AssetHolding {
	res := make(map[basics.AssetIndex]basics.AssetHolding, len(m))
	for id, val := range m {
		res[id] = val
	}
	return res
}

// CloneAssetParams allocates the map of basics.AssetParams if it is nil, and return a copy.
func CloneAssetParams(m map[basics.AssetIndex]basics.AssetParams) map[basics.AssetIndex]basics.AssetParams {
	res := make(map[basics.AssetIndex]basics.AssetParams, len(m))
	for id, val := range m {
		res[id] = val
	}
	return res
}

// CloneAppParams allocates the map of basics.AppParams if it is nil, and return a copy. We do *not*
// call clone on each basics.AppParams -- callers must do that for any values where
// they intend to modify a contained reference type.
func CloneAppParams(m map[basics.AppIndex]basics.AppParams) map[basics.AppIndex]basics.AppParams {
	res := make(map[basics.AppIndex]basics.AppParams, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}

// CloneAppLocalStates allocates the map of LocalStates if it is nil, and return a copy. We do *not*
// call clone on each AppLocalState -- callers must do that for any values
// where they intend to modify a contained reference type.
func CloneAppLocalStates(m map[basics.AppIndex]basics.AppLocalState) map[basics.AppIndex]basics.AppLocalState {
	res := make(map[basics.AppIndex]basics.AppLocalState, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}
