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

	AssetParam    *basics.AssetParams
	AssetHolding  *basics.AssetHolding
	AppLocalState *basics.AppLocalState
	AppParams     *basics.AppParams
}
