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

package eval

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

func (cs *roundCowState) AllocateAsset(addr basics.Address, index basics.AssetIndex, global bool) error {
	if global {
		cs.mods.AddCreatable(
			basics.CreatableIndex(index),
			ledgercore.ModifiedCreatable{
				Ctype:   basics.AssetCreatable,
				Creator: addr,
				Created: true,
			},
		)
	}
	return nil
}

func (cs *roundCowState) DeallocateAsset(addr basics.Address, index basics.AssetIndex, global bool) error {
	if global {
		cs.mods.AddCreatable(
			basics.CreatableIndex(index),
			ledgercore.ModifiedCreatable{
				Ctype:   basics.AssetCreatable,
				Creator: addr,
				Created: false,
			},
		)
	}
	return nil
}
