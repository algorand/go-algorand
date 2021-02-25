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

package ledger

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
)

// Allocate creates kv storage for a given {addr, aidx, global}. It is called on app creation (global) or opting in (local)
// Allocate also registers an asset holding as created
func (cb *roundCowState) Allocate(addr basics.Address, cidx basics.CreatableIndex, ctype basics.CreatableType, global bool, space basics.StateSchema) error {
	if ctype == basics.AppCreatable {
		// Check that account is not already opted in
		aidx := basics.AppIndex(cidx)
		allocated, err := cb.allocated(addr, aidx, global)
		if err != nil {
			return err
		}
		if allocated {
			err = fmt.Errorf("cannot allocate storage, %v", errAlreadyStorage(addr, aidx, global))
			return err
		}

		lsd, err := cb.ensureStorageDelta(addr, aidx, global, allocAction)
		if err != nil {
			return err
		}

		lsd.action = allocAction
		lsd.maxCounts = &space

		return nil
	}

	if ctype == basics.AssetCreatable {
		cb.mods.Accts.SetHoldingDelta(addr, basics.AssetIndex(cidx), true)
		return nil
	}

	return fmt.Errorf("not supported creatable type %v", ctype)
}

// Deallocate clears storage for {addr, aidx, global}. It happens on app deletion (global) or closing out (local)
// Deallocate also registers an asset holding as deleted
func (cb *roundCowState) Deallocate(addr basics.Address, cidx basics.CreatableIndex, ctype basics.CreatableType, global bool) error {
	if ctype == basics.AppCreatable {
		// Check that account has allocated storage
		aidx := basics.AppIndex(cidx)
		allocated, err := cb.allocated(addr, aidx, global)
		if err != nil {
			return err
		}
		if !allocated {
			err = fmt.Errorf("cannot deallocate storage, %v", errNoStorage(addr, aidx, global))
			return err
		}

		lsd, err := cb.ensureStorageDelta(addr, aidx, global, deallocAction)
		if err != nil {
			return err
		}

		lsd.action = deallocAction
		lsd.counts = &basics.StateSchema{}
		lsd.maxCounts = &basics.StateSchema{}
		lsd.kvCow = make(stateDelta)
		return nil
	}

	if ctype == basics.AssetCreatable {
		cb.mods.Accts.SetHoldingDelta(addr, basics.AssetIndex(cidx), false)
		return nil
	}

	return fmt.Errorf("not supported creatable type %v", ctype)
}
