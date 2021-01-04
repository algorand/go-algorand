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

package agreementtest

import (
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
)

// SimpleKeyManager provides a simple implementation of a KeyManager.
type SimpleKeyManager []account.Participation

// Keys implements KeyManager.Keys.
func (m SimpleKeyManager) Keys() []account.Participation {
	var km []account.Participation
	for _, acc := range m {
		km = append(km, acc)
	}
	return km
}

// HasLiveKeys returns true if we have any Participation
// keys valid for the specified round range (inclusive)
func (m SimpleKeyManager) HasLiveKeys(from, to basics.Round) bool {
	for _, acc := range m {
		if acc.OverlapsInterval(from, to) {
			return true
		}
	}
	return false
}

// DeleteOldKeys implements KeyManager.DeleteOldKeys.
func (m SimpleKeyManager) DeleteOldKeys(r basics.Round) {
	// for _, acc := range m {
	// acc.DeleteOldKeys(r)
	// }
}
