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

package testing

import (
	"github.com/algorand/go-algorand/data/basics"
)

// MakeAccountData returns a AccountData with non-empty voting fields for online accounts
func MakeAccountData(status basics.Status, algos basics.MicroAlgos) basics.AccountData {
	ad := basics.AccountData{Status: status, MicroAlgos: algos}
	if status == basics.Online {
		ad.VoteFirstValid = 1
		ad.VoteLastValid = 100_000
	}
	return ad
}
