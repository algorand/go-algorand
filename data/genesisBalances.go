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

package data

import (
	"time"

	"github.com/algorand/go-algorand/data/basics"
)

// GenesisBalances contains the information needed to generate a new ledger
type GenesisBalances struct {
	balances    map[basics.Address]basics.AccountData
	feeSink     basics.Address
	rewardsPool basics.Address
	timestamp   int64
}

// MakeGenesisBalances returns the information needed to bootstrap the ledger based on the current time
func MakeGenesisBalances(balances map[basics.Address]basics.AccountData, feeSink, rewardsPool basics.Address) GenesisBalances {
	return MakeTimestampedGenesisBalances(balances, feeSink, rewardsPool, time.Now().Unix())
}

// MakeTimestampedGenesisBalances returns the information needed to bootstrap the ledger based on a given time
func MakeTimestampedGenesisBalances(balances map[basics.Address]basics.AccountData, feeSink, rewardsPool basics.Address, timestamp int64) GenesisBalances {
	return GenesisBalances{balances: balances, feeSink: feeSink, rewardsPool: rewardsPool, timestamp: timestamp}
}
