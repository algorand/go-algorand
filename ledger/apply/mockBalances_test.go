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

package apply

import (
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

type mockBalances struct {
	protocol.ConsensusVersion
	b map[basics.Address]basics.AccountData
}

// makeMockBalances takes a ConsensusVersion and returns a mocked balances with an Address to AccountData map
func makeMockBalances(cv protocol.ConsensusVersion) *mockBalances {
	return &mockBalances{
		ConsensusVersion: cv,
		b:                map[basics.Address]basics.AccountData{},
	}
}

// makeMockBalancesWithAccounts takes a ConsensusVersion and a map of Address to AccountData and returns a mocked
// balances.
func makeMockBalancesWithAccounts(cv protocol.ConsensusVersion, b map[basics.Address]basics.AccountData) *mockBalances {
	return &mockBalances{
		ConsensusVersion: cv,
		b:                b,
	}
}

func (balances mockBalances) Round() basics.Round {
	return basics.Round(8675309)
}

func (balances mockBalances) Allocate(basics.Address, basics.AppIndex, bool, basics.StateSchema) error {
	return nil
}

func (balances mockBalances) Deallocate(basics.Address, basics.AppIndex, bool) error {
	return nil
}

func (balances mockBalances) StatefulEval(logic.EvalParams, basics.AppIndex, []byte) (bool, basics.EvalDelta, error) {
	return false, basics.EvalDelta{}, nil
}

func (balances mockBalances) PutWithCreatable(basics.Address, basics.AccountData, *basics.CreatableLocator, *basics.CreatableLocator) error {
	return nil
}

func (balances mockBalances) Get(addr basics.Address, withPendingRewards bool) (basics.AccountData, error) {
	return balances.b[addr], nil
}

func (balances mockBalances) GetCreator(idx basics.CreatableIndex, ctype basics.CreatableType) (basics.Address, bool, error) {
	return basics.Address{}, true, nil
}

func (balances mockBalances) Put(addr basics.Address, ad basics.AccountData) error {
	balances.b[addr] = ad
	return nil
}

func (balances mockBalances) Move(src, dst basics.Address, amount basics.MicroAlgos, srcRewards, dstRewards *basics.MicroAlgos) error {
	return nil
}

func (balances mockBalances) ConsensusParams() config.ConsensusParams {
	return config.Consensus[balances.ConsensusVersion]
}
