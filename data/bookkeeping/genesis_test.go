// Copyright (C) 2019-2022 Algorand, Inc.
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

package bookkeeping

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestGenesis_Balances(t *testing.T) {
	partitiontest.PartitionTest(t)
	containsErrorFunc := func(str string) assert.ErrorAssertionFunc {
		return func(_ assert.TestingT, err error, i ...interface{}) bool {
			require.ErrorContains(t, err, str)
			return true
		}
	}
	mustAddr := func(addr string) basics.Address {
		address, err := basics.UnmarshalChecksumAddress(addr)
		require.NoError(t, err)
		return address
	}
	makeAddr := func(addr uint64) basics.Address {
		var address basics.Address
		address[0] = byte(addr)
		return address
	}
	acctWith := func(algos uint64, addr string) GenesisAllocation {
		return GenesisAllocation{
			_struct: struct{}{},
			Address: addr,
			Comment: "",
			State: basics.AccountData{
				MicroAlgos: basics.MicroAlgos{Raw: algos},
			},
		}
	}
	goodAddr := makeAddr(100)
	allocation1 := acctWith(1000, makeAddr(1).String())
	allocation2 := acctWith(2000, makeAddr(2).String())
	badAllocation := acctWith(1234, "El Toro Loco")
	type fields struct {
		Allocation  []GenesisAllocation
		FeeSink     string
		RewardsPool string
	}
	tests := []struct {
		name    string
		fields  fields
		want    GenesisBalances
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "basic test",
			fields: fields{
				Allocation:  []GenesisAllocation{allocation1},
				FeeSink:     goodAddr.String(),
				RewardsPool: goodAddr.String(),
			},
			want: GenesisBalances{
				Balances: map[basics.Address]basics.AccountData{
					mustAddr(allocation1.Address): allocation1.State,
				},
				FeeSink:     goodAddr,
				RewardsPool: goodAddr,
				Timestamp:   0,
			},
			wantErr: assert.NoError,
		},
		{
			name: "two test",
			fields: fields{
				Allocation:  []GenesisAllocation{allocation1, allocation2},
				FeeSink:     goodAddr.String(),
				RewardsPool: goodAddr.String(),
			},
			want: GenesisBalances{
				Balances: map[basics.Address]basics.AccountData{
					mustAddr(allocation1.Address): allocation1.State,
					mustAddr(allocation2.Address): allocation2.State,
				},
				FeeSink:     goodAddr,
				RewardsPool: goodAddr,
				Timestamp:   0,
			},
			wantErr: assert.NoError,
		},
		{
			name: "bad fee sink",
			fields: fields{
				Allocation:  []GenesisAllocation{allocation1, allocation2},
				RewardsPool: goodAddr.String(),
			},
			wantErr: containsErrorFunc("cannot parse fee sink addr"),
		},
		{
			name: "bad rewards pool",
			fields: fields{
				Allocation: []GenesisAllocation{allocation1, allocation2},
				FeeSink:    goodAddr.String(),
			},
			wantErr: containsErrorFunc("cannot parse rewards pool addr"),
		},
		{
			name: "bad genesis addr",
			fields: fields{
				Allocation:  []GenesisAllocation{badAllocation},
				FeeSink:     goodAddr.String(),
				RewardsPool: goodAddr.String(),
			},
			wantErr: containsErrorFunc("cannot parse genesis addr"),
		},
		{
			name: "repeat address",
			fields: fields{
				Allocation:  []GenesisAllocation{allocation1, allocation1},
				FeeSink:     goodAddr.String(),
				RewardsPool: goodAddr.String(),
			},
			wantErr: containsErrorFunc("repeated allocation to"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			genesis := Genesis{
				Allocation:  tt.fields.Allocation,
				FeeSink:     tt.fields.FeeSink,
				RewardsPool: tt.fields.RewardsPool,
			}
			got, err := genesis.Balances()
			if tt.wantErr(t, err, fmt.Sprintf("Balances()")) {
				return
			}
			assert.Equalf(t, tt.want, got, "Balances()")
		})
	}
}
