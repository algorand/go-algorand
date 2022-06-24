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

package testing

import (
	"fmt"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func DbOpenTest(t testing.TB, inMemory bool) (db.Pair, string) {
	fn := fmt.Sprintf("%s.%d", strings.ReplaceAll(t.Name(), "/", "."), crypto.RandUint64())
	dbs, err := db.OpenPair(fn, inMemory)
	require.NoErrorf(t, err, "Filename : %s\nInMemory: %v", fn, inMemory)
	return dbs, fn
}

func SetDbLogging(t testing.TB, dbs db.Pair) {
	dblogger := logging.TestingLog(t)
	dbs.Rdb.SetLogger(dblogger)
	dbs.Wdb.SetLogger(dblogger)
}

// CreatablesFromUpdates calculates creatables from updates
func CreatablesFromUpdates(base map[basics.Address]basics.AccountData, updates ledgercore.AccountDeltas, seen map[basics.CreatableIndex]bool) map[basics.CreatableIndex]ledgercore.ModifiedCreatable {
	known := make(map[basics.CreatableIndex]struct{}, len(seen))
	for aidx := range seen {
		known[aidx] = struct{}{}
	}
	for _, ad := range base {
		for aidx := range ad.AppParams {
			known[basics.CreatableIndex(aidx)] = struct{}{}
		}
		for aidx := range ad.AssetParams {
			known[basics.CreatableIndex(aidx)] = struct{}{}
		}
	}
	return updates.ToModifiedCreatables(known)
}

func ApplyPartialDeltas(base map[basics.Address]basics.AccountData, deltas ledgercore.AccountDeltas) map[basics.Address]basics.AccountData {
	result := make(map[basics.Address]basics.AccountData, len(base)+deltas.Len())
	for addr, ad := range base {
		result[addr] = ad
	}

	for i := 0; i < deltas.Len(); i++ {
		addr, _ := deltas.GetByIdx(i)
		ad, ok := result[addr]
		if !ok {
			ad, _ = deltas.GetBasicsAccountData(addr)
		} else {
			ad = deltas.ApplyToBasicsAccountData(addr, ad)
		}
		result[addr] = ad
	}
	return result
}
