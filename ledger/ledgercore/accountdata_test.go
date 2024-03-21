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

package ledgercore

import (
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

// TestBasicsAccountDataRoundtripConversion ensures that basics.AccountData can be converted to
// ledgercore.AccountData and back without losing any data. It uses reflection to be sure that this
// test is always up-to-date with new fields.
//
// In other words, this test makes sure any new fields in basics.AccountData also get added to
// ledgercore.AccountData.
func TestBasicsAccountDataRoundtripConversion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for i := 0; i < 1000; i++ {
		randObj, _ := protocol.RandomizeObject(&basics.AccountData{})
		basicsAccount := *randObj.(*basics.AccountData)

		ledgercoreAccount := ToAccountData(basicsAccount)
		var roundTripAccount basics.AccountData
		AssignAccountData(&roundTripAccount, ledgercoreAccount)

		// Manually set resources, since AssignAccountData doesn't attempt to restore them
		roundTripAccount.AssetParams = basicsAccount.AssetParams
		roundTripAccount.Assets = basicsAccount.Assets
		roundTripAccount.AppLocalStates = basicsAccount.AppLocalStates
		roundTripAccount.AppParams = basicsAccount.AppParams

		require.Equal(t, basicsAccount, roundTripAccount)
		require.Equal(t, uint64(len(roundTripAccount.AssetParams)), ledgercoreAccount.TotalAssetParams)
		require.Equal(t, uint64(len(roundTripAccount.Assets)), ledgercoreAccount.TotalAssets)
		require.Equal(t, uint64(len(roundTripAccount.AppLocalStates)), ledgercoreAccount.TotalAppLocalStates)
		require.Equal(t, uint64(len(roundTripAccount.AppParams)), ledgercoreAccount.TotalAppParams)
	}
}

// TestLedgercoreAccountDataRoundtripConversion ensures that ledgercore.AccountData can be converted
// to basics.AccountData and back without losing any data. It uses reflection to be sure that no
// new fields are omitted.
//
// In other words, this test makes sure any new fields in ledgercore.AccountData also get added to
// basics.AccountData. You should add a manual override in this test if the field really only
// belongs in ledgercore.AccountData.
func TestLedgercoreAccountDataRoundtripConversion(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for i := 0; i < 1000; i++ {
		randObj, _ := protocol.RandomizeObject(&AccountData{})
		ledgercoreAccount := *randObj.(*AccountData)

		var basicsAccount basics.AccountData
		AssignAccountData(&basicsAccount, ledgercoreAccount)
		roundTripAccount := ToAccountData(basicsAccount)

		// Manually set resources, since resource information is lost in AssignAccountData
		roundTripAccount.TotalAssetParams = ledgercoreAccount.TotalAssetParams
		roundTripAccount.TotalAssets = ledgercoreAccount.TotalAssets
		roundTripAccount.TotalAppLocalStates = ledgercoreAccount.TotalAppLocalStates
		roundTripAccount.TotalAppParams = ledgercoreAccount.TotalAppParams

		require.Equal(t, ledgercoreAccount, roundTripAccount)
	}
}
