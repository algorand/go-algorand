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

package remote

import (
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand/testPartitioning"
	"github.com/stretchr/testify/require"
)

func TestLoadBootstrappedData(t *testing.T) {
	testPartitioning.PartitionTest(t)

	badSpecPath := filepath.Join("./../../test", "testdata/deployednettemplates/networks/bootstrapped/badSpec.json")
	_, err := LoadBootstrappedData(badSpecPath)
	require.NotEqual(t, nil, err)

	okSpecPath := filepath.Join("./../../test", "testdata/deployednettemplates/networks/bootstrapped/okSpec.json")
	var data BootstrappedNetwork
	data, err = LoadBootstrappedData(okSpecPath)
	expected := BootstrappedNetwork{
		NumRounds:                 65000,
		RoundTransactionsCount:    1000,
		GeneratedAccountsCount:    7000000,
		GeneratedAssetsCount:      200000,
		GeneratedApplicationCount: 1000000,
		SourceWalletName:          "wallet1",
	}
	require.Equal(t, nil, err)
	require.Equal(t, data.NumRounds, expected.NumRounds)
	require.Equal(t, data.RoundTransactionsCount, expected.RoundTransactionsCount)
	require.Equal(t, data.GeneratedAccountsCount, expected.GeneratedAccountsCount)
	require.Equal(t, data.GeneratedAssetsCount, expected.GeneratedAssetsCount)
	require.Equal(t, data.GeneratedApplicationCount, expected.GeneratedApplicationCount)
	require.Equal(t, data.SourceWalletName, expected.SourceWalletName)
}
