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

package kmdtest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/daemon/kmd/config"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func TestNonAbsSQLiteWalletConfigFails(t *testing.T) {
	t.Parallel()
	var f fixtures.KMDFixture
	f.Initialize(t)
	defer f.Shutdown()

	// Test non-absolute wallet config fails
	cfg := `{"drivers":{"sqlite":{"wallets_dir":"not/absolute"}}}`
	err := f.TestConfig([]byte(cfg))
	// Should return an error
	require.NotNil(t, err)
	// Should return the correct error
	require.Equal(t, err, config.ErrSQLiteWalletNotAbsolute)
}

func TestAbsSQLiteWalletConfigSucceeds(t *testing.T) {
	t.Parallel()
	var f fixtures.KMDFixture
	f.Initialize(t)
	defer f.Shutdown()

	// Test non-absolute wallet config fails
	cfg := `{"drivers":{"sqlite":{"wallets_dir":"/very/absolute"}}}`
	err := f.TestConfig([]byte(cfg))
	// Error should be nil
	require.Nil(t, err)
}
