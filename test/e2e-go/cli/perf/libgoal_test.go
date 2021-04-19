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

package algod

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func BenchmarkLibGoalPerf(b *testing.B) {
	var fixture fixtures.LibGoalFixture
	fixture.SetupNoStart(b, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	fixture.Start()
	defer fixture.Shutdown()
	binDir := fixture.GetBinDir()

	c, err := libgoal.MakeClientWithBinDir(binDir, fixture.PrimaryDataDir(), fixture.PrimaryDataDir(), libgoal.FullClient)
	a := require.New(fixtures.SynchronizedTest(b))
	a.NoError(err)

	b.Run("algod", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := c.AlgodVersions()
			a.NoError(err)
		}
	})

	b.Run("kmd", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := c.GetUnencryptedWalletHandle()
			a.NoError(err)
		}
	})
}
