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

package gen

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"

	"github.com/stretchr/testify/require"
)

func TestLoadMultiRootKeyConcurrent(t *testing.T) {
	t.Skip() // skip in auto-test mode
	a := require.New(t)
	tempDir, err := ioutil.TempDir("", "loadkey-test-")
	a.NoError(err)
	defer os.RemoveAll(tempDir)

	const numThreads = 100
	var wg sync.WaitGroup
	wg.Add(numThreads)

	for i := 0; i < numThreads; i++ {
		go func(idx int) {
			defer wg.Done()
			wallet := filepath.Join(tempDir, fmt.Sprintf("wallet%d", idx+1))
			rootDB, err := db.MakeErasableAccessor(wallet)
			defer rootDB.Close()
			a.NoError(err)
			_, err = account.GenerateRoot(rootDB)
			a.NoError(err)
		}(i)
	}

	wg.Wait()

	for r := 0; r < 1000; r++ {
		var wg sync.WaitGroup
		wg.Add(numThreads)
		for i := 0; i < numThreads; i++ {
			go func(idx int) {
				defer wg.Done()
				wallet := filepath.Join(tempDir, fmt.Sprintf("wallet%d", idx+1))
				_, db, err := loadRootKey(wallet)
				a.NoError(err)
				db.Close()
			}(i)
		}
		wg.Wait()
	}
}

func TestLoadSingleRootKeyConcurrent(t *testing.T) {
	t.Skip() // skip in auto-test mode
	a := require.New(t)
	tempDir, err := ioutil.TempDir("", "loadkey-test-")
	a.NoError(err)
	defer os.RemoveAll(tempDir)

	wallet := filepath.Join(tempDir, "wallet1")
	rootDB, err := db.MakeErasableAccessor(wallet)
	a.NoError(err)
	_, err = account.GenerateRoot(rootDB)
	rootDB.Close()
	a.NoError(err)

	const numThreads = 10000
	var wg sync.WaitGroup
	wg.Add(numThreads)

	for i := 0; i < numThreads; i++ {
		go func(idx int) {
			defer wg.Done()
			wallet := filepath.Join(tempDir, "wallet1")
			_, db, err := loadRootKey(wallet)
			a.NoError(err)
			db.Close()
		}(i)
	}
	wg.Wait()
}

func TestGenesisRoundoff(t *testing.T) {
	verbosity := strings.Builder{}
	genesisData := DefaultGenesis
	genesisData.NetworkName = "wat"
	genesisData.ConsensusProtocol = protocol.ConsensusCurrentVersion // TODO: also check ConsensusFuture ?
	genesisData.Wallets = make([]WalletData, 15)
	for i := range genesisData.Wallets {
		genesisData.Wallets[i].Name = fmt.Sprintf("w%d", i)
		genesisData.Wallets[i].Stake = 100.0 / float64(len(genesisData.Wallets))
	}
	_, _, _, err := setupGenerateGenesisFiles(genesisData, config.Consensus, &verbosity)
	require.NoError(t, err)
	require.True(t, strings.Contains(verbosity.String(), "roundoff"))
}
