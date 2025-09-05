// Copyright (C) 2019-2025 Algorand, Inc.
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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand/data/basics"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

func TestLoadMultiRootKeyConcurrent(t *testing.T) {
	t.Skip() // skip in auto-test mode
	a := require.New(t)
	tempDir := t.TempDir()

	const numThreads = 100
	var wg sync.WaitGroup
	wg.Add(numThreads)

	for i := 0; i < numThreads; i++ {
		go func(idx int) {
			defer wg.Done()
			wallet := filepath.Join(tempDir, fmt.Sprintf("wallet%d", idx+1))
			rootDB, err := db.MakeErasableAccessor(wallet)
			a.NoError(err)
			defer rootDB.Close()
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
	tempDir := t.TempDir()

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
	partitiontest.PartitionTest(t)
	verbosity := strings.Builder{}
	genesisData := DefaultGenesis
	genesisData.NetworkName = "wat"
	genesisData.ConsensusProtocol = protocol.ConsensusCurrentVersion // TODO: also check ConsensusFuture ?
	genesisData.Wallets = make([]WalletData, 15)
	for i := range genesisData.Wallets {
		genesisData.Wallets[i].Name = fmt.Sprintf("w%d", i)
		genesisData.Wallets[i].Stake = 100.0 / float64(len(genesisData.Wallets))
	}
	_, _, _, err := setupGenerateGenesisFiles(&genesisData, config.Consensus, &verbosity)
	require.NoError(t, err)
	require.True(t, strings.Contains(verbosity.String(), "roundoff"))
}

// `TestGenesisJsonCreation` defends against regressions to `genesis.json` generation by comparing a known, valid `genesis.json` against a version generated during test invocation.
//
// * For each `testCase`, there is a corresponding `genesis.json` in `gen/resources` representing the known, valid output.
// * When adding test cases, it's assumed folks peer review new artifacts in `gen/resources`.
// * Since _some_ `genesis.json` values are non-deterministic, the test replaces these values with static values to facilitate equality checks.
func TestGenesisJsonCreation(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	type testCase struct {
		name             string
		gd               GenesisData
		expectedOverride string
	}

	defaultGenesisFromFile := func(filename string) GenesisData {
		jsonBytes, err := os.ReadFile(filename)
		require.NoError(t, err)

		gd := DefaultGenesis
		err = json.Unmarshal(jsonBytes, &gd)
		require.NoError(t, err)

		return gd
	}

	// `base` is a canonical test confirming `devnet.json` generates the intended `genesis.json`.
	base := func() testCase {
		return testCase{"base", defaultGenesisFromFile("devnet.json"), ""}
	}

	// `balance` extends `base` to confirm overriding the rewards pool balance works.
	balance := func() testCase {
		gd := base().gd
		gd.RewardsPoolBalance = 0 // Expect generated balance == MinBalance
		return testCase{"balance", gd, ""}
	}

	// `testnet` confirms the generated genesis.json conforms to a previously generated _installer_ artifact.
	testnet := func() testCase {
		return testCase{"testnet", defaultGenesisFromFile("testnet.json"), "../installer/genesis/testnet/genesis.json"}
	}

	// `blotOutRandomValues` replaces random values with static values to support equality checks.
	blotOutRandomValues := func(as []bookkeeping.GenesisAllocation) {
		deterministicAddresses := []string{"FeeSink", "RewardsPool"}

		isNondeterministicAddress := func(name string) bool {
			return !slices.Contains(deterministicAddresses, name)
		}

		for i := range as {
			require.Len(t, as[i].State.VoteID, 32)
			as[i].State.VoteID = crypto.OneTimeSignatureVerifier{}
			require.Len(t, as[i].State.VoteID, 32)
			as[i].State.SelectionID = crypto.VRFVerifier{}

			if isNondeterministicAddress(as[i].Comment) {
				require.Len(t, as[i].Address, 58)
				as[i].Address = ""
			}
		}
	}

	const quickLastPartKeyRound = basics.Round(10) // Ensure quick test execution by reducing rounds.

	// `blotOutFixedValues` replaces values from actual genesis values in order to be compatible with artifacts generated by tests.
	blotOutFixedValues := func(g *bookkeeping.Genesis) {
		for i := range g.Allocation {
			if g.Allocation[i].State.Status == basics.Online {
				require.Greater(t, g.Allocation[i].State.VoteLastValid, quickLastPartKeyRound)
				g.Allocation[i].State.VoteLastValid = quickLastPartKeyRound
			}
		}

		require.NotZero(t, g.Timestamp)
		g.Timestamp = 0

		require.NotEmpty(t, g.Network)
		g.Network = ""
	}

	saveGeneratedGenesisJSON := func(filename, artifactName string) {
		src, err := os.Open(filename)
		require.NoError(t, err)
		defer src.Close()

		dst, err := os.CreateTemp("", "*-"+artifactName)
		require.NoError(t, err)
		defer dst.Close()

		_, err = io.Copy(dst, src)
		require.NoError(t, err)

		t.Log("generated genesis.json = " + dst.Name())
	}

	// Since `t.TempDir` deletes the generated dir, retain generated `genesis.json` on test failure.
	saveOnFailure := func(result bool, generatedFilename, artifactName string) {
		if !result {
			saveGeneratedGenesisJSON(generatedFilename, artifactName)
			t.FailNow()
		}
	}

	for _, tc := range []testCase{
		base(),
		balance(),
		testnet(),
	} {
		t.Run(fmt.Sprintf("name=%v", tc.name), func(t *testing.T) {
			gd := tc.gd
			gd.LastPartKeyRound = quickLastPartKeyRound

			outDir := t.TempDir()
			err := GenerateGenesisFiles(gd, config.Consensus, outDir, nil)
			require.NoError(t, err)

			artifactName := fmt.Sprintf("genesis-%v.json", tc.name)
			generatedFilename := fmt.Sprintf("%v/genesis.json", outDir)
			saveOnFailure := func(result bool) {
				saveOnFailure(result, generatedFilename, artifactName)
			}

			roundtrip, err := bookkeeping.LoadGenesisFromFile(generatedFilename)
			require.NoError(t, err)

			expectedFilepath := func() string {
				if len(tc.expectedOverride) == 0 {
					return "resources/" + artifactName
				}
				return tc.expectedOverride
			}
			expected, err := bookkeeping.LoadGenesisFromFile(expectedFilepath())
			saveOnFailure(assert.NoError(t, err))

			blotOutRandomValues(expected.Allocation)
			blotOutRandomValues(roundtrip.Allocation)

			if len(tc.expectedOverride) > 0 {
				blotOutFixedValues(&expected)
			}

			saveOnFailure(assert.Equal(t, expected, roundtrip))
		})
	}
}
