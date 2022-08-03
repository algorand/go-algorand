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

package data

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/components/mocks"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

func TestAccountManagerKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	registry := &mocks.MockParticipationRegistry{}
	testAccountManagerKeys(t, registry, false)
}

// copied from account/participationRegistry_test.go
func getRegistryImpl(t testing.TB, inMem bool, erasable bool) (registry account.ParticipationRegistry, dbName string) {
	var rootDB db.Pair
	var err error
	dbName = strings.Replace(t.Name(), "/", "_", -1)
	if erasable {
		require.False(t, inMem, "erasable registry can't be in-memory")
		rootDB, err = db.OpenErasablePair(dbName)
	} else {
		rootDB, err = db.OpenPair(dbName, inMem)
	}
	require.NoError(t, err)

	registry, err = account.MakeParticipationRegistry(rootDB, logging.TestingLog(t))
	require.NoError(t, err)
	require.NotNil(t, registry)

	if inMem { // no files to clean up
		dbName = ""
	}
	return registry, dbName
}

func registryCloseTest(t testing.TB, registry account.ParticipationRegistry, dbfilePrefix string) {
	registry.Close()
	// clean up DB files
	if dbfilePrefix != "" {
		dbfiles, err := filepath.Glob(dbfilePrefix + "*")
		require.NoError(t, err)
		for _, f := range dbfiles {
			t.Log("removing", f)
			require.NoError(t, os.Remove(f))
		}
	}
}

func TestAccountManagerKeysRegistry(t *testing.T) {
	partitiontest.PartitionTest(t)
	registry, dbName := getRegistryImpl(t, false, true)
	defer registryCloseTest(t, registry, dbName)
	testAccountManagerKeys(t, registry, true)
}

func testAccountManagerKeys(t *testing.T, registry account.ParticipationRegistry, flushRegistry bool) {
	log := logging.TestingLog(t)
	log.SetLevel(logging.Error)

	acctManager := MakeAccountManager(log, registry)

	databaseFiles := make([]string, 0)
	defer func() {
		for _, fileName := range databaseFiles {
			os.Remove(fileName)
			os.Remove(fileName + "-shm")
			os.Remove(fileName + "-wal")
		}
	}()

	// create participation keys
	numPartKeys := 10
	if nk, err := strconv.Atoi(os.Getenv("NUMKEYS")); err == nil { // allow setting numKeys via env var
		numPartKeys = nk
	}
	for partKeyIdx := 0; partKeyIdx < numPartKeys; partKeyIdx++ {
		rootFilename := t.Name() + "_root_" + strconv.Itoa(partKeyIdx) + ".sqlite"
		partFilename := t.Name() + "_part_" + strconv.Itoa(partKeyIdx) + ".sqlite"
		os.Remove(rootFilename)
		os.Remove(partFilename)
		rootAccessor, err := db.MakeAccessor(rootFilename, false, true)
		require.NoError(t, err)

		root, err := account.GenerateRoot(rootAccessor)
		require.NoError(t, err)

		accessor, err := db.MakeErasableAccessor(partFilename)
		require.NoError(t, err)
		accessor.SetLogger(log)

		part, err := account.FillDBWithParticipationKeys(accessor, root.Address(), 0, 100, 10000)
		require.NoError(t, err)

		rootAccessor.Close()
		databaseFiles = append(databaseFiles, rootFilename)
		databaseFiles = append(databaseFiles, partFilename)

		// Not ephemeral to be backwards compatible with the test
		acctManager.AddParticipation(part, false)
	}
	if _, mocked := acctManager.Registry().(*mocks.MockParticipationRegistry); !mocked {
		require.Len(t, acctManager.Keys(basics.Round(1)), numPartKeys, "incorrect number of keys, can happen if test crashes and leaves SQLite files")
		require.Len(t, acctManager.Registry().GetAll(), numPartKeys, "incorrect number of keys, can happen if test crashes and leaves SQLite files")
	}

	keyDeletionDone := make(chan struct{}, 1)
	nextRoundCh := make(chan basics.Round, 2)
	// kick off key deletion thread.
	go func() {
		defer close(keyDeletionDone)
		agreementProto := config.Consensus[protocol.ConsensusCurrentVersion]
		header := bookkeeping.BlockHeader{}
		for rnd := range nextRoundCh {
			header.Round = rnd
			t0 := time.Now()
			acctManager.DeleteOldKeys(header, agreementProto)
			t.Logf("DeleteOldKeys\trnd %d took %v", uint64(rnd), time.Since(t0))

			if flushRegistry {
				t0 = time.Now()
				err := acctManager.Registry().Flush(10 * time.Second)
				require.NoError(t, err)
				t.Logf("Flush\t\trnd %d took %v", uint64(rnd), time.Since(t0))
			}
		}
	}()

	testStartTime := time.Now()
	keysTotalDuration := time.Duration(0)
	for i := 1; i < 20; i++ {
		nextRoundCh <- basics.Round(i)
		startTime := time.Now()
		acctManager.Keys(basics.Round(i))
		keysTotalDuration += time.Since(startTime)
	}
	close(nextRoundCh)
	<-keyDeletionDone
	testDuration := time.Since(testStartTime)
	t.Logf("testDuration %v keysTotalDuration %v\n", testDuration, keysTotalDuration)
	require.Lessf(t, keysTotalDuration, testDuration/100, fmt.Sprintf("the time to aquire the keys via Keys() was %v whereas blocking on keys deletion took %v", keysTotalDuration, testDuration))
	t.Logf("Calling AccountManager.Keys() while AccountManager.DeleteOldKeys() was busy, 10 times in a row, resulted in accumulated delay of %v\n", keysTotalDuration)
}
