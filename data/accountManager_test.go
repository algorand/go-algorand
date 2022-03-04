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
	"strconv"
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
	log := logging.TestingLog(t)
	log.SetLevel(logging.Error)
	registry := &mocks.MockParticipationRegistry{}

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
	const numPartKeys = 10
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

		acctManager.AddParticipation(part)
	}

	keyDeletionDone := make(chan struct{}, 1)
	nextRoundCh := make(chan basics.Round, 2)
	// kick off key deletion thread.
	go func() {
		defer close(keyDeletionDone)
		ccSigs := make(map[basics.Address]basics.Round)
		agreementProto := config.Consensus[protocol.ConsensusCurrentVersion]
		header := bookkeeping.BlockHeader{}
		for rnd := range nextRoundCh {
			header.Round = rnd
			acctManager.DeleteOldKeys(header, ccSigs, agreementProto)
		}
	}()

	testStartTime := time.Now()
	keysTotalDuration := time.Duration(0)
	for i := 1; i < 10; i++ {
		nextRoundCh <- basics.Round(i)
		startTime := time.Now()
		acctManager.Keys(basics.Round(i))
		keysTotalDuration += time.Since(startTime)
	}
	close(nextRoundCh)
	<-keyDeletionDone
	testDuration := time.Since(testStartTime)
	require.Lessf(t, keysTotalDuration, testDuration/100, fmt.Sprintf("the time to aquire the keys via Keys() was %v whereas blocking on keys deletion took %v", keysTotalDuration, testDuration))
	t.Logf("Calling AccountManager.Keys() while AccountManager.DeleteOldKeys() was busy, 10 times in a row, resulted in accumulated delay of %v\n", keysTotalDuration)
}
