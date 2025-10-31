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

package participation

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
)

// TestOverlappingParticipationKeys is a test that "overlaps" participation keys across
// various nodes. Keys are installed in a rotating fashion across the nodes where:
// ((Network Round - 1) Mod 10) = nodeIdx and nodeIdx is used to pull out from an
// "array" of nodes similar to {Node1, Node2, Node3} etc.  The Mod 10 simply pulls the
// "digit" from the number:
//
//	Round: 13 -> 13 - 1 = 12 ->  12 Mod 10 -> 2 -> Node3 with nodeIdx == 2
//
// The keys are overlapped in the sense that a key is registered to a node and
// "overlaps" with other installed keys that are also valid.  Meaning there might be:
// PKI 1 (Valid 3-15) and PKI 2 (Valid 13-25) and PKI 3 (Valid 23-35) all installed
// on the same node
func TestOverlappingParticipationKeys(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	consensus := make(config.ConsensusProtocols)
	shortPartKeysProtocol := config.Consensus[protocol.ConsensusCurrentVersion]
	shortPartKeysProtocol.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	// keys round = current - 2 * (2 * 1) (see selector.go)
	//  --> return r.SubSaturate(basics.Round(2 * cparams.SeedRefreshInterval * cparams.SeedLookback))
	// new keys must exist at least 4 rounds prior use
	shortPartKeysProtocol.SeedLookback = 2
	shortPartKeysProtocol.SeedRefreshInterval = 1
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		// amd64 and arm64 platforms are generally quite capable, so accelerate the round times to make the test run faster.
		shortPartKeysProtocol.AgreementFilterTimeoutPeriod0 = 1 * time.Second
		shortPartKeysProtocol.AgreementFilterTimeout = 1 * time.Second
	}
	consensus[protocol.ConsensusVersion("shortpartkeysprotocol")] = shortPartKeysProtocol

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	// ShortParticipationKeys template has LastPartKeyRound=8
	// to allow the 3rd key to be registered and appear after 4+4 round for its first use
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "ShortParticipationKeys.json"))
	defer fixture.Shutdown()

	accountsNum := len(fixture.NodeDataDirs())

	genesis, err := bookkeeping.LoadGenesisFromFile(filepath.Join(fixture.PrimaryDataDir(), "genesis.json"))
	a.NoError(err)
	genesisHash := genesis.Hash()
	rootKeys := make(map[int]*account.Root)
	regTransactions := make(map[int]transactions.SignedTxn)
	const lastRound = 39 // check 3 rounds of keys rotations

	// prepare the participation keys ahead of time.
	for round := uint64(1); round < lastRound; round++ {
		if (round-1)%10 >= uint64(accountsNum) {
			continue
		}
		acctIdx := (round - 1) % 10

		// Prepare the registration keys ahead of time.  Note that the + 10 is because we use Mod 10

		// These variables control when the transaction will be sent out to be valid from.
		// These variables will also be the name of the file produced EXCEPT
		// prepareParticipationKey() will add 2 to the txStartRound for the filename.
		// so the file for round 1 will be 3.15
		// For round 11 (the next round that Mod 10 will index to 1), that means the filename will be
		// 13.25 which results in a 2 round overlap
		txStartRound := round
		txEndRound := txStartRound + 10 + 4
		// The registration variables here control when the participation key will actually be valid from
		// For round 1, that means from 1-16 (one round of overlap)
		// For round 11 (the next round that Mod 10 will index to 1), that means the 11-26
		regStartRound := round
		regEndRound := regStartRound + 11 + 4

		err = prepareParticipationKey(a, &fixture, acctIdx, txStartRound, txEndRound, regStartRound, regEndRound, genesisHash, rootKeys, regTransactions, config.Consensus[protocol.ConsensusCurrentVersion])
		a.NoError(err)
	}

	fixture.Start()
	currentRound := basics.Round(0)
	fixture.AlgodClient = fixture.GetAlgodClientForController(fixture.NC)

	// ******** IMPORTANT ********
	// It is CRITICAL that this for loop NOT BLOCK.
	// This loop assumes that it stays current with the round of the network.
	// Remember: this test is running while the network is advancing rounds in parallel
	// If this test blocks for more than a couple seconds, then the network round count will have advanced
	// farther than the current "currentRound" variable.  This will mean that the "addParticipationKey" function
	// will NOT install the participation key in time for the shortened SeedLookback variable resulting
	// in a network stall and a test failure
	for {
		err := fixture.WaitForRoundWithTimeout(currentRound + 1)
		a.NoError(err)

		// A sanity check that makes sure that the round of the network is the same as our
		// current round variable
		sts, err := fixture.GetAlgodClientForController(fixture.NC).Status()
		a.NoError(err, "the network stalled, see test comments and review node.log in each nodes data directory for details.")
		a.Equal(sts.LastRound, currentRound+1)

		currentRound++
		if (currentRound-1)%10 < basics.Round(accountsNum) {
			acctIdx := int((currentRound - 1) % 10)

			// We do a plus two because the filenames were stored with a plus 2
			startRound := currentRound + 2 // +2 and -2 below to balance, start/end must match in part key file name
			endRound := startRound + 10 + 4 - 2

			regStartRound := currentRound
			regEndRound := regStartRound + 11 + 4

			// This cannot block! (See above)
			// We pull the files from the disk according to their start round end round filenames
			// and install them as well as send out a transaction
			pk, err := addParticipationKey(a, &fixture, acctIdx, startRound, endRound, regTransactions)
			a.NoError(err)
			t.Logf("[.] Round %d, Added reg key for node %d range [%d..%d] %s\n", currentRound, acctIdx, regStartRound, regEndRound, hex.EncodeToString(pk[:8]))
		} else {
			t.Logf("[.] Round %d\n", currentRound)
		}

		if currentRound == lastRound {
			break
		}
	}

}

func addParticipationKey(a *require.Assertions, fixture *fixtures.RestClientFixture, acctNum int, startRound, endRound basics.Round, regTransactions map[int]transactions.SignedTxn) (crypto.OneTimeSignatureVerifier, error) {
	dataDir := fixture.NodeDataDirs()[acctNum]
	nc := fixture.GetNodeControllerForDataDir(dataDir)

	partKeyName := filepath.Join(dataDir, config.PartKeyFilename("Wallet", uint64(startRound), uint64(endRound)))

	// This function can take more than a couple seconds, we can't have this function block so
	// we wrap it in a go routine
	go func() {
		clientController := fixture.GetLibGoalClientFromNodeController(nc)
		_, err := clientController.AddParticipationKey(partKeyName)
		a.NoError(err)
	}()

	signedTxn := regTransactions[int(startRound-2)]
	a.NotEmpty(signedTxn.Sig)
	_, err := fixture.GetAlgodClientForController(nc).SendRawTransaction(signedTxn)
	a.NoError(err)
	return signedTxn.Txn.KeyregTxnFields.VotePK, err
}

func prepareParticipationKey(a *require.Assertions, fixture *fixtures.RestClientFixture, acctNum, txStartRound, txEndRound, regStartRound, regEndRound uint64, genesisHash crypto.Digest, rootKeys map[int]*account.Root, regTransactions map[int]transactions.SignedTxn, c config.ConsensusParams) error {
	dataDir := fixture.NodeDataDirs()[acctNum]

	nc := fixture.GetNodeControllerForDataDir(dataDir)
	genesisDir, err := nc.GetGenesisDir()
	if err != nil {
		a.NoError(err)
		return err
	}
	var rootAccount account.Root
	if _, have := rootKeys[int(acctNum)]; !have {
		var rootKeyFilename string
		err = filepath.Walk(genesisDir, func(path string, f os.FileInfo, errIn error) error {
			if errIn != nil {
				return errIn
			}
			if f.IsDir() {
				return nil
			}
			if config.IsRootKeyFilename(f.Name()) {
				rootKeyFilename = path
			}
			return nil
		})
		if err != nil {
			a.NoError(err)
			return err
		}

		rootKeyHandle, err := db.MakeAccessor(rootKeyFilename, false, false)
		if err != nil {
			a.NoError(err)
			return err
		}

		// generate a new participation key.
		rootAccount, err = account.RestoreRoot(rootKeyHandle)
		if err != nil {
			a.NoError(err)
			return err
		}
		rootKeys[int(acctNum)] = &rootAccount
		rootKeyHandle.Close()
	}
	rootAccount = *rootKeys[int(acctNum)]

	partKeyName := filepath.Join(dataDir, config.PartKeyFilename("Wallet", txStartRound+2, txEndRound))

	partkeyHandle, err := db.MakeAccessor(partKeyName, false, false)
	if err != nil {
		a.NoError(err)
		return err
	}

	persistedParticipation, err := account.FillDBWithParticipationKeys(partkeyHandle, rootAccount.Address(), basics.Round(regStartRound), basics.Round(regEndRound), fixture.LibGoalFixture.Genesis().PartKeyDilution)
	if err != nil {
		a.NoError(err)
		return err
	}
	partkeyHandle.Vacuum(context.Background())
	persistedParticipation.Close()

	unsignedTxn := persistedParticipation.GenerateRegistrationTransaction(basics.MicroAlgos{Raw: c.MinTxnFee}, basics.Round(txStartRound), basics.Round(txEndRound), [32]byte{}, c.EnableStateProofKeyregCheck)
	copy(unsignedTxn.GenesisHash[:], genesisHash[:])
	regTransactions[int(txStartRound)] = unsignedTxn.Sign(rootAccount.Secrets())
	return nil
}
