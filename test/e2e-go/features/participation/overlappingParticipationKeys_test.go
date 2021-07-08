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
	"github.com/algorand/go-algorand/util/db"
)

func TestOverlappingParticipationKeys(t *testing.T) {
	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	consensus := make(config.ConsensusProtocols)
	shortPartKeysProtocol := config.Consensus[protocol.ConsensusCurrentVersion]
	shortPartKeysProtocol.ApprovedUpgrades = map[protocol.ConsensusVersion]uint64{}
	// keys round = current - 2 * (2 * 1) (see selector.go)
	// new keys must exist at least 4 rounds prior use
	shortPartKeysProtocol.SeedLookback = 2
	shortPartKeysProtocol.SeedRefreshInterval = 1
	if runtime.GOARCH == "amd64" {
		// amd64 platforms are generally quite capable, so accelerate the round times to make the test run faster.
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
	for _, dataDir := range fixture.NodeDataDirs() {
		cfg, err := config.LoadConfigFromDisk(dataDir)
		a.NoError(err)
		cfg.ParticipationKeysRefreshInterval = 500 * time.Millisecond
		err = cfg.SaveToDisk(dataDir)
		a.NoError(err)
	}

	genesis, err := bookkeeping.LoadGenesisFromFile(filepath.Join(fixture.PrimaryDataDir(), "genesis.json"))
	a.NoError(err)
	genesisHash := crypto.HashObj(genesis)
	rootKeys := make(map[int]*account.Root)
	regTransactions := make(map[int]transactions.SignedTxn)
	lastRound := uint64(39) // check 3 rounds of keys rotations

	// prepare the participation keys ahead of time.
	for round := uint64(1); round < lastRound; round++ {
		if (round-1)%10 >= uint64(accountsNum) {
			continue
		}
		acctIdx := (round - 1) % 10
		txStartRound := round
		txEndRound := txStartRound + 10 + 4
		regStartRound := round
		regEndRound := regStartRound + 11 + 4
		err = prepareParticipationKey(a, &fixture, acctIdx, txStartRound, txEndRound, regStartRound, regEndRound, genesisHash, rootKeys, regTransactions)
		a.NoError(err)
	}

	fixture.Start()
	currentRound := uint64(0)
	fixture.AlgodClient = fixture.GetAlgodClientForController(fixture.NC)
	for {
		err := fixture.WaitForRoundWithTimeout(currentRound + 1)
		a.NoError(err)
		currentRound++
		if (currentRound-1)%10 < uint64(accountsNum) {
			acctIdx := (currentRound - 1) % 10
			startRound := currentRound + 2 // +2 and -2 below to balance, start/end must match in part key file name
			endRound := startRound + 10 + 4 - 2
			regStartRound := currentRound
			regEndRound := regStartRound + 11 + 4
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

func addParticipationKey(a *require.Assertions, fixture *fixtures.RestClientFixture, acctNum uint64, startRound, endRound uint64, regTransactions map[int]transactions.SignedTxn) (crypto.OneTimeSignatureVerifier, error) {
	dataDir := fixture.NodeDataDirs()[acctNum]
	nc := fixture.GetNodeControllerForDataDir(dataDir)
	genesisDir, err := nc.GetGenesisDir()

	partKeyName := filepath.Join(dataDir, config.PartKeyFilename("Wallet", startRound, endRound))
	partKeyNameTarget := filepath.Join(genesisDir, config.PartKeyFilename("Wallet", startRound, endRound))

	// make the rename in the background to ensure it won't take too long. We have ~4 rounds to complete this.
	go os.Rename(partKeyName, partKeyNameTarget)

	signedTxn := regTransactions[int(startRound-2)]
	a.NotEmpty(signedTxn.Sig)
	_, err = fixture.GetAlgodClientForController(nc).SendRawTransaction(signedTxn)
	a.NoError(err)
	return signedTxn.Txn.KeyregTxnFields.VotePK, err
}

func prepareParticipationKey(a *require.Assertions, fixture *fixtures.RestClientFixture, acctNum uint64, txStartRound, txEndRound, regStartRound, regEndRound uint64, genesisHash crypto.Digest, rootKeys map[int]*account.Root, regTransactions map[int]transactions.SignedTxn) error {
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

	unsignedTxn := persistedParticipation.GenerateRegistrationTransaction(basics.MicroAlgos{Raw: 1000}, basics.Round(txStartRound), basics.Round(txEndRound), [32]byte{})
	copy(unsignedTxn.GenesisHash[:], genesisHash[:])
	if err != nil {
		a.NoError(err)
		return err
	}
	regTransactions[int(txStartRound)] = unsignedTxn.Sign(rootAccount.Secrets())
	return err
}
