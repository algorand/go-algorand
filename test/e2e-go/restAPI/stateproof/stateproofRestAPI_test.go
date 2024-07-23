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

package stateproof

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/algorand/go-algorand/util/db"
	"github.com/stretchr/testify/require"

	helper "github.com/algorand/go-algorand/test/e2e-go/restAPI"
)

func TestStateProofInParticipationInfo(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture

	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	localFixture.SetConsensus(config.ConsensusProtocols{protocol.ConsensusCurrentVersion: proto})

	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient
	helper.WaitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	a.NotEmpty(someAddress, "no addr with funds")

	addr, err := basics.UnmarshalChecksumAddress(someAddress)
	a.NoError(err)

	params, err := testClient.SuggestedParams()
	a.NoError(err)

	firstRound := basics.Round(params.LastRound + 1)
	lastRound := basics.Round(params.LastRound + 1000)
	dilution := uint64(100)
	randomVotePKStr := helper.RandomString(32)
	var votePK crypto.OneTimeSignatureVerifier
	copy(votePK[:], randomVotePKStr)
	randomSelPKStr := helper.RandomString(32)
	var selPK crypto.VRFVerifier
	copy(selPK[:], randomSelPKStr)
	var mssRoot [merklesignature.MerkleSignatureSchemeRootSize]byte
	randomRootStr := helper.RandomString(merklesignature.MerkleSignatureSchemeRootSize)
	copy(mssRoot[:], randomRootStr)
	var gh crypto.Digest
	copy(gh[:], params.GenesisHash)

	tx := transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:      addr,
			Fee:         basics.MicroAlgos{Raw: 10000},
			FirstValid:  firstRound,
			LastValid:   lastRound,
			GenesisHash: gh,
		},
		KeyregTxnFields: transactions.KeyregTxnFields{
			VotePK:           votePK,
			SelectionPK:      selPK,
			VoteFirst:        firstRound,
			StateProofPK:     mssRoot,
			VoteLast:         lastRound,
			VoteKeyDilution:  dilution,
			Nonparticipation: false,
		},
	}
	txID, err := testClient.SignAndBroadcastTransaction(wh, nil, tx)
	a.NoError(err)
	_, err = helper.WaitForTransaction(t, testClient, txID, 120*time.Second)
	a.NoError(err)

	account, err := testClient.AccountInformation(someAddress, false)
	a.NoError(err)
	a.NotNil(account.Participation.StateProofKey)

	actual := [merklesignature.MerkleSignatureSchemeRootSize]byte{}
	copy(actual[:], *account.Participation.StateProofKey)
	a.Equal(mssRoot, actual)
}

func TestStateProofParticipationKeysAPI(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture

	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50Each.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient
	helper.WaitForRoundOne(t, testClient)

	partdb, err := db.MakeErasableAccessor(filepath.Join(testClient.DataDir(), "/..", "/Wallet1.0.3000.partkey"))
	a.NoError(err)

	partkey, err := account.RestoreParticipation(partdb)
	a.NoError(err)

	pRoot, err := testClient.GetParticipationKeys()
	a.NoError(err)

	actual := [merklesignature.MerkleSignatureSchemeRootSize]byte{}
	a.NotNil(pRoot[0].Key.StateProofKey)
	copy(actual[:], *pRoot[0].Key.StateProofKey)
	a.Equal(partkey.StateProofSecrets.GetVerifier().Commitment[:], actual[:])
}

func TestNilStateProofInParticipationInfo(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	a := require.New(fixtures.SynchronizedTest(t))
	var localFixture fixtures.RestClientFixture

	localFixture.Setup(t, filepath.Join("nettemplates", "TwoNodes50EachV30.json"))
	defer localFixture.Shutdown()

	testClient := localFixture.LibGoalClient
	helper.WaitForRoundOne(t, testClient)
	wh, err := testClient.GetUnencryptedWalletHandle()
	a.NoError(err)
	addresses, err := testClient.ListAddresses(wh)
	a.NoError(err)
	_, someAddress := helper.GetMaxBalAddr(t, testClient, addresses)
	a.NotEmpty(someAddress, "no addr with funds")

	addr, err := basics.UnmarshalChecksumAddress(someAddress)
	a.NoError(err)

	params, err := testClient.SuggestedParams()
	a.NoError(err)

	firstRound := basics.Round(1)
	lastRound := basics.Round(20)
	dilution := uint64(100)
	randomVotePKStr := helper.RandomString(32)
	var votePK crypto.OneTimeSignatureVerifier
	copy(votePK[:], []byte(randomVotePKStr))
	randomSelPKStr := helper.RandomString(32)
	var selPK crypto.VRFVerifier
	copy(selPK[:], []byte(randomSelPKStr))
	var gh crypto.Digest
	copy(gh[:], params.GenesisHash)

	tx := transactions.Transaction{
		Type: protocol.KeyRegistrationTx,
		Header: transactions.Header{
			Sender:      addr,
			Fee:         basics.MicroAlgos{Raw: 10000},
			FirstValid:  firstRound,
			LastValid:   lastRound,
			GenesisHash: gh,
		},
		KeyregTxnFields: transactions.KeyregTxnFields{
			VotePK:           votePK,
			SelectionPK:      selPK,
			VoteFirst:        firstRound,
			VoteLast:         lastRound,
			VoteKeyDilution:  dilution,
			Nonparticipation: false,
		},
	}
	txID, err := testClient.SignAndBroadcastTransaction(wh, nil, tx)
	a.NoError(err)
	_, err = helper.WaitForTransaction(t, testClient, txID, 30*time.Second)
	a.NoError(err)

	account, err := testClient.AccountInformation(someAddress, false)
	a.NoError(err)
	a.Nil(account.Participation.StateProofKey)
}
