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

package stateproofs

import (
	"encoding/binary"
	//	"fmt"
	"path/filepath"
	"time"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func helperFillSignBroadcast(client libgoal.Client, wh []byte, sender string, tx transactions.Transaction, err error) (string, error) {
	if err != nil {
		return "", err
	}

	// we're sending many txns, so might need to raise the fee
	tx, err = client.FillUnsignedTxTemplate(sender, 0, 0, 1000000, tx)
	if err != nil {
		return "", err
	}

	return client.SignAndBroadcastTransaction(wh, nil, tx)
}

// prepares a send algo transaction
func sendTransaction(
	round uint64,
	sender basics.Address,
	receiver basics.Address,
	amount uint64,
	note []byte,
	genesisHash crypto.Digest) (txn transactions.Transaction) {

	txn = transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: config.Consensus[protocol.ConsensusCurrentVersion].MinTxnFee*10},
			FirstValid:  basics.Round(round),
			LastValid:   basics.Round(round + 1000),
			GenesisHash: genesisHash,
			Note:        note,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: amount},
		},
	}
	return
}

func TestNoRoomForSP(t *testing.T) {
	partitiontest.PartitionTest(t)
	defer fixtures.ShutdownSynchronizedTest(t)

	t.Parallel()
	a := require.New(fixtures.SynchronizedTest(t))

	var fixture fixtures.RestClientFixture
	configurableConsensus := make(config.ConsensusProtocols)
	consensusVersion := protocol.ConsensusVersion("future")
	consensusParams := getDefaultStateProofConsensusParams()
	configurableConsensus[consensusVersion] = consensusParams

	fixture.SetConsensus(configurableConsensus)
	fixture.SetupNoStart(t, filepath.Join("nettemplates", "TwoNodes50EachFuture.json"))

	// update the configuration file to enable the developer API
	dir, err := fixture.GetNodeDir("Primary")
	a.NoError(err)

	cfg, err := config.LoadConfigFromDisk(dir)
	a.NoError(err)
	cfg.TxPoolSize = 0
	cfg.SaveToDisk(dir)

	dir, err = fixture.GetNodeDir("Node")
	a.NoError(err)
	cfg.SaveToDisk(dir)

	fixture.Start()
	defer fixture.Shutdown()

	relay := fixture.GetLibGoalClientForNamedNode("Primary")
	relayWallet, err := relay.GetUnencryptedWalletHandle()
	require.NoError(t, err)
	relayAccounts, err := relay.ListAddresses(relayWallet)
	require.NoError(t, err)
	relayAccount, err := basics.UnmarshalChecksumAddress(relayAccounts[0])
	require.NoError(t, err)
	//	node := fixture.GetLibGoalClientForNamedNode("Node")

	params, err := relay.SuggestedParams()
	require.NoError(t, err)

	var genesisHash crypto.Digest
	copy(genesisHash[:], params.GenesisHash)

	maxNumTransactions := 2000000//10000000000000
	for i := 0; i < maxNumTransactions; i++ {
		relayWallet, err = relay.GetUnencryptedWalletHandle()
		require.NoError(t, err)

		params, err = relay.SuggestedParams()
		require.NoError(t, err)

		note := make([]byte, 8)
		binary.BigEndian.PutUint64(note, uint64(i))
		tx := sendTransaction(params.LastRound+1, relayAccount, relayAccount, 10, note, genesisHash)
		_, err := helperFillSignBroadcast(relay, relayWallet, relayAccounts[0], tx, err)
		if err != nil {
			for err != nil {
				_, err = helperFillSignBroadcast(relay, relayWallet, relayAccounts[0], tx, err)
			}
			//			fmt.Printf("err: %v\n", err)
			err = fixture.WaitForRound(params.LastRound+1, 30*time.Second)
			require.NoError(t, err)
			i = i - 1
		}
		//		require.NoError(t, err)		
		/*		for err != nil {
			time.Sleep(5*consensusParams.AgreementFilterTimeout)
			_, err = helperFillSignBroadcast(relay, relayWallet, relayAccounts[0], tx, err)
		}*/
	}
}
