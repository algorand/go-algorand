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

package upgrades

import (
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/framework/fixtures"
	"github.com/stretchr/testify/require"
)

func TestKeysWithoutStateProofKeyCannotRegister(t *testing.T) {
	a := require.New(fixtures.SynchronizedTest(t))

	consensus := getStateProofConcensus()

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(consensus)
	fixture.Setup(t, filepath.Join("nettemplates", "TwoNodesWithoutStateProofPartkeys.json"))
	defer fixture.Shutdown()
	lastValid := uint64(1000 * 5)

	a.NoError(registerKey(&fixture, a, lastValid, protocol.ConsensusV29))
	a.Error(registerKey(&fixture, a, lastValid+1, protocol.ConsensusFuture))

	runUntilProtocolUpgrades(a, &fixture)

	a.Error(registerKey(&fixture, a, lastValid+2, protocol.ConsensusV29))
	a.NoError(registerKey(&fixture, a, lastValid+3, protocol.ConsensusFuture))
}

func registerKey(fixture *fixtures.RestClientFixture, a *require.Assertions, lastValid uint64, ver protocol.ConsensusVersion) error {
	client := fixture.GetLibGoalClientForNamedNode("Node")
	wh, err := client.GetUnencryptedWalletHandle()
	a.NoError(err)
	actList, err := client.ListAddresses(wh)
	a.NoError(err)
	addr := actList[0]

	pongBalance, err := client.GetBalance(addr)
	a.NoError(err)
	a.Greater(pongBalance, uint64(10000))

	partKey, _, err := client.GenParticipationKeys(addr, 1, lastValid, 1000)
	a.NoError(err)

	cparams := config.Consensus[ver]

	tx := partKey.GenerateRegistrationTransaction(
		basics.MicroAlgos{Raw: 1000},
		0,
		100,
		[32]byte{},
		cparams,
	)

	if cparams.SupportGenesisHash {
		prms, err := client.SuggestedParams()
		a.NoError(err)

		var genHash crypto.Digest
		copy(genHash[:], prms.GenesisHash)
		tx.GenesisHash = genHash
	}

	_, err = client.SignAndBroadcastTransaction(wh, nil, tx)
	return err
}

func getStateProofConcensus() config.ConsensusProtocols {
	consensus := generateFastUpgradeConsensus()

	// TODO: set inside concensus file!
	consensus[consensusTestFastUpgrade(protocol.ConsensusV29)].
		ApprovedUpgrades[consensusTestFastUpgrade(protocol.ConsensusFuture)] = 0
	return consensus
}
