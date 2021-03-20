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

package compactcert

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/compactcert"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/v1"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/test/framework/fixtures"
)

func TestCompactCerts(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	configurableConsensus := make(config.ConsensusProtocols)
	consensusVersion := protocol.ConsensusVersion("test-fast-compactcert")
	consensusParams := config.Consensus[protocol.ConsensusCurrentVersion]
	consensusParams.CompactCertRounds = 8
	consensusParams.CompactCertTopVoters = 1024
	consensusParams.CompactCertVotersLookback = 2
	consensusParams.CompactCertWeightThreshold = (1 << 32) * 30 / 100
	consensusParams.CompactCertSecKQ = 128
	consensusParams.AgreementFilterTimeoutPeriod0 = 500 * time.Millisecond
	configurableConsensus[consensusVersion] = consensusParams

	var fixture fixtures.RestClientFixture
	fixture.SetConsensus(configurableConsensus)
	fixture.Setup(t, filepath.Join("nettemplates", "CompactCert.json"))
	defer fixture.Shutdown()

	restClient, err := fixture.NC.AlgodClient()
	r.NoError(err)

	node0Client := fixture.GetLibGoalClientForNamedNode("Node0")
	node0Wallet, err := node0Client.GetUnencryptedWalletHandle()
	r.NoError(err)
	node0AccountList, err := node0Client.ListAddresses(node0Wallet)
	r.NoError(err)
	node0Account := node0AccountList[0]

	node1Client := fixture.GetLibGoalClientForNamedNode("Node1")
	node1Wallet, err := node1Client.GetUnencryptedWalletHandle()
	r.NoError(err)
	node1AccountList, err := node1Client.ListAddresses(node1Wallet)
	r.NoError(err)
	node1Account := node1AccountList[0]

	var lastCertBlock v1.Block
	libgoal := fixture.LibGoalClient
	for rnd := uint64(1); rnd <= consensusParams.CompactCertRounds*4; rnd++ {
		// send a dummy payment transaction.
		minTxnFee, _, err := fixture.CurrentMinFeeAndBalance()
		r.NoError(err)

		_, err = node0Client.SendPaymentFromUnencryptedWallet(node0Account, node1Account, minTxnFee, rnd, nil)
		r.NoError(err)

		fixture.WaitForRound(rnd, 30*time.Second)
		blk, err := libgoal.Block(rnd)
		r.NoError(err)

		t.Logf("Round %d, block %v\n", rnd, blk)

		if (rnd % consensusParams.CompactCertRounds) == 0 {
			// Must have a merkle commitment for participants
			r.True(len(blk.CompactCertVoters) > 0)
			r.True(blk.CompactCertVotersTotal != 0)

			// Special case: bootstrap validation with the first block
			// that has a merkle root.
			if lastCertBlock.Round == 0 {
				lastCertBlock = blk
			}
		}

		for lastCertBlock.Round != 0 && lastCertBlock.Round+consensusParams.CompactCertRounds < blk.CompactCertNextRound {
			nextCertRound := lastCertBlock.Round + consensusParams.CompactCertRounds

			// Find the cert transaction
			res, err := restClient.TransactionsByAddr(transactions.CompactCertSender.String(), 0, rnd, 4)
			r.NoError(err)

			var compactCert compactcert.Cert
			compactCertFound := false
			for _, txn := range res.Transactions {
				r.Equal(txn.Type, string(protocol.CompactCertTx))
				r.True(txn.CompactCert != nil)
				if txn.CompactCert.CertRound == nextCertRound {
					err = protocol.Decode(txn.CompactCert.Cert, &compactCert)
					r.NoError(err)
					compactCertFound = true
				}
			}
			r.True(compactCertFound)

			nextCertBlock, err := libgoal.Block(nextCertRound)
			r.NoError(err)

			nextCertBlockRaw, err := libgoal.RawBlock(nextCertRound)
			r.NoError(err)

			var nextCertBlockDecoded rpcs.EncodedBlockCert
			err = protocol.Decode(nextCertBlockRaw, &nextCertBlockDecoded)
			r.NoError(err)

			var votersRoot crypto.Digest
			copy(votersRoot[:], lastCertBlock.CompactCertVoters)

			provenWeight, overflowed := basics.Muldiv(lastCertBlock.CompactCertVotersTotal, uint64(consensusParams.CompactCertWeightThreshold), 1<<32)
			r.False(overflowed)

			ccparams := compactcert.Params{
				Msg:          nextCertBlockDecoded.Block.BlockHeader,
				ProvenWeight: provenWeight,
				SigRound:     basics.Round(nextCertBlock.Round + 1),
				SecKQ:        consensusParams.CompactCertSecKQ,
			}
			verif := compactcert.MkVerifier(ccparams, votersRoot)
			err = verif.Verify(&compactCert)
			r.NoError(err)

			lastCertBlock = nextCertBlock
		}
	}

	r.True(lastCertBlock.Round == consensusParams.CompactCertRounds*3)
}
