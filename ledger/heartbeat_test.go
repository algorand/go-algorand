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

package ledger

import (
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/txntest"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

/* Tests within the `apply` package test the effects of heartbeats, while test
   here are closer to integration tests, they test heartbeats in the context of
   a more realistic ledger. */

// TestHearbeat exercises heartbeat transactions
func TestHeartBeat(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	genBalances, addrs, _ := ledgertesting.NewTestGenesis(func(cfg *ledgertesting.GenesisCfg) {
		cfg.OnlineCount = 2 // addrs[0] and addrs[1] will be online
	})
	heartbeatsBegin := 40

	ledgertesting.TestConsensusRange(t, heartbeatsBegin, 0,
		func(t *testing.T, ver int, cv protocol.ConsensusVersion, cfg config.Local) {
			dl := NewDoubleLedger(t, genBalances, cv, cfg)
			defer dl.Close()

			// empty HbAddress means ZeroAddress, and it's not online
			dl.txn(&txntest.Txn{Type: "hb", Sender: addrs[1]},
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ has no voting keys")

			// addrs[2] is not online, it has no voting keys
			dl.txn(&txntest.Txn{Type: "hb", Sender: addrs[1], HbAddress: addrs[2]},
				addrs[2].String()+" has no voting keys")

			// addrs[1] is online, it has voting keys, but seed is missing
			dl.txn(&txntest.Txn{Type: "hb", Sender: addrs[1], HbAddress: addrs[1]},
				"does not match round 0's seed")

			// NewTestGenesis creates random VoterID. Verification will fail.
			b0, err := dl.generator.BlockHdr(0)
			require.NoError(t, err)
			dl.txn(&txntest.Txn{
				Type:      "hb",
				Sender:    addrs[1],
				HbAddress: addrs[1],
				HbSeed:    b0.Seed,
			},
				"heartbeat failed verification with")

			// keyreg addr[1] so we have a valid VoterID
			const kd = 10
			firstID := basics.OneTimeIDForRound(1, kd)
			otss := crypto.GenerateOneTimeSignatureSecrets(firstID.Batch, 5)
			dl.txn(&txntest.Txn{
				Type:            "keyreg",
				Sender:          addrs[1],
				VotePK:          otss.OneTimeSignatureVerifier,
				SelectionPK:     crypto.VrfPubkey([32]byte{0x01}), // must be non-zero
				VoteKeyDilution: kd,
			})

			// Supply and sign the wrong HbSeed
			dl.txn(&txntest.Txn{
				Type:      "hb",
				Sender:    addrs[1],
				HbAddress: addrs[1],
				HbSeed:    b0.Seed,
				HbProof:   otss.Sign(firstID, b0.Seed).ToHeartbeatProof(),
			},
				"does not match round 1's seed")

			b1, err := dl.generator.BlockHdr(1)
			require.NoError(t, err)

			// Supply the right seed, but sign something else. We're also now
			// setting LastValid and the proper OneTimeIDForRound, so that these
			// tests are failing for the reasons described, not that.
			dl.txn(&txntest.Txn{
				Type:      "hb",
				LastValid: 30,
				Sender:    addrs[1],
				HbAddress: addrs[1],
				HbSeed:    b1.Seed,
				HbProof:   otss.Sign(basics.OneTimeIDForRound(30, kd), b0.Seed).ToHeartbeatProof(),
			},
				"failed verification")

			// Sign the right seed, but supply something else
			dl.txn(&txntest.Txn{
				Type:      "hb",
				LastValid: 30,
				Sender:    addrs[1],
				HbAddress: addrs[1],
				HbSeed:    b0.Seed,
				HbProof:   otss.Sign(basics.OneTimeIDForRound(30, kd), b1.Seed).ToHeartbeatProof(),
			},
				"does not match round 1's")

			// Mismatch the last valid and OneTimeIDForRound
			dl.txn(&txntest.Txn{
				Type:      "hb",
				LastValid: 29,
				Sender:    addrs[1],
				HbAddress: addrs[1],
				HbSeed:    b1.Seed,
				HbProof:   otss.Sign(basics.OneTimeIDForRound(30, kd), b1.Seed).ToHeartbeatProof(),
			},
				"failed verification")

			// now we can make a real heartbeat, with a properly signed blockseed
			dl.txn(&txntest.Txn{
				Type:      "hb",
				LastValid: 30,
				Sender:    addrs[1],
				HbAddress: addrs[1],
				HbSeed:    b1.Seed,
				HbProof:   otss.Sign(basics.OneTimeIDForRound(30, kd), b1.Seed).ToHeartbeatProof(),
			})

		})
}
