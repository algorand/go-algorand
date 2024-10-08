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

package apply

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestHeartbeat(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// Creator
	sender := basics.Address{0x01}
	voter := basics.Address{0x02}
	const keyDilution = 777

	fv := basics.Round(100)
	lv := basics.Round(1000)

	id := basics.OneTimeIDForRound(lv, keyDilution)
	otss := crypto.GenerateOneTimeSignatureSecrets(1, 2) // This will cover rounds 1-2*777

	mockBal := makeMockBalancesWithAccounts(protocol.ConsensusFuture, map[basics.Address]basics.AccountData{
		sender: {
			MicroAlgos: basics.MicroAlgos{Raw: 10_000_000},
		},
		voter: {
			Status:            basics.Online,
			MicroAlgos:        basics.MicroAlgos{Raw: 100_000_000},
			VoteID:            otss.OneTimeSignatureVerifier,
			VoteKeyDilution:   keyDilution,
			IncentiveEligible: true,
		},
	})

	seed := committee.Seed{0x01, 0x02, 0x03}
	mockHdr := makeMockHeaders(bookkeeping.BlockHeader{
		Round: fv - 1,
		Seed:  seed,
	})

	tx := transactions.Transaction{
		Type: protocol.HeartbeatTx,
		Header: transactions.Header{
			Sender:     sender,
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: fv,
			LastValid:  lv,
		},
		HeartbeatTxnFields: transactions.HeartbeatTxnFields{
			HeartbeatAddress: voter,
			Proof:            otss.Sign(id, seed),
			Seed:             seed,
		},
	}

	rnd := basics.Round(150)
	err := Heartbeat(tx.HeartbeatTxnFields, tx.Header, mockBal, mockHdr, rnd)
	require.NoError(t, err)

	after, err := mockBal.Get(voter, false)
	require.NoError(t, err)
	require.Equal(t, rnd, after.LastHeartbeat)
	require.Zero(t, after.LastProposed) // unchanged
}
