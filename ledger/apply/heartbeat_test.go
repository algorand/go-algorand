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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/data/txntest"
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

	test := txntest.Txn{
		Type:       protocol.HeartbeatTx,
		Sender:     sender,
		Fee:        basics.MicroAlgos{Raw: 1},
		FirstValid: fv,
		LastValid:  lv,
		HbAddress:  voter,
		HbProof:    otss.Sign(id, seed),
		HbSeed:     seed,
	}

	tx := test.Txn()

	rnd := basics.Round(150)
	// no fee
	err := Heartbeat(tx.HeartbeatTxnFields, tx.Header, mockBal, mockHdr, rnd)
	require.ErrorContains(t, err, "cheap heartbeat")

	test.Fee = basics.MicroAlgos{Raw: 10}
	tx = test.Txn()
	// just as bad: cheap
	err = Heartbeat(tx.HeartbeatTxnFields, tx.Header, mockBal, mockHdr, rnd)
	require.ErrorContains(t, err, "cheap heartbeat")

	test.Fee = 1000
	tx = test.Txn()
	err = Heartbeat(tx.HeartbeatTxnFields, tx.Header, mockBal, mockHdr, rnd)
	require.NoError(t, err)

	after, err := mockBal.Get(voter, false)
	require.NoError(t, err)
	require.Equal(t, rnd, after.LastHeartbeat)
	require.Zero(t, after.LastProposed) // unchanged
}

// TestCheapRules ensures a heartbeat can only have a low fee if the account
// being heartbeat for is online, under risk of suspension by challenge, and
// incentive eligible.
func TestCheapRules(t *testing.T) {
	type tcase struct {
		rnd              basics.Round
		addrStart        byte
		status           basics.Status
		incentiveEligble bool
		note             []byte
		lease            [32]byte
		rekey            [32]byte
		err              string
	}
	empty := [32]byte{}
	// Grace period is 200. For the second half of the grace period (1101-1200),
	// the heartbeat is free for online, incentive eligible, challenged accounts.
	cases := []tcase{
		// test of range
		{1100, 0x01, basics.Online, true, nil, empty, empty, "no challenge"},
		{1101, 0x01, basics.Online, true, nil, empty, empty, ""},
		{1200, 0x01, basics.Online, true, nil, empty, empty, ""},
		{1201, 0x01, basics.Online, true, nil, empty, empty, "no challenge"},

		// test of the other requirements
		{1101, 0x01, basics.Online, true, []byte("note"), empty, empty, "not allowed to have a note"},
		{1101, 0x01, basics.Online, true, nil, [32]byte{'l', 'e', 'a', 's', 'e'}, empty, "not allowed to have a lease"},
		{1101, 0x01, basics.Online, true, nil, empty, [32]byte{'r', 'e', 'k', 'e', 'y'}, "not allowed to rekey"},
		{1101, 0xf1, basics.Online, true, nil, empty, empty, "not challenged by"},
		{1101, 0x01, basics.Offline, true, nil, empty, empty, "not allowed for Offline"},
		{1101, 0x01, basics.Online, false, nil, empty, empty, "not allowed when not IncentiveEligible"},
	}
	for _, tc := range cases {
		const keyDilution = 777

		lv := basics.Round(tc.rnd + 10)

		id := basics.OneTimeIDForRound(lv, keyDilution)
		otss := crypto.GenerateOneTimeSignatureSecrets(1, 10) // This will cover rounds 1-10*777

		sender := basics.Address{0x01}
		voter := basics.Address{tc.addrStart}
		mockBal := makeMockBalancesWithAccounts(protocol.ConsensusFuture, map[basics.Address]basics.AccountData{
			sender: {
				MicroAlgos: basics.MicroAlgos{Raw: 10_000_000},
			},
			voter: {
				Status:            tc.status,
				MicroAlgos:        basics.MicroAlgos{Raw: 100_000_000},
				VoteID:            otss.OneTimeSignatureVerifier,
				VoteKeyDilution:   keyDilution,
				IncentiveEligible: tc.incentiveEligble,
			},
		})

		seed := committee.Seed{0x01, 0x02, 0x03}
		mockHdr := makeMockHeaders()
		mockHdr.setFallback(bookkeeping.BlockHeader{
			UpgradeState: bookkeeping.UpgradeState{
				CurrentProtocol: protocol.ConsensusFuture,
			},
			Seed: seed,
		})
		txn := txntest.Txn{
			Type:       protocol.HeartbeatTx,
			Sender:     sender,
			Fee:        basics.MicroAlgos{Raw: 1},
			FirstValid: tc.rnd - 10,
			LastValid:  tc.rnd + 10,
			Lease:      tc.lease,
			Note:       tc.note,
			RekeyTo:    tc.rekey,
			HbAddress:  voter,
			HbProof:    otss.Sign(id, seed),
			HbSeed:     seed,
		}

		tx := txn.Txn()
		fmt.Printf("tc %+v\n", tc)
		err := Heartbeat(tx.HeartbeatTxnFields, tx.Header, mockBal, mockHdr, tc.rnd)
		if tc.err == "" {
			assert.NoError(t, err)
		} else {
			assert.ErrorContains(t, err, tc.err, "%+v", tc)
		}
	}
}