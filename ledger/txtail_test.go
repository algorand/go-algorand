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

package ledger

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func TestTxTailCheckdup(t *testing.T) {
	ledger := makeMockLedgerForTracker(t, true, 1, protocol.ConsensusCurrentVersion)
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	tail := txTail{}
	require.NoError(t, tail.loadFromDisk(ledger))

	lastRound := basics.Round(proto.MaxTxnLife)
	lookback := basics.Round(100)
	txvalidity := basics.Round(10)
	leasevalidity := basics.Round(32)

	// push 1000 rounds into the txtail
	for rnd := basics.Round(1); rnd < lastRound; rnd++ {
		blk := bookkeeping.Block{
			BlockHeader: bookkeeping.BlockHeader{
				Round: rnd,
				UpgradeState: bookkeeping.UpgradeState{
					CurrentProtocol: protocol.ConsensusCurrentVersion,
				},
			},
		}

		txids := make(map[transactions.Txid]basics.Round)
		txids[transactions.Txid(crypto.Hash([]byte{byte(rnd % 256), byte(rnd / 256), byte(1)}))] = rnd + txvalidity
		txleases := make(map[txlease]basics.Round)
		txleases[txlease{sender: basics.Address(crypto.Hash([]byte{byte(rnd % 256), byte(rnd / 256), byte(2)})), lease: crypto.Hash([]byte{byte(rnd % 256), byte(rnd / 256), byte(3)})}] = rnd + leasevalidity

		tail.newBlock(blk, StateDelta{accts: make(map[basics.Address]accountDelta), hdr: &blk.BlockHeader, Txids: txids, txleases: txleases})
		tail.committedUpTo(rnd.SubSaturate(lookback))
	}

	// test txid duplication testing.
	for rnd := basics.Round(1); rnd < lastRound; rnd++ {
		txid := transactions.Txid(crypto.Hash([]byte{byte(rnd % 256), byte(rnd / 256), byte(1)}))
		err := tail.checkDup(proto, basics.Round(0), basics.Round(0), rnd+txvalidity, txid, txlease{})
		require.Errorf(t, err, "round %d", rnd)
		if rnd < lastRound-lookback-txvalidity-1 {
			var missingRoundErr *txtailMissingRound
			require.Truef(t, errors.As(err, &missingRoundErr), "error a txtailMissingRound(%d) : %v ", rnd, err)
		} else {
			var txInLedgerErr *TransactionInLedgerError
			require.Truef(t, errors.As(err, &txInLedgerErr), "error a TransactionInLedgerError(%d) : %v ", rnd, err)
		}
	}

	// test lease detection
	for rnd := basics.Round(1); rnd < lastRound; rnd++ {
		lease := txlease{sender: basics.Address(crypto.Hash([]byte{byte(rnd % 256), byte(rnd / 256), byte(2)})), lease: crypto.Hash([]byte{byte(rnd % 256), byte(rnd / 256), byte(3)})}
		err := tail.checkDup(proto, rnd, basics.Round(0), rnd, transactions.Txid{}, lease)
		require.Errorf(t, err, "round %d", rnd)
		if rnd < lastRound-lookback-1 {
			var missingRoundErr *txtailMissingRound
			require.Truef(t, errors.As(err, &missingRoundErr), "error a txtailMissingRound(%d) : %v ", rnd, err)
		} else {
			var leaseInLedgerErr *LeaseInLedgerError
			require.Truef(t, errors.As(err, &leaseInLedgerErr), "error a LeaseInLedgerError(%d) : %v ", rnd, err)
		}
	}
}
