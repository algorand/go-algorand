// Copyright (C) 2019-2023 Algorand, Inc.
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

package simulationtesting

import (
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/txntest"
	"github.com/algorand/go-algorand/ledger"
	ledgertesting "github.com/algorand/go-algorand/ledger/testing"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

// ==============================
// > Simulation Test Helpers
// ==============================

type Account struct {
	Addr     basics.Address
	Sk       *crypto.SignatureSecrets
	AcctData basics.AccountData
}

type TxnInfo struct {
	LatestHeader bookkeeping.BlockHeader
}

func (info TxnInfo) CurrentProtocolParams() config.ConsensusParams {
	return config.Consensus[info.LatestHeader.CurrentProtocol]
}

func (info TxnInfo) NewTxn(txn txntest.Txn) txntest.Txn {
	txn.FirstValid = info.LatestHeader.Round
	txn.GenesisID = info.LatestHeader.GenesisID
	txn.GenesisHash = info.LatestHeader.GenesisHash
	txn.FillDefaults(info.CurrentProtocolParams())
	return txn
}

func PrepareSimulatorTest(t *testing.T) (l *data.Ledger, accounts []Account, txnInfo TxnInfo) {
	genesisInitState, keys := ledgertesting.GenerateInitState(t, protocol.ConsensusCurrentVersion, 100)

	// Prepare ledger
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	log := logging.TestingLog(t)
	log.SetLevel(logging.Warn)
	realLedger, err := ledger.OpenLedger(log, t.Name(), inMem, genesisInitState, cfg)
	require.NoError(t, err, "could not open ledger")

	l = &data.Ledger{Ledger: realLedger}
	require.NotNil(t, l)

	// Reformat accounts
	accounts = make([]Account, len(keys)-2) // -2 for pool and sink accounts
	i := 0
	for addr, key := range keys {
		if addr == ledgertesting.PoolAddr() || addr == ledgertesting.SinkAddr() {
			continue
		}

		acctData := genesisInitState.Accounts[addr]
		accounts[i] = Account{
			Addr:     addr,
			Sk:       key,
			AcctData: acctData,
		}
		i++
	}

	hdr, err := l.BlockHdr(l.Latest())
	require.NoError(t, err)
	txnInfo = TxnInfo{hdr}

	return
}
