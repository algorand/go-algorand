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

package datatest

import (
	"time"

	"github.com/algorand/go-algorand/agreement/agreementtest"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/account"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// var roundDeadline = time.Second
var roundDeadline = 0 * time.Second

// FabricateLedger is a test-only helper to create a new in-memory Ledger and run the protocol through the specified Round with the given accounts
func FabricateLedger(log logging.Logger, ledgerName string, accounts []account.Participation, genesis data.GenesisBalances, lastRound basics.Round) (*data.Ledger, error) {
	const inMem = true
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	ledger, err := data.LoadLedger(log, ledgerName, inMem, protocol.ConsensusCurrentVersion, genesis, "", crypto.Digest{}, nil, cfg)
	if err != nil {
		return nil, err
	}

	numRounds := lastRound - ledger.LastRound()
	err = agreementtest.Simulate(ledgerName, numRounds, roundDeadline, ledgerImpl{l: ledger}, agreementtest.SimpleKeyManager(accounts), entryFactoryImpl{l: ledger}, entryValidatorImpl{l: ledger}, logging.Base())
	return ledger, err
}
