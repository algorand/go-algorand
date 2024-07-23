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
	"context"
	"fmt"

	"github.com/algorand/go-algorand/ledger/store/trackerdb"
)

// trackerDBInitialize initializes the accounts DB if needed and return current account round.
// as part of the initialization, it tests the current database schema version, and perform upgrade
// procedures to bring it up to the database schema supported by the binary.
func trackerDBInitialize(l ledgerForTracker, catchpointEnabled bool, dbPathPrefix string) (mgr trackerdb.InitParams, err error) {
	dbs := l.trackerDB()
	bdbs := l.blockDB()
	log := l.trackerLog()

	lastestBlockRound := l.Latest()

	if l.GenesisAccounts() == nil {
		err = fmt.Errorf("trackerDBInitialize: initAccounts not set")
		return
	}

	tp := trackerdb.Params{
		InitAccounts:      l.GenesisAccounts(),
		InitProto:         l.GenesisProtoVersion(),
		GenesisHash:       l.GenesisHash(),
		FromCatchpoint:    false,
		CatchpointEnabled: catchpointEnabled,
		DbPathPrefix:      dbPathPrefix,
		BlockDb:           bdbs,
	}

	// run migrations
	mgr, err = dbs.RunMigrations(context.Background(), tp, log, trackerdb.AccountDBVersion)
	if err != nil {
		return
	}

	// create reader for db
	ar, err := dbs.MakeAccountsReader()
	if err != nil {
		return
	}

	// check current round
	lastBalancesRound, err := ar.AccountsRound()
	if err != nil {
		return
	}

	// Check for blocks DB and tracker DB un-sync
	if lastBalancesRound > lastestBlockRound {
		log.Warnf("trackerDBInitialize: resetting accounts DB (on round %v, but blocks DB's latest is %v)", lastBalancesRound, lastestBlockRound)
		err = dbs.Transaction(func(ctx context.Context, tx trackerdb.TransactionScope) error {
			var aw trackerdb.AccountsWriterExt
			aw, err = tx.MakeAccountsWriter()
			if err != nil {
				return err
			}
			err = aw.AccountsReset(ctx)
			if err != nil {
				return err
			}
			mgr, err = tx.RunMigrations(ctx, tp, log, trackerdb.AccountDBVersion)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return
		}
	}

	return
}
