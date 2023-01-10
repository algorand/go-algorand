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

package ledger

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/algorand/go-algorand/ledger/store"
)

// trackerDBInitialize initializes the accounts DB if needed and return current account round.
// as part of the initialization, it tests the current database schema version, and perform upgrade
// procedures to bring it up to the database schema supported by the binary.
func trackerDBInitialize(l ledgerForTracker, catchpointEnabled bool, dbPathPrefix string) (mgr store.TrackerDBInitParams, err error) {
	dbs := l.trackerDB()
	bdbs := l.blockDB()
	log := l.trackerLog()

	lastestBlockRound := l.Latest()

	if l.GenesisAccounts() == nil {
		err = fmt.Errorf("trackerDBInitialize: initAccounts not set")
		return
	}

	err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		arw := store.NewAccountsSQLReaderWriter(tx)

		tp := store.TrackerDBParams{
			InitAccounts:      l.GenesisAccounts(),
			InitProto:         l.GenesisProtoVersion(),
			GenesisHash:       l.GenesisHash(),
			FromCatchpoint:    false,
			CatchpointEnabled: catchpointEnabled,
			DbPathPrefix:      dbPathPrefix,
			BlockDb:           bdbs,
		}
		var err0 error
		mgr, err0 = store.RunMigrations(ctx, tx, tp, log, store.AccountDBVersion)
		if err0 != nil {
			return err0
		}
		lastBalancesRound, err := arw.AccountsRound()
		if err != nil {
			return err
		}
		// Check for blocks DB and tracker DB un-sync
		if lastBalancesRound > lastestBlockRound {
			log.Warnf("trackerDBInitialize: resetting accounts DB (on round %v, but blocks DB's latest is %v)", lastBalancesRound, lastestBlockRound)
			err0 = arw.AccountsReset(ctx)
			if err0 != nil {
				return err0
			}
			mgr, err0 = store.RunMigrations(ctx, tx, tp, log, store.AccountDBVersion)
			if err0 != nil {
				return err0
			}
		}
		return nil
	})

	return
}
