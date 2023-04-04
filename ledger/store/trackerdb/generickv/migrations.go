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

package generickv

import (
	"context"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
)

func RunMigrations(ctx context.Context, db trackerdb.TrackerStore, params trackerdb.Params, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	proto := config.Consensus[params.InitProto]

	// if targetVersion < 9 {
	// 	return mgr, fmt.Errorf("KV implementations start at schema version 9")
	// }

	// TODO: make this a batch scope
	err = db.TransactionContext(ctx, func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		aow, err := tx.MakeAccountsOptimizedWriter(true, false, false, false)
		if err != nil {
			return err
		}

		oaow, err := tx.MakeOnlineAccountsOptimizedWriter(true)
		if err != nil {
			return err
		}

		arw, err := tx.MakeAccountsReaderWriter()
		if err != nil {
			return err
		}

		updRound := basics.Round(0)

		// mark the db as round 0
		err = arw.UpdateAccountsRound(updRound)
		if err != nil {
			return err
		}

		var ot basics.OverflowTracker
		var totals ledgercore.AccountTotals

		// insert initial accounts
		for addr, account := range params.InitAccounts {
			// build a trackerdb.BaseAccountData to pass to the DB
			var bad trackerdb.BaseAccountData
			bad.SetAccountData(&account)
			// insert the account
			aow.InsertAccount(addr, account.NormalizedOnlineBalance(proto), bad)
			// build a ledgercore.AccountData to track the totals
			ad := ledgercore.ToAccountData(account)
			// track the totals
			totals.AddAccount(proto, ad, &ot)

			// insert online account (if online)
			if bad.Status == basics.Online {
				var baseOnlineAD trackerdb.BaseOnlineAccountData
				baseOnlineAD.BaseVotingData = bad.BaseVotingData
				baseOnlineAD.MicroAlgos = bad.MicroAlgos
				baseOnlineAD.RewardsBase = bad.RewardsBase

				_, err := oaow.InsertOnlineAccount(addr, account.NormalizedOnlineBalance(proto), baseOnlineAD, uint64(updRound), uint64(baseOnlineAD.VoteLastValid))
				if err != nil {
					return err
				}
			}
		}

		// make sure we didn't overflow
		if ot.Overflowed {
			return fmt.Errorf("overflow computing totals")
		}

		// insert the totals
		err = arw.AccountsPutTotals(totals, false)
		if err != nil {
			return err
		}

		// insert online params
		params := []ledgercore.OnlineRoundParamsData{
			ledgercore.OnlineRoundParamsData{
				OnlineSupply:    totals.Online.Money.Raw,
				RewardsLevel:    totals.RewardsLevel,
				CurrentProtocol: params.InitProto,
			},
		}
		err = arw.AccountsPutOnlineRoundParams(params, basics.Round(0))
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return mgr, err
	}

	// KV's start at version 9
	mgr.SchemaVersion = 9
	mgr.VacuumOnStartup = false

	return mgr, nil
}
