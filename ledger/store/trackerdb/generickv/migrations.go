// Copyright (C) 2019-2025 Algorand, Inc.
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
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
)

func getSchemaVersion(ctx context.Context, kvr KvRead) (int32, error) {
	// read version entry
	key := schemaVersionKey()
	value, closer, err := kvr.Get(key[:])
	if err == trackerdb.ErrNotFound {
		// ignore the error, return version 0
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	defer closer.Close()

	// parse the bytes into a i32
	version := int32(binary.BigEndian.Uint32(value))

	return version, nil
}

func setSchemaVersion(ctx context.Context, kvw KvWrite, version int32) error {
	// write version entry
	raw := bigEndianUint32(uint32(version))
	key := schemaVersionKey()
	err := kvw.Set(key[:], raw[:])
	if err != nil {
		return err
	}

	return nil
}

type dbForMigrations interface {
	trackerdb.Store
	KvRead
	KvWrite
}

// RunMigrations runs the migrations on the store up to the target version.
func RunMigrations(ctx context.Context, db dbForMigrations, params trackerdb.Params, targetVersion int32) (mgr trackerdb.InitParams, err error) {

	dbVersion, err := getSchemaVersion(ctx, db)
	if err != nil {
		return
	}

	mgr.SchemaVersion = dbVersion
	mgr.VacuumOnStartup = false

	migrator := &migrator{
		currentVersion: dbVersion,
		targetVersion:  targetVersion,
		params:         params,
		db:             db,
	}

	err = migrator.Migrate(ctx)
	if err != nil {
		return
	}

	mgr.SchemaVersion = migrator.currentVersion

	return mgr, nil
}

type migrator struct {
	currentVersion int32
	targetVersion  int32
	params         trackerdb.Params
	db             dbForMigrations
}

func (m *migrator) Migrate(ctx context.Context) error {
	// we cannot rollback
	if m.currentVersion > m.targetVersion {
		return nil
	}
	// upgrade the db one version at at time
	for m.currentVersion < m.targetVersion {
		// run next version upgrade
		switch m.currentVersion {
		case 0: // initial version
			err := m.initialVersion(ctx)
			if err != nil {
				return err
			}
		default:
			// any other version we do nothing
			return nil
		}
	}
	return nil
}

func (m *migrator) setVersion(ctx context.Context, version int32) error {
	// update crrent version in the db
	err := setSchemaVersion(ctx, m.db, version)
	if err != nil {
		return err
	}
	// update current version in the migrator
	m.currentVersion = version
	return nil
}

func (m *migrator) initialVersion(ctx context.Context) error {
	proto := config.Consensus[m.params.InitProto]

	// TODO: make this a batch scope
	err := m.db.TransactionContext(ctx, func(ctx context.Context, tx trackerdb.TransactionScope) (err error) {
		aow, err := tx.MakeAccountsOptimizedWriter(true, false, false, false)
		if err != nil {
			return err
		}

		oaow, err := tx.MakeOnlineAccountsOptimizedWriter(true)
		if err != nil {
			return err
		}

		aw, err := tx.MakeAccountsWriter()
		if err != nil {
			return err
		}

		updRound := basics.Round(0)

		// mark the db as round 0
		err = aw.UpdateAccountsRound(updRound)
		if err != nil {
			return err
		}

		var ot basics.OverflowTracker
		var totals ledgercore.AccountTotals

		// insert initial accounts
		for addr, account := range m.params.InitAccounts {
			// build a trackerdb.BaseAccountData to pass to the DB
			var bad trackerdb.BaseAccountData
			bad.SetAccountData(&account)
			// insert the account
			_, err = aow.InsertAccount(addr, account.NormalizedOnlineBalance(proto), bad)
			if err != nil {
				return err
			}

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

				_, err = oaow.InsertOnlineAccount(addr, account.NormalizedOnlineBalance(proto), baseOnlineAD, uint64(updRound), uint64(baseOnlineAD.VoteLastValid))
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
		err = aw.AccountsPutTotals(totals, false)
		if err != nil {
			return err
		}

		// insert online params
		params := []ledgercore.OnlineRoundParamsData{
			{
				OnlineSupply:    totals.Online.Money.Raw,
				RewardsLevel:    totals.RewardsLevel,
				CurrentProtocol: m.params.InitProto,
			},
		}
		err = aw.AccountsPutOnlineRoundParams(params, basics.Round(0))
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	// KV store starts at version 11
	return m.setVersion(ctx, 11)
}
