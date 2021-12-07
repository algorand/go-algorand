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
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
)

type trackerDBParams struct {
	initAccounts      map[basics.Address]basics.AccountData
	initProto         config.ConsensusParams
	catchpointEnabled bool
	dbPathPrefix      string
}

type trackerDBSchemaInitializer struct {
	trackerDBParams

	// schemaVersion contains current db version
	schemaVersion int32
	// vacuumOnStartup controls whether the accounts database would get vacuumed on startup.
	vacuumOnStartup bool
	// newDatabase indicates if the db is newly created
	newDatabase bool

	log logging.Logger
}

type trackerDBInitParams struct {
	schemaVersion   int32
	vacuumOnStartup bool
}

// trackerDBInitialize initializes the accounts DB if needed and return current account round.
// as part of the initialization, it tests the current database schema version, and perform upgrade
// procedures to bring it up to the database schema supported by the binary.
func trackerDBInitialize(l ledgerForTracker, catchpointEnabled bool, dbPathPrefix string) (mgr trackerDBInitParams, err error) {
	dbs := l.trackerDB()
	log := l.trackerLog()

	lastestBlockRound := l.Latest()

	if l.GenesisAccounts() == nil {
		err = fmt.Errorf("trackerDBInitialize: initAccounts not set")
		return
	}

	err = dbs.Wdb.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		tp := trackerDBParams{l.GenesisAccounts(), l.GenesisProto(), catchpointEnabled, dbPathPrefix}
		var err0 error
		mgr, err0 = trackerDBInitializeImpl(ctx, tx, tp, log)
		if err0 != nil {
			return err0
		}
		lastBalancesRound, err := accountsRound(tx)
		if err != nil {
			return err
		}
		// Check for blocks DB and tracker DB un-sync
		if lastBalancesRound > lastestBlockRound {
			log.Warnf("trackerDBInitialize: resetting accounts DB (on round %v, but blocks DB's latest is %v)", lastBalancesRound, lastestBlockRound)
			err0 = accountsReset(tx)
			if err0 != nil {
				return err0
			}
			mgr, err0 = trackerDBInitializeImpl(ctx, tx, tp, log)
			if err0 != nil {
				return err0
			}
		}
		return nil
	})

	return
}

// trackerDBInitializeImpl initializes the accounts DB if needed and return current account round.
// as part of the initialization, it tests the current database schema version, and perform upgrade
// procedures to bring it up to the database schema supported by the binary.
func trackerDBInitializeImpl(ctx context.Context, tx *sql.Tx, params trackerDBParams, log logging.Logger) (mgr trackerDBInitParams, err error) {
	// check current database version.
	dbVersion, err := db.GetUserVersion(ctx, tx)
	if err != nil {
		return trackerDBInitParams{}, fmt.Errorf("trackerDBInitialize unable to read database schema version : %v", err)
	}

	tu := trackerDBSchemaInitializer{
		trackerDBParams: params,
		schemaVersion:   dbVersion,
		log:             log,
	}

	// if database version is greater than supported by current binary, write a warning. This would keep the existing
	// fallback behavior where we could use an older binary iff the schema happen to be backward compatible.
	if tu.version() > accountDBVersion {
		tu.log.Warnf("trackerDBInitialize database schema version is %d, but algod supports only %d", tu.version(), accountDBVersion)
	}

	if tu.version() < accountDBVersion {
		tu.log.Infof("trackerDBInitialize upgrading database schema from version %d to version %d", tu.version(), accountDBVersion)
		// newDatabase is determined during the tables creations. If we're filling the database with accounts,
		// then we set this variable to true, allowing some of the upgrades to be skipped.
		for tu.version() < accountDBVersion {
			tu.log.Infof("trackerDBInitialize performing upgrade from version %d", tu.version())
			// perform the initialization/upgrade
			switch tu.version() {
			case 0:
				err = tu.upgradeDatabaseSchema0(ctx, tx)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 0 : %v", err)
					return
				}
			case 1:
				err = tu.upgradeDatabaseSchema1(ctx, tx)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 1 : %v", err)
					return
				}
			case 2:
				err = tu.upgradeDatabaseSchema2(ctx, tx)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 2 : %v", err)
					return
				}
			case 3:
				err = tu.upgradeDatabaseSchema3(ctx, tx)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 3 : %v", err)
					return
				}
			case 4:
				err = tu.upgradeDatabaseSchema4(ctx, tx)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 4 : %v", err)
					return
				}
			default:
				return trackerDBInitParams{}, fmt.Errorf("trackerDBInitialize unable to upgrade database from schema version %d", tu.schemaVersion)
			}
		}
		tu.log.Infof("trackerDBInitialize database schema upgrade complete")
	}

	return trackerDBInitParams{tu.schemaVersion, tu.vacuumOnStartup}, nil
}

func (tu *trackerDBSchemaInitializer) setVersion(ctx context.Context, tx *sql.Tx, version int32) (err error) {
	oldVersion := tu.schemaVersion
	tu.schemaVersion = version
	_, err = db.SetUserVersion(ctx, tx, tu.schemaVersion)
	if err != nil {
		return fmt.Errorf("trackerDBInitialize unable to update database schema version from %d to %d: %v", oldVersion, version, err)
	}
	return nil
}

func (tu trackerDBSchemaInitializer) version() int32 {
	return tu.schemaVersion
}

// upgradeDatabaseSchema0 upgrades the database schema from version 0 to version 1
//
// Schema of version 0 is expected to be aligned with the schema used on version 2.0.8 or before.
// Any database of version 2.0.8 would be of version 0. At this point, the database might
// have the following tables : ( i.e. a newly created database would not have these )
// * acctrounds
// * accounttotals
// * accountbase
// * assetcreators
// * storedcatchpoints
// * accounthashes
// * catchpointstate
//
// As the first step of the upgrade, the above tables are being created if they do not already exists.
// Following that, the assetcreators table is being altered by adding a new column to it (ctype).
// Last, in case the database was just created, it would get initialized with the following:
// The accountbase would get initialized with the au.initAccounts
// The accounttotals would get initialized to align with the initialization account added to accountbase
// The acctrounds would get updated to indicate that the balance matches round 0
//
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema0(ctx context.Context, tx *sql.Tx) (err error) {
	tu.log.Infof("upgradeDatabaseSchema0 initializing schema")
	tu.newDatabase, err = accountsInit(tx, tu.initAccounts, tu.initProto)
	if err != nil {
		return fmt.Errorf("upgradeDatabaseSchema0 unable to initialize schema : %v", err)
	}
	return tu.setVersion(ctx, tx, 1)
}

// upgradeDatabaseSchema1 upgrades the database schema from version 1 to version 2
//
// The schema updated to version 2 intended to ensure that the encoding of all the accounts data is
// both canonical and identical across the entire network. On release 2.0.5 we released an upgrade to the messagepack.
// the upgraded messagepack was decoding the account data correctly, but would have different
// encoding compared to it's predecessor. As a result, some of the account data that was previously stored
// would have different encoded representation than the one on disk.
// To address this, this startup procedure would attempt to scan all the accounts data. for each account data, we would
// see if it's encoding aligns with the current messagepack encoder. If it doesn't we would update it's encoding.
// then, depending if we found any such account data, we would reset the merkle trie and stored catchpoints.
// once the upgrade is complete, the trackerDBInitialize would (if needed) rebuild the merkle trie using the new
// encoded accounts.
//
// This upgrade doesn't change any of the actual database schema ( i.e. tables, indexes ) but rather just performing
// a functional update to it's content.
//
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema1(ctx context.Context, tx *sql.Tx) (err error) {
	var modifiedAccounts uint
	if tu.newDatabase {
		goto schemaUpdateComplete
	}

	// update accounts encoding.
	tu.log.Infof("upgradeDatabaseSchema1 verifying accounts data encoding")
	modifiedAccounts, err = reencodeAccounts(ctx, tx)
	if err != nil {
		return err
	}

	if modifiedAccounts > 0 {
		tu.log.Infof("upgradeDatabaseSchema1 reencoded %d accounts", modifiedAccounts)

		tu.log.Infof("upgradeDatabaseSchema1 resetting account hashes")
		// reset the merkle trie
		err = resetAccountHashes(tx)
		if err != nil {
			return fmt.Errorf("upgradeDatabaseSchema1 unable to reset account hashes : %v", err)
		}

		tu.log.Infof("upgradeDatabaseSchema1 preparing queries")
		// initialize a new accountsq with the incoming transaction.
		accountsq, err := accountsInitDbQueries(tx, tx)
		if err != nil {
			return fmt.Errorf("upgradeDatabaseSchema1 unable to prepare queries : %v", err)
		}

		// close the prepared statements when we're done with them.
		defer accountsq.close()

		tu.log.Infof("upgradeDatabaseSchema1 resetting prior catchpoints")
		// delete the last catchpoint label if we have any.
		_, err = accountsq.writeCatchpointStateString(ctx, catchpointStateLastCatchpoint, "")
		if err != nil {
			return fmt.Errorf("upgradeDatabaseSchema1 unable to clear prior catchpoint : %v", err)
		}

		tu.log.Infof("upgradeDatabaseSchema1 deleting stored catchpoints")
		// delete catchpoints.
		err = deleteStoredCatchpoints(ctx, accountsq, tu.dbPathPrefix)
		if err != nil {
			return fmt.Errorf("upgradeDatabaseSchema1 unable to delete stored catchpoints : %v", err)
		}
	} else {
		tu.log.Infof("upgradeDatabaseSchema1 found that no accounts needed to be reencoded")
	}

schemaUpdateComplete:
	return tu.setVersion(ctx, tx, 2)
}

// upgradeDatabaseSchema2 upgrades the database schema from version 2 to version 3
//
// This upgrade only enables the database vacuuming which will take place once the upgrade process is complete.
// If the user has already specified the OptimizeAccountsDatabaseOnStartup flag in the configuration file, this
// step becomes a no-op.
//
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema2(ctx context.Context, tx *sql.Tx) (err error) {
	if !tu.newDatabase {
		tu.vacuumOnStartup = true
	}

	// update version
	return tu.setVersion(ctx, tx, 3)
}

// upgradeDatabaseSchema3 upgrades the database schema from version 3 to version 4,
// adding the normalizedonlinebalance column to the accountbase table.
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema3(ctx context.Context, tx *sql.Tx) (err error) {
	err = accountsAddNormalizedBalance(tx, tu.initProto)
	if err != nil {
		return err
	}

	// update version
	return tu.setVersion(ctx, tx, 4)
}

// upgradeDatabaseSchema4 does not change the schema but migrates data:
// remove empty AccountData entries from accountbase table
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema4(ctx context.Context, tx *sql.Tx) (err error) {
	var numDeleted int64
	var addresses []basics.Address

	if tu.newDatabase {
		goto done
	}

	numDeleted, addresses, err = removeEmptyAccountData(tx, tu.catchpointEnabled)
	if err != nil {
		return err
	}

	if tu.catchpointEnabled && len(addresses) > 0 {
		mc, err := MakeMerkleCommitter(tx, false)
		if err != nil {
			// at this point record deleted and DB is pruned for account data
			// if hash deletion fails just log it and do not abort startup
			tu.log.Errorf("upgradeDatabaseSchema4: failed to create merkle committer: %v", err)
			goto done
		}
		trie, err := merkletrie.MakeTrie(mc, TrieMemoryConfig)
		if err != nil {
			tu.log.Errorf("upgradeDatabaseSchema4: failed to create merkle trie: %v", err)
			goto done
		}

		var totalHashesDeleted int
		for _, addr := range addresses {
			hash := accountHashBuilder(addr, basics.AccountData{}, []byte{0x80})
			deleted, err := trie.Delete(hash)
			if err != nil {
				tu.log.Errorf("upgradeDatabaseSchema4: failed to delete hash '%s' from merkle trie for account %v: %v", hex.EncodeToString(hash), addr, err)
			} else {
				if !deleted {
					tu.log.Warnf("upgradeDatabaseSchema4: failed to delete hash '%s' from merkle trie for account %v", hex.EncodeToString(hash), addr)
				} else {
					totalHashesDeleted++
				}
			}
		}

		if _, err = trie.Commit(); err != nil {
			tu.log.Errorf("upgradeDatabaseSchema4: failed to commit changes to merkle trie: %v", err)
		}

		tu.log.Infof("upgradeDatabaseSchema4: deleted %d hashes", totalHashesDeleted)
	}

done:
	tu.log.Infof("upgradeDatabaseSchema4: deleted %d rows", numDeleted)

	return tu.setVersion(ctx, tx, 5)
}
