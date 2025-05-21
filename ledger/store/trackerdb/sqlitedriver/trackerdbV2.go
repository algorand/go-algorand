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

package sqlitedriver

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merkletrie"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/store/trackerdb"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
)

type trackerDBSchemaInitializer struct {
	trackerdb.Params

	// schemaVersion contains current db version
	schemaVersion int32
	// vacuumOnStartup controls whether the accounts database would get vacuumed on startup.
	vacuumOnStartup bool
	// newDatabase indicates if the db is newly created
	newDatabase bool

	log logging.Logger
}

// RunMigrations initializes the accounts DB if needed and return current account round.
// as part of the initialization, it tests the current database schema version, and perform upgrade
// procedures to bring it up to the database schema supported by the binary.
func RunMigrations(ctx context.Context, e db.Executable, params trackerdb.Params, log logging.Logger, targetVersion int32) (mgr trackerdb.InitParams, err error) {
	// check current database version.
	dbVersion, err := db.GetUserVersion(ctx, e)
	if err != nil {
		return trackerdb.InitParams{}, fmt.Errorf("trackerDBInitialize unable to read database schema version : %v", err)
	}

	tu := trackerDBSchemaInitializer{
		Params:        params,
		schemaVersion: dbVersion,
		log:           log,
	}

	// if database version is greater than supported by current binary, write a warning. This would keep the existing
	// fallback behavior where we could use an older binary iff the schema happen to be backward compatible.
	if tu.version() > targetVersion {
		tu.log.Warnf("trackerDBInitialize database schema version is %d, but migration target version is %d", tu.version(), targetVersion)
	}

	if tu.version() < targetVersion {
		tu.log.Infof("trackerDBInitialize upgrading database schema from version %d to version %d", tu.version(), targetVersion)
		// newDatabase is determined during the tables creations. If we're filling the database with accounts,
		// then we set this variable to true, allowing some of the upgrades to be skipped.
		for tu.version() < targetVersion {
			tu.log.Infof("trackerDBInitialize performing upgrade from version %d", tu.version())
			// perform the initialization/upgrade
			switch tu.version() {
			case 0:
				err = tu.upgradeDatabaseSchema0(ctx, e)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 0 : %v", err)
					return
				}
			case 1:
				err = tu.upgradeDatabaseSchema1(ctx, e)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 1 : %v", err)
					return
				}
			case 2:
				err = tu.upgradeDatabaseSchema2(ctx, e)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 2 : %v", err)
					return
				}
			case 3:
				err = tu.upgradeDatabaseSchema3(ctx, e)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 3 : %v", err)
					return
				}
			case 4:
				err = tu.upgradeDatabaseSchema4(ctx, e)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 4 : %v", err)
					return
				}
			case 5:
				err = tu.upgradeDatabaseSchema5(ctx, e)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 5 : %v", err)
					return
				}
			case 6:
				err = tu.upgradeDatabaseSchema6(ctx, e)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 6 : %v", err)
					return
				}
			case 7:
				err = tu.upgradeDatabaseSchema7(ctx, e)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 7 : %v", err)
					return
				}
			case 8:
				err = tu.upgradeDatabaseSchema8(ctx, e)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 8 : %v", err)
					return
				}
			case 9:
				err = tu.upgradeDatabaseSchema9(ctx, e)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 9 : %v", err)
					return
				}
			case 10:
				err = tu.upgradeDatabaseSchema10(ctx, e)
				if err != nil {
					tu.log.Warnf("trackerDBInitialize failed to upgrade accounts database (ledger.tracker.sqlite) from schema 10 : %v", err)
					return
				}
			default:
				return trackerdb.InitParams{}, fmt.Errorf("trackerDBInitialize unable to upgrade database from schema version %d", tu.schemaVersion)
			}
		}
		tu.log.Infof("trackerDBInitialize database schema upgrade complete")
	}

	return trackerdb.InitParams{SchemaVersion: tu.schemaVersion, VacuumOnStartup: tu.vacuumOnStartup}, nil
}

func (tu *trackerDBSchemaInitializer) setVersion(ctx context.Context, e db.Executable, version int32) (err error) {
	oldVersion := tu.schemaVersion
	tu.schemaVersion = version
	_, err = db.SetUserVersion(ctx, e, tu.schemaVersion)
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
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema0(ctx context.Context, e db.Executable) (err error) {
	tu.log.Infof("upgradeDatabaseSchema0 initializing schema")
	tu.newDatabase, err = accountsInit(e, tu.InitAccounts, config.Consensus[tu.InitProto])
	if err != nil {
		return fmt.Errorf("upgradeDatabaseSchema0 unable to initialize schema : %v", err)
	}
	return tu.setVersion(ctx, e, 1)
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
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema1(ctx context.Context, e db.Executable) (err error) {
	var modifiedAccounts uint
	if tu.newDatabase {
		goto schemaUpdateComplete
	}

	// update accounts encoding.
	tu.log.Infof("upgradeDatabaseSchema1 verifying accounts data encoding")
	modifiedAccounts, err = reencodeAccounts(ctx, e)
	if err != nil {
		return err
	}

	if modifiedAccounts > 0 {
		crw := NewCatchpointSQLReaderWriter(e)
		arw := NewAccountsSQLReaderWriter(e)

		tu.log.Infof("upgradeDatabaseSchema1 reencoded %d accounts", modifiedAccounts)

		tu.log.Infof("upgradeDatabaseSchema1 resetting account hashes")
		// reset the merkle trie
		err = arw.ResetAccountHashes(ctx)
		if err != nil {
			return fmt.Errorf("upgradeDatabaseSchema1 unable to reset account hashes : %v", err)
		}

		tu.log.Infof("upgradeDatabaseSchema1 preparing queries")
		tu.log.Infof("upgradeDatabaseSchema1 resetting prior catchpoints")
		// delete the last catchpoint label if we have any.
		err = crw.WriteCatchpointStateString(ctx, trackerdb.CatchpointStateLastCatchpoint, "")
		if err != nil {
			return fmt.Errorf("upgradeDatabaseSchema1 unable to clear prior catchpoint : %v", err)
		}

		tu.log.Infof("upgradeDatabaseSchema1 deleting stored catchpoints")
		// delete catchpoints.
		err = crw.DeleteStoredCatchpoints(ctx, tu.Params.DbPathPrefix)
		if err != nil {
			return fmt.Errorf("upgradeDatabaseSchema1 unable to delete stored catchpoints : %v", err)
		}
	} else {
		tu.log.Infof("upgradeDatabaseSchema1 found that no accounts needed to be reencoded")
	}

schemaUpdateComplete:
	return tu.setVersion(ctx, e, 2)
}

// upgradeDatabaseSchema2 upgrades the database schema from version 2 to version 3
//
// This upgrade only enables the database vacuuming which will take place once the upgrade process is complete.
// If the user has already specified the OptimizeAccountsDatabaseOnStartup flag in the configuration file, this
// step becomes a no-op.
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema2(ctx context.Context, e db.Executable) (err error) {
	if !tu.newDatabase {
		tu.vacuumOnStartup = true
	}

	// update version
	return tu.setVersion(ctx, e, 3)
}

// upgradeDatabaseSchema3 upgrades the database schema from version 3 to version 4,
// adding the normalizedonlinebalance column to the accountbase table.
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema3(ctx context.Context, e db.Executable) (err error) {
	err = accountsAddNormalizedBalance(e, config.Consensus[tu.InitProto])
	if err != nil {
		return err
	}

	// update version
	return tu.setVersion(ctx, e, 4)
}

// upgradeDatabaseSchema4 does not change the schema but migrates data:
// remove empty AccountData entries from accountbase table
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema4(ctx context.Context, e db.Executable) (err error) {
	var numDeleted int64
	var addresses []basics.Address

	if tu.newDatabase {
		goto done
	}

	numDeleted, addresses, err = removeEmptyAccountData(e, tu.CatchpointEnabled)
	if err != nil {
		return err
	}

	if tu.CatchpointEnabled && len(addresses) > 0 {
		mc, err := MakeMerkleCommitter(e, false)
		if err != nil {
			// at this point record deleted and DB is pruned for account data
			// if hash deletion fails just log it and do not abort startup
			tu.log.Errorf("upgradeDatabaseSchema4: failed to create merkle committer: %v", err)
			goto done
		}
		trie, err := merkletrie.MakeTrie(mc, trackerdb.TrieMemoryConfig)
		if err != nil {
			tu.log.Errorf("upgradeDatabaseSchema4: failed to create merkle trie: %v", err)
			goto done
		}

		var totalHashesDeleted int
		for _, addr := range addresses {
			hash := trackerdb.AccountHashBuilder(addr, basics.AccountData{}, []byte{0x80})
			deleted, delErr := trie.Delete(hash)
			if delErr != nil {
				tu.log.Errorf("upgradeDatabaseSchema4: failed to delete hash '%s' from merkle trie for account %v: %v", hex.EncodeToString(hash), addr, delErr)
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

	return tu.setVersion(ctx, e, 5)
}

// upgradeDatabaseSchema5 upgrades the database schema from version 5 to version 6,
// adding the resources table and clearing empty catchpoint directories.
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema5(ctx context.Context, e db.Executable) (err error) {
	arw := NewAccountsSQLReaderWriter(e)

	err = accountsCreateResourceTable(ctx, e)
	if err != nil {
		return fmt.Errorf("upgradeDatabaseSchema5 unable to create resources table : %v", err)
	}

	err = removeEmptyDirsOnSchemaUpgrade(tu.Params.DbPathPrefix)
	if err != nil {
		return fmt.Errorf("upgradeDatabaseSchema5 unable to clear empty catchpoint directories : %v", err)
	}

	var lastProgressInfoMsg time.Time
	const progressLoggingInterval = 5 * time.Second
	migrationProcessLog := func(processed, total uint64) {
		if time.Since(lastProgressInfoMsg) < progressLoggingInterval {
			return
		}
		lastProgressInfoMsg = time.Now()
		tu.log.Infof("upgradeDatabaseSchema5 upgraded %d out of %d accounts [ %3.1f%% ]", processed, total, float64(processed)*100.0/float64(total))
	}

	err = performResourceTableMigration(ctx, e, migrationProcessLog)
	if err != nil {
		return fmt.Errorf("upgradeDatabaseSchema5 unable to complete data migration : %v", err)
	}

	// reset the merkle trie
	err = arw.ResetAccountHashes(ctx)
	if err != nil {
		return fmt.Errorf("upgradeDatabaseSchema5 unable to reset account hashes : %v", err)
	}

	// update version
	return tu.setVersion(ctx, e, 6)
}

func (tu *trackerDBSchemaInitializer) deleteUnfinishedCatchpoint(ctx context.Context, e db.Executable) error {
	cts := NewCatchpointSQLReaderWriter(e)
	// Delete an unfinished catchpoint if there is one.
	round, err := cts.ReadCatchpointStateUint64(ctx, trackerdb.CatchpointStateWritingCatchpoint)
	if err != nil {
		return err
	}
	if round == 0 {
		return nil
	}

	relCatchpointFilePath := filepath.Join(
		trackerdb.CatchpointDirName,
		trackerdb.MakeCatchpointFilePath(basics.Round(round)))
	err = trackerdb.RemoveSingleCatchpointFileFromDisk(tu.DbPathPrefix, relCatchpointFilePath)
	if err != nil {
		return err
	}

	return cts.WriteCatchpointStateUint64(ctx, trackerdb.CatchpointStateWritingCatchpoint, 0)
}

// upgradeDatabaseSchema6 upgrades the database schema from version 6 to version 7,
// adding a new onlineaccounts table
// TODO: onlineaccounts: upgrade as needed after switching to the final table version
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema6(ctx context.Context, e db.Executable) (err error) {
	err = accountsCreateOnlineAccountsTable(ctx, e)
	if err != nil {
		return err
	}

	err = accountsCreateTxTailTable(ctx, e)
	if err != nil {
		return err
	}

	err = accountsCreateOnlineRoundParamsTable(ctx, e)
	if err != nil {
		return err
	}

	var lastProgressInfoMsg time.Time
	const progressLoggingInterval = 5 * time.Second

	migrationProcessLog := func(processed, total uint64) {
		if time.Since(lastProgressInfoMsg) < progressLoggingInterval {
			return
		}
		lastProgressInfoMsg = time.Now()
		tu.log.Infof("upgradeDatabaseSchema6 upgraded %d out of %d accounts [ %3.1f%% ]", processed, total, float64(processed)*100.0/float64(total))
	}
	err = performOnlineAccountsTableMigration(ctx, e, migrationProcessLog, tu.log)
	if err != nil {
		return fmt.Errorf("upgradeDatabaseSchema6 unable to complete online account data migration : %w", err)
	}

	if !tu.newDatabase {
		err = performTxTailTableMigration(ctx, e, tu.BlockDb.Rdb)
		if err != nil {
			return fmt.Errorf("upgradeDatabaseSchema6 unable to complete transaction tail data migration : %w", err)
		}
	}

	err = performOnlineRoundParamsTailMigration(ctx, e, tu.BlockDb.Rdb, tu.newDatabase, tu.InitProto)
	if err != nil {
		return fmt.Errorf("upgradeDatabaseSchema6 unable to complete online round params data migration : %w", err)
	}

	err = tu.deleteUnfinishedCatchpoint(ctx, e)
	if err != nil {
		return err
	}
	err = accountsCreateCatchpointFirstStageInfoTable(ctx, e)
	if err != nil {
		return err
	}
	err = accountsCreateUnfinishedCatchpointsTable(ctx, e)
	if err != nil {
		return err
	}

	// update version
	return tu.setVersion(ctx, e, 7)
}

// upgradeDatabaseSchema7 upgrades the database schema from version 7 to version 8.
// adding the kvstore table for box feature support.
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema7(ctx context.Context, e db.Executable) (err error) {
	err = accountsCreateBoxTable(ctx, e)
	if err != nil {
		return fmt.Errorf("upgradeDatabaseSchema7 unable to create kvstore through createTables : %v", err)
	}
	return tu.setVersion(ctx, e, 8)
}

// upgradeDatabaseSchema8 upgrades the database schema from version 8 to version 9,
// forcing a rebuild of the accounthashes table on betanet nodes. Otherwise it has no effect.
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema8(ctx context.Context, e db.Executable) (err error) {
	arw := NewAccountsSQLReaderWriter(e)
	betanetGenesisHash, _ := crypto.DigestFromString("TBMBVTC7W24RJNNUZCF7LWZD2NMESGZEQSMPG5XQD7JY4O7JKVWQ")
	if tu.GenesisHash == betanetGenesisHash && !tu.FromCatchpoint {
		// reset hash round to 0, forcing catchpointTracker.initializeHashes to rebuild accounthashes
		err = arw.UpdateAccountsHashRound(ctx, 0)
		if err != nil {
			return fmt.Errorf("upgradeDatabaseSchema8 unable to reset acctrounds table 'hashbase' round : %v", err)
		}
	}
	return tu.setVersion(ctx, e, 9)
}

// upgradeDatabaseSchema9 upgrades the database schema from version 9 to version 10,
// adding a new stateproofverification table,
// scrubbing out all nil values from kvstore table and replace with empty byte slice.
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema9(ctx context.Context, e db.Executable) (err error) {
	err = createStateProofVerificationTable(ctx, e)
	if err != nil {
		return err
	}

	err = performKVStoreNullBlobConversion(ctx, e)
	if err != nil {
		return fmt.Errorf("upgradeDatabaseSchema9 unable to replace kvstore nil entries with empty byte slices : %v", err)
	}

	err = convertOnlineRoundParamsTail(ctx, e)
	if err != nil {
		return fmt.Errorf("upgradeDatabaseSchema10 unable to convert onlineroundparamstail: %v", err)
	}

	// update version
	return tu.setVersion(ctx, e, 10)
}

// upgradeDatabaseSchema10 upgrades the database schema from version 10 to version 11,
// altering the resources table to add a new column, resources.ctype.
func (tu *trackerDBSchemaInitializer) upgradeDatabaseSchema10(ctx context.Context, e db.Executable) (err error) {
	err = accountsAddCreatableTypeColumn(ctx, e, true)
	if err != nil {
		return err
	}
	// update version
	return tu.setVersion(ctx, e, 11)
}

func removeEmptyDirsOnSchemaUpgrade(dbDirectory string) (err error) {
	catchpointRootDir := filepath.Join(dbDirectory, trackerdb.CatchpointDirName)
	if _, err := os.Stat(catchpointRootDir); os.IsNotExist(err) {
		return nil
	}
	for {
		emptyDirs, err := trackerdb.GetEmptyDirs(catchpointRootDir)
		if err != nil {
			return err
		}
		// There are no empty dirs
		if len(emptyDirs) == 0 {
			break
		}
		// only left with the root dir
		if len(emptyDirs) == 1 && emptyDirs[0] == catchpointRootDir {
			break
		}
		for _, emptyDirPath := range emptyDirs {
			os.Remove(emptyDirPath)
		}
	}
	return nil
}
