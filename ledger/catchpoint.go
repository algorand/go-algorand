// Copyright (C) 2019-2020 Algorand, Inc.
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
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/util/db"
)

const defaultCatchpointNextCandidateRound = 0
const databaseBackupRoundRate = 1024 * 1024 // set to 1MB per round.

type nodeArchivalModeEnum uint64

const (
	nodeArchivalModeUnknown  nodeArchivalModeEnum = iota
	nodeArchivalModeDisabled                      // archival mode is disabled for this node.
	nodeArchivalModeEnabled                       // archival mode is enabled for this node.
)

type catchpointStageEnum uint64

const (
	catchpointStageUnknown   catchpointStageEnum = iota
	catchpointStageScheduled                     // we have scheduled the next catchpoint, and we know exactly when the backup need to start ( in the future ). Non archival node would typically remain in this state.
	catchpointStageBackingUp                     // we started backing up the balances, and will keep doing so until the we reach the schduled catchpoint round.
	catchpointStageBackedUp                      // we reached the schduled catchpoint round and we're generating the catchpoint.
)

type catchpointTracker struct {
	ledger                       ledgerForTracker     // the parent ledger
	dbs                          dbPair               // Connection to the tracker database
	archivalLedger               bool                 // was the ledger configured as archival ? used only during startup to adjust current status if archival mode was changed by end-user since last startup.
	log                          logging.Logger       // the log object
	nextCatchpointCandidateRound basics.Round         // next catchpoint candidate round
	nodeArchivalMode             nodeArchivalModeEnum // the current archival mode
	stage                        catchpointStageEnum  // the current stage of the catchpoint tracker
	lastCommittedRound           basics.Round         // the last committed round
	lastCatchpointDatabaseSize   uint64               // the tracker database size on the last time we were at a catchpoint round.
	catchpointInterval           uint64               // the configured interval at which we generate catchpoints

	// The following fields are typically used only by archival nodes.
	stagingDatabaseName        string                     // the full path of the staging database name.
	inMemoryDatabase           bool                       // indicates whether the database copy should be done into an in-memory database.
	backupAccessor             *db.BackupAccessor         // the database accessor used during the catchpointStageBackingUp step.
	backupRemainingPages       int                        // remaining pages need to be copied
	backupTotalPages           int                        // total number of pages for the backup operation
	backupRate                 int                        // how many pages do we copy per step
	stagingAccessor            db.Accessor                // the backed-up database accessor, one the backup is complete.
	buildingCatchpoint         chan catchpointBuildResult // this channel is being updated by the background goroutine that builds the catchpoint file
	catchpointBuilderWaitGroup sync.WaitGroup             // wait group to syncronize the catchpoint file creation
	closingCtx                 context.Context            // a close context to notify the file creation goroutine that we're shutting down.
	signalClosing              context.CancelFunc         // a close context function for closingCtx
}

type catchpointBuildResult struct {
	err        error        // the error that was encoutered during the catchpoint file generation
	round      basics.Round // the round number of the catchpoint file
	fileName   string       // the file name of the catchpoint
	fileSize   int64        // the file size of the catchpoint
	catchpoint string       // the catchpoint string
}

// why do we backup ?
// on archival node, we want to make sure that if the node is crashing on round n+1, we will always be able to
// generate a catchpoint.

func (cp *catchpointTracker) initialize(cfg config.Local, dbPathPrefix string, dbMem bool) {
	cp.catchpointInterval = cfg.CatchpointInterval
	cp.inMemoryDatabase = dbMem
	cp.stagingDatabaseName = dbPathPrefix + ".catchpoint.staging.sqlite"
	cp.archivalLedger = cfg.Archival
	cp.buildingCatchpoint = make(chan catchpointBuildResult, 1)
	cp.closingCtx, cp.signalClosing = context.WithCancel(context.Background())
	return
}

func (cp *catchpointTracker) updateLastCommittedRound() error {
	// test to see if the commited round is identical to the one in the database.
	trackerDBs := cp.ledger.trackerDB()
	// load the catchpoint tracker state from the database.
	err := trackerDBs.rdb.Atomic(func(tx *sql.Tx) (err error) {
		cp.lastCommittedRound, err = accountsRound(tx)
		return
	})
	if err != nil {
		cp.log.Infof("catchpointTracker: updateLastCommittedRound: %v", err)
	}
	return err
}

// committedUpTo is called after we've committed the given round to disk, and allow us to move the catchpoint state one step further.
func (cp *catchpointTracker) committedUpTo(rnd basics.Round) (outRound basics.Round) {
	outRound = rnd

	cp.lastCommittedRound = rnd

	cp.log.Debugf("catchpointTracker: committedUpTo: round=%d stage=%d next=%d", rnd, cp.stage, cp.nextCatchpointCandidateRound)
	switch cp.stage {
	case catchpointStageScheduled:
		// if this is an archival node,
		if cp.nodeArchivalMode == nodeArchivalModeEnabled {
			startBackupRound := cp.startBackupRound()
			if rnd >= startBackupRound {
				// it's time to start the backup.
				err := cp.startBackup(context.Background())
				if err != nil {
					// TODO.
				}
			}
		} else {
			// this is not an archival node.
			// update the schedule once we've reached a catchpoint round.
			if cp.isCatchpointCandidateRound(rnd) {
				err := cp.scheduleCatchpoint()
				if err != nil {
					// TODO.

				}
			}
		}
	case catchpointStageBackingUp:
		// try to make some progress. This stage is applicable only for archival nodes.
		if rnd < cp.nextCatchpointCandidateRound {
			// we haven't reached the catchpoint round.
			pagesToCopy := cp.backupRate
			if cp.backupRemainingPages <= pagesToCopy {
				// don't copy the last page.
				pagesToCopy = cp.backupRemainingPages - 1
			}

			cp.backupAccessor.Step(pagesToCopy)
			cp.backupRemainingPages = cp.backupAccessor.Remaining()
		} else {
			// we reached the catchpoint round.
			err := cp.finishBackup()
			if err != nil {
				// TODO.
			}
		}
	case catchpointStageBackedUp:
		// see if we're done building the catchpoint.
		select {
		case buildResult := <-cp.buildingCatchpoint:
			err := buildResult.err
			if err != nil {
				// TODO - report the error.
			}
			err = cp.saveCatchpoint(buildResult)
			if err != nil {
				// TODO - report the error.
			}
			err = cp.scheduleCatchpoint()
			if err != nil {
				// TODO.

			}

		default:
			// no, we're still processing the staging database.
		}
	}
	return
}

func (cp *catchpointTracker) loadFromDisk(l ledgerForTracker) error {
	cp.ledger = l
	cp.log = l.trackerLog()
	cp.dbs = cp.ledger.trackerDB()

	cp.lastCommittedRound = l.Latest()

	// load the catchpoint tracker state from the database.
	err := cp.dbs.wdb.Atomic(cp.loadCatchpointState)
	if err != nil {
		cp.log.Errorf("catchpointTracker: loadCatchpointState: %v", err)
		return err
	}

	if cp.nodeArchivalMode == nodeArchivalModeDisabled && cp.archivalLedger {
		// user enabled the archival mode since last startup
		err = cp.updateArchivalMode(true)
		if err != nil {
			return err
		}

	} else if cp.nodeArchivalMode == nodeArchivalModeEnabled && (!cp.archivalLedger) {
		// user disabled the archival mode since last startup
		err = cp.updateArchivalMode(false)
		if err != nil {
			return err
		}
	}

	rescheduleCatchpoint := true
	if cp.nodeArchivalMode == nodeArchivalModeEnabled && cp.stage == catchpointStageBackedUp {
		// start the checkpoint staging file generation.
		cp.stagingAccessor, err = db.MakeAccessor(cp.stagingDatabaseName, false, false)
		if err == nil {
			// no error, so kick off the staging catchpoint generator
			rescheduleCatchpoint = false
			cp.asyncGenerateCatchpoint()
		}
	}

	if rescheduleCatchpoint {
		err = cp.scheduleCatchpoint()
		if err != nil {
			return err
		}
	}
	return nil
}

func (cp *catchpointTracker) close() {
	switch cp.stage {
	case catchpointStageBackingUp:
		cp.abortBackup()
		cp.deleteStagingBackup()
	case catchpointStageBackedUp:
		cp.signalClosing()
		cp.catchpointBuilderWaitGroup.Wait()
	default:
	}
}

func (cp *catchpointTracker) newBlock(blk bookkeeping.Block, delta StateDelta) {
	// we don't do much when a new block comes in and before it's being committed to disk.
}

func (cp *catchpointTracker) loadCatchpointState(tx *sql.Tx) (err error) {
	nextCatchpointRound := uint64(0)
	nextCatchpointRound, _, err = readCatchpointStateUint64(context.Background(), tx, "catchpointNextCandidateRound")
	if err != nil {
		return fmt.Errorf("unable to load catchpoint state 'catchpointNextCandidateRound': %v", err)
	}
	cp.nextCatchpointCandidateRound = basics.Round(nextCatchpointRound)

	archivalMode := uint64(0)
	archivalMode, _, err = readCatchpointStateUint64(context.Background(), tx, "catchpointArchivalMode")
	if err != nil {
		return fmt.Errorf("unable to load catchpoint state 'catchpointArchivalMode': %v", err)
	}
	if archivalMode == uint64(nodeArchivalModeUnknown) {
		if cp.archivalLedger {
			archivalMode = uint64(nodeArchivalModeEnabled)
		} else {
			archivalMode = uint64(nodeArchivalModeDisabled)
		}
		_, err = writeCatchpointStateUint64(context.Background(), tx, "catchpointArchivalMode", archivalMode)
		if err != nil {
			return fmt.Errorf("unable to set catchpoint state 'catchpointArchivalMode': %v", err)
		}
	}
	cp.nodeArchivalMode = nodeArchivalModeEnum(archivalMode)

	catchpointStage := uint64(0)
	catchpointStage, _, err = readCatchpointStateUint64(context.Background(), tx, "catchpointStage")
	if err != nil {
		return fmt.Errorf("unable to read catchpoint state 'catchpointStage': %v", err)
	}
	cp.stage = catchpointStageEnum(catchpointStage)

	cp.lastCatchpointDatabaseSize, _, err = readCatchpointStateUint64(context.Background(), tx, "catchpointLastDatabaseSize")
	if err != nil {
		return fmt.Errorf("unable to read catchpoint state 'catchpointLastDatabaseSize': %v", err)
	}

	return nil
}

func (cp *catchpointTracker) scheduleCatchpoint() error {
	if cp.catchpointInterval == 0 {
		cp.log.Infof("catchpointTracker: scheduleCatchpoint: catchpointInterval is zero")
		return nil
	}
	hdr, err := cp.ledger.BlockHdr(cp.lastCommittedRound)
	if err != nil {
		cp.log.Infof("catchpointTracker: scheduleCatchpoint: no block header is available for round %d : %v", cp.lastCommittedRound, err)
		return err
	}
	proto := config.Consensus[hdr.CurrentProtocol]
	if cp.lastCommittedRound <= basics.Round(proto.MaxBalLookback) {
		// don't schedule any catchpoint before we have MaxBalLookback entries.
		return nil
	}

	isCatchpointRound := cp.isCatchpointCandidateRound(cp.lastCommittedRound)
	var nextCatchpointRound uint64
	if cp.nodeArchivalMode != nodeArchivalModeEnabled {
		nextCatchpointRound = ((uint64(cp.lastCommittedRound) / cp.catchpointInterval) + 1) * cp.catchpointInterval
	} else {
		// on archival nodes, try to first flush the current catchpoint if we're on a catchpoint round.
		if isCatchpointRound {
			nextCatchpointRound = (uint64(cp.lastCommittedRound) / cp.catchpointInterval) * cp.catchpointInterval
		} else {
			nextCatchpointRound = ((uint64(cp.lastCommittedRound) / cp.catchpointInterval) + 1) * cp.catchpointInterval
		}
	}

	var dbSize uint64

	// the point where we want to start backing up is somewhere in the future, just set it here for now.
	err = cp.dbs.wdb.Atomic(func(tx *sql.Tx) (err error) {
		_, err = writeCatchpointStateUint64(context.Background(), tx, "catchpointNextCandidateRound", nextCatchpointRound)
		if err != nil {
			return fmt.Errorf("unable to set catchpoint state 'catchpointNextCandidateRound': %v", err)
		}
		_, err = writeCatchpointStateUint64(context.Background(), tx, "catchpointStage", uint64(catchpointStageScheduled))
		if err != nil {
			return fmt.Errorf("unable to set catchpoint state 'catchpointStage': %v", err)
		}

		if cp.nodeArchivalMode == nodeArchivalModeEnabled {
			dbSize, err = cp.databaseSize(tx)
			if err != nil {
				return fmt.Errorf("unable to read database size: %v", err)
			}
			_, err = writeCatchpointStateUint64(context.Background(), tx, "catchpointLastDatabaseSize", dbSize)
			if err != nil {
				return fmt.Errorf("unable to set catchpoint state 'catchpointLastDatabaseSize': %v", err)
			}
		}
		return err
	})
	if err != nil {
		cp.log.Errorf("catchpointTracker: scheduleCatchpoint: %v", err)
		return err
	}

	cp.nextCatchpointCandidateRound = basics.Round(nextCatchpointRound)
	cp.stage = catchpointStageScheduled

	if cp.nodeArchivalMode != nodeArchivalModeEnabled {
		return nil
	}

	cp.lastCatchpointDatabaseSize = dbSize
	startBackupRound := cp.startBackupRound()
	if startBackupRound <= cp.lastCommittedRound {
		err = cp.startBackup(context.Background())
		if err != nil {
			cp.log.Errorf("catchpointTracker: scheduleCatchpoint: unable to start backup: %v", err)
			return err
		}

		// at this time, we don't know if we'll be able to keep with with whatever rate we've set to do, so we'll need to copy all the pages - 1 right now.
		if cp.backupRemainingPages > 1 {
			complete, err := cp.backupAccessor.Step(cp.backupRemainingPages - 1)
			if err != nil {
				cp.log.Errorf("catchpointTracker: scheduleCatchpoint: unable to make a backup step: %v", err)
				return err
			}
			if complete {
				cp.log.Errorf("catchpointTracker: scheduleCatchpoint: step(%d) is not expected to complete the database backup, as %d pages remained", cp.backupRemainingPages-1, cp.backupRemainingPages)
				return err
			}
			cp.backupRemainingPages = cp.backupAccessor.Remaining()
		}

		// should we finish this backup and move to the next stage ?
		if isCatchpointRound {
			cp.finishBackup()
		}
	}

	return nil
}

func (cp *catchpointTracker) isCatchpointRound(round basics.Round) bool {
	return round == cp.nextCatchpointCandidateRound
}

func (cp *catchpointTracker) isCatchpointCandidateRound(rnd basics.Round) bool {
	if cp.catchpointInterval == 0 {
		return false
	}
	return 0 == (uint64(rnd) % cp.catchpointInterval)
}

func (cp *catchpointTracker) startBackupRound() basics.Round {
	return basics.Round(uint64(cp.nextCatchpointCandidateRound) - (cp.lastCatchpointDatabaseSize / databaseBackupRoundRate) - 1)
}

func (cp *catchpointTracker) updateArchivalMode(enable bool) error {
	mode := nodeArchivalModeDisabled
	if enable {
		mode = nodeArchivalModeEnabled
	}

	err := cp.dbs.wdb.Atomic(func(tx *sql.Tx) (err error) {
		_, err = writeCatchpointStateUint64(context.Background(), tx, "catchpointNextCandidateRound", 0)
		if err != nil {
			return fmt.Errorf("unable to set catchpoint state 'catchpointNextCandidateRound': %v", err)
		}
		_, err = writeCatchpointStateUint64(context.Background(), tx, "catchpointLastDatabaseSize", 0)
		if err != nil {
			return fmt.Errorf("unable to set catchpoint state 'catchpointLastDatabaseSize': %v", err)
		}
		_, err = writeCatchpointStateUint64(context.Background(), tx, "catchpointStage", uint64(catchpointStageUnknown))
		if err != nil {
			return fmt.Errorf("unable to set catchpoint state 'catchpointStage': %v", err)
		}
		_, err = writeCatchpointStateUint64(context.Background(), tx, "catchpointArchivalMode", uint64(mode))
		if err != nil {
			return fmt.Errorf("unable to set catchpoint state 'catchpointArchivalMode': %v", err)
		}
		return nil
	})
	if err != nil {
		cp.log.Errorf("catchpointTracker: updateArchivalMode: %v", err)
		return err
	}
	cp.lastCatchpointDatabaseSize = 0
	cp.nodeArchivalMode = mode
	previousStage := cp.stage
	cp.stage = catchpointStageUnknown
	cp.nextCatchpointCandidateRound = 0

	// if the previous stage had a backed up database, we want to delete it.
	// ( i.e. this is called only when the user has changed the archival model in the configuration file )
	if previousStage == catchpointStageBackingUp || previousStage == catchpointStageBackedUp {
		err = cp.deleteStagingBackup()
		if err != nil {
			cp.log.Errorf("catchpointTracker: updateArchivalMode: unable to delete staged backup database: %v", err)
			return err
		}
	}
	return nil
}

func (cp *catchpointTracker) startBackup(ctx context.Context) (err error) {
	cp.backupAccessor, err = cp.dbs.rdb.Backup(ctx, cp.stagingDatabaseName, cp.inMemoryDatabase)
	if err != nil {
		cp.log.Errorf("catchpointTracker: startBackup: unable to create backup accessor: %v", err)
		cp.deleteStagingBackup()
		return err
	}
	// call the Step to initialize the Remaining and PageCount.
	_, err = cp.backupAccessor.Step(0)
	if err != nil {
		cp.log.Errorf("catchpointTracker: startBackup: unable to make backup step: %v", err)
		cp.deleteStagingBackup()
		return err
	}
	cp.backupRemainingPages = cp.backupAccessor.Remaining()
	cp.backupTotalPages = cp.backupAccessor.PageCount()
	if cp.lastCommittedRound < cp.nextCatchpointCandidateRound {
		cp.backupRate = int(uint64(cp.backupTotalPages*2) / (uint64(cp.nextCatchpointCandidateRound) - uint64(cp.lastCommittedRound)))
	} else {
		cp.backupRate = -1 // copy all.
	}

	err = cp.dbs.wdb.Atomic(func(tx *sql.Tx) (err error) {
		_, err = writeCatchpointStateUint64(context.Background(), tx, "catchpointStage", uint64(catchpointStageBackingUp))
		return
	})
	if err != nil {
		cp.log.Errorf("catchpointTracker: startBackup: unable to update 'catchpointStage': %v", err)
		cp.deleteStagingBackup()
		return err
	}
	cp.stage = catchpointStageBackingUp
	return
}

func (cp *catchpointTracker) abortBackup() (err error) {
	cp.stagingAccessor, err = cp.backupAccessor.Finish()
	if err != nil {
		cp.log.Errorf("catchpointTracker: abortBackup: unable to finish backing up database: %v", err)
		return
	}
	cp.backupAccessor = nil
	cp.stagingAccessor.Close()
	return
}

func (cp *catchpointTracker) finishBackup() (err error) {
	cp.backupAccessor.Step(-1)
	cp.stagingAccessor, err = cp.backupAccessor.Finish()
	if err != nil {
		cp.log.Errorf("catchpointTracker: finishBackup: unable to finish backing up database: %v", err)
		return
	}
	cp.backupAccessor = nil
	err = cp.dbs.wdb.Atomic(func(tx *sql.Tx) (err error) {
		_, err = writeCatchpointStateUint64(context.Background(), tx, "catchpointStage", uint64(catchpointStageBackedUp))
		return
	})
	if err != nil {
		cp.log.Errorf("catchpointTracker: finishBackup: unable to update 'catchpointStage': %v", err)
		return
	}
	cp.stage = catchpointStageBackedUp
	cp.asyncGenerateCatchpoint()
	return
}

func (cp *catchpointTracker) deleteStagingBackup() (err error) {
	err = os.Remove(cp.stagingDatabaseName)
	if !os.IsNotExist(err) {
		return err
	}
	err = os.Remove(cp.stagingDatabaseName + "-shm")
	if !os.IsNotExist(err) {
		return err
	}
	err = os.Remove(cp.stagingDatabaseName + "-wal")
	if !os.IsNotExist(err) {
		return err
	}
	err = nil
	return
}

func catchpointRoundToPath(rnd basics.Round) string {
	irnd := int64(rnd) / 256
	outStr := ""
	for irnd > 0 {
		outStr = filepath.Join(outStr, fmt.Sprintf("%02x", irnd%256))
		irnd = irnd / 256
	}
	outStr = filepath.Join(outStr, strconv.FormatInt(int64(rnd), 10)+".catchpoint")
	return outStr
}

func (cp *catchpointTracker) asyncGenerateCatchpoint() {
	blockHdr, err := cp.ledger.BlockHdr(cp.nextCatchpointCandidateRound)
	if err != nil {
		buildResult := catchpointBuildResult{
			err: fmt.Errorf("no block header is available for round %d : %v", cp.nextCatchpointCandidateRound, err),
		}
		cp.log.Errorf("catchpointTracker: asyncGenerateCatchpoint: %v", err)
		cp.buildingCatchpoint <- buildResult
		return
	}
	cp.catchpointBuilderWaitGroup.Add(1)
	go func(blockHeader bookkeeping.BlockHeader) {
		var buildResult catchpointBuildResult
		defer func() {
			cp.stagingAccessor.Close()
			cp.deleteStagingBackup()
			cp.buildingCatchpoint <- buildResult
			cp.catchpointBuilderWaitGroup.Done()
		}()

		// create a dummy file for now.
		catchpointsRoot := filepath.Dir(cp.stagingDatabaseName)
		buildResult.fileName = filepath.Join("catchpoints", catchpointRoundToPath(blockHeader.Round))
		catchpointPath := filepath.Join(catchpointsRoot, buildResult.fileName)

		writer := makeCatchpointWriter(catchpointPath, cp.stagingAccessor, blockHeader.Round, blockHeader.Hash())
		more := true
		for more && buildResult.err == nil {
			stepCtx, stepCancelFunction := context.WithTimeout(cp.closingCtx, 50*time.Millisecond)
			more, buildResult.err = writer.WriteStep(stepCtx)
			stepCancelFunction()
			if buildResult.err == nil && more {
				// we just wrote some data, but there is more to be written.
				// go to sleep for while.
				select {
				case <-time.After(100 * time.Millisecond):
				case <-cp.closingCtx.Done():
					buildResult.err = cp.closingCtx.Err()
					return
				}
			}
			if buildResult.err != nil {
				cp.log.Errorf("catchpointTracker: asyncGenerateCatchpoint: unable to create catchpoint : %v", buildResult.err)
			}
			buildResult.fileSize = writer.GetSize()
			buildResult.round = blockHeader.Round
			buildResult.catchpoint = writer.GetCatchpoint()
		}
	}(blockHdr)
}

func (cp *catchpointTracker) saveCatchpoint(b catchpointBuildResult) (err error) {
	err = cp.dbs.wdb.Atomic(func(tx *sql.Tx) (err error) {
		err = cp.storeCatchpoint(tx, b.round, b.fileName, b.catchpoint, b.fileSize)
		return
	})
	if err != nil {
		cp.log.Errorf("catchpointTracker: saveCatchpoint: unable to save catchpoint: %v", err)
		return
	}
	return
}
