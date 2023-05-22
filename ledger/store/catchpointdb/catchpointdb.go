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

package catchpointdb

import (
	"context"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
)

type Store interface {
	ReaderWriter
	// init
	RunMigrations(ctx context.Context, targetVersion int32) (err error)
	// batch support
	Batch(fn BatchFn) (err error)
	BatchContext(ctx context.Context, fn BatchFn) (err error)
	// root methods
	DeleteStoredCatchpoints(ctx context.Context, dbDirectory string) (err error)
	// cleanup
	Close()
}

// BatchFn is the callback lambda used in `Batch`.
type BatchFn func(ctx context.Context, tx BatchScope) error

// BatchScope is an atomic write-only scope to the store.
type BatchScope interface {
	Writer
}

// Writer is the write interface for the catchpoint store
type Writer interface {
	MetadataWriter
	GeneratorWriter
	CatchupWriter
}

// GeneratorWriter all writes needs into the catchpoint store during catchpoint generation
type GeneratorWriter interface {
	CatchpointDB_catchpointstate_Writer
	CatchpointDB_unfinishedcatchpoints_Writer
	CatchpointDB_catchpointfirststageinfo_Writer
}

// CatchupWriter all catchpoint processing writes needed during catchpoint catchup
type CatchupWriter interface {
	CatchpointDB_catchpointstate_Writer
}

// Reader is the read interface for the catchpoint store
type Reader interface {
	GetVersion(ctx context.Context, staging bool) (uint64, error)

	MetadataReader
	GeneratorReader
	CatchupReader
}

// GeneratorReader all read needs from the catchpoint store during catchpoint generation
type GeneratorReader interface {
	CatchpointDB_catchpointstate_Reader
	CatchpointDB_unfinishedcatchpoints_Reader
	CatchpointDB_catchpointfirststageinfo_Reader
}

// CatchupReader all catchpoint processing reads needed during catchpoint catchup
type CatchupReader interface {
	CatchpointDB_catchpointstate_Reader
}

// ReaderWriter combines the Reader and Writer
type ReaderWriter interface {
	Reader
	Writer
}

/// -------------
/// catchpoints metadata register

type MetadataWriter interface {
	StoreCatchpoint(ctx context.Context, round basics.Round, fileName string, catchpoint string, fileSize int64) (err error)
}

type MetadataReader interface {
	GetCatchpoint(ctx context.Context, round basics.Round) (fileName string, catchpoint string, fileSize int64, err error)
	GetOldestCatchpointFiles(ctx context.Context, fileCount int, filesToKeep int) (fileNames map[basics.Round]string, err error)
}

///------------------------
/// catchup runtime (durable)
/// could this be part of apply?

// used during:
// - mainly in catchpoint application, with a couple uses in catchpoint generation
// - used in catchpoint tracker during commit round
//   - used to signal that the db state is ready for being read by the catchpoint generator
//   - CatchpointStateWritingFirstStageInfo, catchpoint is unfinished (dirty flag)
//   - CatchpointStateCatchpointLookback, handle protocol changes during crash recovery
//
// decision here:
// we could simplify the code, and restart cathcpoint from a clean state after a crash
// and not need to resume where we left of

// During Generation:
// - CatchpointStateWritingFirstStageInfo (write)
// - CatchpointStateCatchpointLookback (write)
// - CatchpointStateLastCatchpoint (write)
// During Apply:
// - CatchpointStateCatchupVersion .. version (write)
// - CatchpointStateCatchupState .. state (write)
// - CatchpointStateCatchupBlockRound .. block round (write)
// - CatchpointStateCatchupHashRound .. hash round (write)
// - CatchpointStateCatchupBalancesRound .. balances round (write)
// - CatchpointStateCatchupLabel .. label (write)
type CatchpointDB_catchpointstate_Writer interface {
	WriteCatchpointStateUint64(ctx context.Context, stateName CatchpointState, setValue uint64) (err error)
	WriteCatchpointStateString(ctx context.Context, stateName CatchpointState, setValue string) (err error)
}

// During Generation:
// - CatchpointStateWritingFirstStageInfo (read)
// - CatchpointStateCatchpointLookback (read)
// - CatchpointStateLastCatchpoint (read)
// During Apply:
// - CatchpointStateCatchupVersion .. version (read)
// - CatchpointStateCatchupState .. state (read)
// - CatchpointStateCatchupBlockRound .. block round (read)
// - CatchpointStateCatchupHashRound .. hash round (read)
// - CatchpointStateCatchupBalancesRound .. balances round (read)
// - CatchpointStateCatchupLabel .. label (read)
// CatchpointDump?:
// - CatchpointStateCatchupVersion .. version (read)
type CatchpointDB_catchpointstate_Reader interface {
	ReadCatchpointStateUint64(ctx context.Context, stateName CatchpointState) (val uint64, err error)
	ReadCatchpointStateString(ctx context.Context, stateName CatchpointState) (val string, err error)
}

// During Generation:
// - InsertUnfinishedCatchpoint
// - DeleteUnfinishedCatchpoint
type CatchpointDB_unfinishedcatchpoints_Writer interface {
	InsertUnfinishedCatchpoint(ctx context.Context, round basics.Round, blockHash crypto.Digest) error
	DeleteUnfinishedCatchpoint(ctx context.Context, round basics.Round) error
}

// During Generation:
// - SelectUnfinishedCatchpoints
type CatchpointDB_unfinishedcatchpoints_Reader interface {
	SelectUnfinishedCatchpoints(ctx context.Context) ([]UnfinishedCatchpointRecord, error)
}

// During Generation:
// - InsertOrReplaceCatchpointFirstStageInfo
// - DeleteOldCatchpointFirstStageInfo
type CatchpointDB_catchpointfirststageinfo_Writer interface {
	InsertOrReplaceCatchpointFirstStageInfo(ctx context.Context, round basics.Round, info *CatchpointFirstStageInfo) error
	DeleteOldCatchpointFirstStageInfo(ctx context.Context, maxRoundToDelete basics.Round) error
}

// During Generation:
// - SelectCatchpointFirstStageInfo
// - SelectOldCatchpointFirstStageInfoRounds
type CatchpointDB_catchpointfirststageinfo_Reader interface {
	SelectCatchpointFirstStageInfo(ctx context.Context, round basics.Round) (CatchpointFirstStageInfo, bool /*exists*/, error)
	SelectOldCatchpointFirstStageInfoRounds(ctx context.Context, maxRound basics.Round) ([]basics.Round, error)
}
