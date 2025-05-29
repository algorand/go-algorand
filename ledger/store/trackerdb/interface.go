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

package trackerdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/encoded"
	"github.com/algorand/go-algorand/ledger/ledgercore"
)

// ErrNotFound is returned when a record is not found.
var ErrNotFound = errors.New("trackerdb: not found")

// ErrIoErr is returned when a Disk/IO error is encountered
type ErrIoErr struct {
	InnerError error
}

func (e *ErrIoErr) Error() string {
	return fmt.Sprintf("trackerdb: io error: %v", e.InnerError)
}

func (e *ErrIoErr) Unwrap() error {
	return e.InnerError
}

// AccountRef is an opaque ref to an account in the db.
type AccountRef interface {
	AccountRefMarker()
	String() string
}

// OnlineAccountRef is an opaque ref to an "online" account in the db.
type OnlineAccountRef interface {
	OnlineAccountRefMarker()
}

// ResourceRef is an opaque ref to a resource in the db.
type ResourceRef interface {
	ResourceRefMarker()
}

// CreatableRef is an opaque ref to a creatable in the db.
type CreatableRef interface {
	CreatableRefMarker()
}

// AccountsWriter is the write interface for:
// - accounts, resources, app kvs, creatables
type AccountsWriter interface {
	InsertAccount(addr basics.Address, normBalance uint64, data BaseAccountData) (ref AccountRef, err error)
	DeleteAccount(ref AccountRef) (rowsAffected int64, err error)
	UpdateAccount(ref AccountRef, normBalance uint64, data BaseAccountData) (rowsAffected int64, err error)

	InsertResource(accountRef AccountRef, aidx basics.CreatableIndex, data ResourcesData) (ref ResourceRef, err error)
	DeleteResource(accountRef AccountRef, aidx basics.CreatableIndex) (rowsAffected int64, err error)
	UpdateResource(accountRef AccountRef, aidx basics.CreatableIndex, data ResourcesData) (rowsAffected int64, err error)

	UpsertKvPair(key string, value []byte) error
	DeleteKvPair(key string) error

	InsertCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType, creator []byte) (ref CreatableRef, err error)
	DeleteCreatable(cidx basics.CreatableIndex, ctype basics.CreatableType) (rowsAffected int64, err error)

	Close()
}

// AccountsWriterExt is the write interface used inside transactions and batch operations.
type AccountsWriterExt interface {
	AccountsReset(ctx context.Context) error
	ResetAccountHashes(ctx context.Context) (err error)
	TxtailNewRound(ctx context.Context, baseRound basics.Round, roundData [][]byte, forgetBeforeRound basics.Round) error
	UpdateAccountsRound(rnd basics.Round) (err error)
	UpdateAccountsHashRound(ctx context.Context, hashRound basics.Round) (err error)
	AccountsPutTotals(totals ledgercore.AccountTotals, catchpointStaging bool) error
	OnlineAccountsDelete(forgetBefore basics.Round) (err error)
	AccountsPutOnlineRoundParams(onlineRoundParamsData []ledgercore.OnlineRoundParamsData, startRound basics.Round) error
	AccountsPruneOnlineRoundParams(deleteBeforeRound basics.Round) error
}

// AccountsReader is the "optimized" read interface for:
// - accounts, resources, app kvs, creatables
type AccountsReader interface {
	LookupAccount(addr basics.Address) (data PersistedAccountData, err error)

	LookupResources(addr basics.Address, aidx basics.CreatableIndex, ctype basics.CreatableType) (data PersistedResourcesData, err error)
	LookupAllResources(addr basics.Address) (data []PersistedResourcesData, rnd basics.Round, err error)
	LookupLimitedResources(addr basics.Address, minIdx basics.CreatableIndex, maxCreatables uint64, ctype basics.CreatableType) (data []PersistedResourcesDataWithCreator, rnd basics.Round, err error)

	LookupKeyValue(key string) (pv PersistedKVData, err error)
	LookupKeysByPrefix(prefix string, maxKeyNum uint64, results map[string]bool, resultCount uint64) (round basics.Round, err error)

	LookupCreator(cidx basics.CreatableIndex, ctype basics.CreatableType) (addr basics.Address, ok bool, dbRound basics.Round, err error)

	Close()
}

// AccountsReaderExt is the read interface for:
// - accounts, resources, app kvs, creatables
type AccountsReaderExt interface {
	AccountsTotals(ctx context.Context, catchpointStaging bool) (totals ledgercore.AccountTotals, err error)
	AccountsHashRound(ctx context.Context) (hashrnd basics.Round, err error)
	LookupAccountAddressFromAddressID(ctx context.Context, ref AccountRef) (address basics.Address, err error)
	LookupAccountRowID(basics.Address) (ref AccountRef, err error)
	LookupResourceDataByAddrID(accountRef AccountRef, aidx basics.CreatableIndex) (data []byte, err error)
	TotalResources(ctx context.Context) (total uint64, err error)
	TotalAccounts(ctx context.Context) (total uint64, err error)
	TotalKVs(ctx context.Context) (total uint64, err error)
	TotalOnlineAccountRows(ctx context.Context) (total uint64, err error)
	TotalOnlineRoundParams(ctx context.Context) (total uint64, err error)
	AccountsRound() (rnd basics.Round, err error)
	LookupOnlineAccountDataByAddress(addr basics.Address) (ref OnlineAccountRef, data []byte, err error)
	AccountsOnlineTop(rnd basics.Round, offset uint64, n uint64, proto config.ConsensusParams) (map[basics.Address]*ledgercore.OnlineAccount, error)
	AccountsOnlineRoundParams() (onlineRoundParamsData []ledgercore.OnlineRoundParamsData, endRound basics.Round, err error)
	ExpiredOnlineAccountsForRound(rnd, voteRnd basics.Round, proto config.ConsensusParams, rewardsLevel uint64) (map[basics.Address]*basics.OnlineAccountData, error)
	OnlineAccountsAll(maxAccounts uint64) ([]PersistedOnlineAccountData, error)
	LoadTxTail(ctx context.Context, dbRound basics.Round) (roundData []*TxTailRound, roundHash []crypto.Digest, baseRound basics.Round, err error)
	LoadAllFullAccounts(ctx context.Context, balancesTable string, resourcesTable string, acctCb func(basics.Address, basics.AccountData)) (count int, err error)
	// testing
	Testing() AccountsReaderTestExt
}

// AccountsReaderWriter is AccountsReader+AccountsWriter
type AccountsReaderWriter interface {
	// AccountsReader
	// AccountsWriter
	AccountsWriterExt
	AccountsReaderExt
}

// OnlineAccountsWriter is the write interface for:
// - online accounts
type OnlineAccountsWriter interface {
	InsertOnlineAccount(addr basics.Address, normBalance uint64, data BaseOnlineAccountData, updRound uint64, voteLastValid uint64) (ref OnlineAccountRef, err error)

	Close()
}

// OnlineAccountsReader is the read interface for:
// - online accounts
type OnlineAccountsReader interface {
	LookupOnline(addr basics.Address, rnd basics.Round) (data PersistedOnlineAccountData, err error)
	LookupOnlineRoundParams(rnd basics.Round) (onlineRoundParamsData ledgercore.OnlineRoundParamsData, err error)
	LookupOnlineHistory(addr basics.Address) (result []PersistedOnlineAccountData, rnd basics.Round, err error)

	Close()
}

// CatchpointWriter is the write interface for:
// - catchpoints
type CatchpointWriter interface {
	CreateCatchpointStagingHashesIndex(ctx context.Context) (err error)

	StoreCatchpoint(ctx context.Context, round basics.Round, fileName string, catchpoint string, fileSize int64) (err error)

	WriteCatchpointStateUint64(ctx context.Context, stateName CatchpointState, setValue uint64) (err error)
	WriteCatchpointStateString(ctx context.Context, stateName CatchpointState, setValue string) (err error)

	WriteCatchpointStagingBalances(ctx context.Context, bals []NormalizedAccountBalance) error
	WriteCatchpointStagingKVs(ctx context.Context, keys [][]byte, values [][]byte, hashes [][]byte) error
	WriteCatchpointStagingOnlineAccounts(context.Context, []encoded.OnlineAccountRecordV6) error
	WriteCatchpointStagingOnlineRoundParams(context.Context, []encoded.OnlineRoundParamsRecordV6) error
	WriteCatchpointStagingCreatable(ctx context.Context, bals []NormalizedAccountBalance) error
	WriteCatchpointStagingHashes(ctx context.Context, bals []NormalizedAccountBalance) error

	ApplyCatchpointStagingBalances(ctx context.Context, balancesRound basics.Round, merkleRootRound basics.Round) (err error)
	ApplyCatchpointStagingTablesV7(ctx context.Context) error
	ResetCatchpointStagingBalances(ctx context.Context, newCatchup bool) (err error)

	InsertUnfinishedCatchpoint(ctx context.Context, round basics.Round, blockHash crypto.Digest) error
	DeleteUnfinishedCatchpoint(ctx context.Context, round basics.Round) error
	DeleteOldCatchpointFirstStageInfo(ctx context.Context, maxRoundToDelete basics.Round) error
	InsertOrReplaceCatchpointFirstStageInfo(ctx context.Context, round basics.Round, info *CatchpointFirstStageInfo) error

	DeleteStoredCatchpoints(ctx context.Context, dbDirectory string) (err error)
}

// CatchpointReader is the read interface for:
// - catchpoints
type CatchpointReader interface {
	GetCatchpoint(ctx context.Context, round basics.Round) (fileName string, catchpoint string, fileSize int64, err error)
	GetOldestCatchpointFiles(ctx context.Context, fileCount int, filesToKeep int) (fileNames map[basics.Round]string, err error)

	ReadCatchpointStateUint64(ctx context.Context, stateName CatchpointState) (val uint64, err error)
	ReadCatchpointStateString(ctx context.Context, stateName CatchpointState) (val string, err error)

	SelectUnfinishedCatchpoints(ctx context.Context) ([]UnfinishedCatchpointRecord, error)
	SelectCatchpointFirstStageInfo(ctx context.Context, round basics.Round) (CatchpointFirstStageInfo, bool /*exists*/, error)
	SelectOldCatchpointFirstStageInfoRounds(ctx context.Context, maxRound basics.Round) ([]basics.Round, error)
}

// CatchpointReaderWriter is CatchpointReader+CatchpointWriter
type CatchpointReaderWriter interface {
	CatchpointReader
	CatchpointWriter
}

// MerkleCommitter allows storing and loading merkletrie pages from a sqlite database.
type MerkleCommitter interface {
	StorePage(page uint64, content []byte) error
	LoadPage(page uint64) (content []byte, err error)
}

// OrderedAccountsIter is an iterator for Ordered Accounts.
type OrderedAccountsIter interface {
	Next(ctx context.Context) (acct []AccountAddressHash, processedRecords int, err error)
	Close(ctx context.Context) (err error)
}

// AccountAddressHash is used by Next to return a single account address and the associated hash.
type AccountAddressHash struct {
	AccountRef AccountRef
	Digest     []byte
}

// KVsIter is an iterator for an application Key/Values.
type KVsIter interface {
	Next() bool
	KeyValue() (k []byte, v []byte, err error)
	Close()
}

// TableIterator is used to add online accounts and online round params to catchpoint files.
type TableIterator[T any] interface {
	Next() bool
	GetItem() (T, error)
	Close()
}

// EncodedAccountsBatchIter is an iterator for a accounts.
type EncodedAccountsBatchIter interface {
	Next(ctx context.Context, accountCount int, resourceCount int) (bals []encoded.BalanceRecordV6, numAccountsProcessed uint64, err error)
	Close()
}

// CatchpointPendingHashesIter is an iterator for pending hashes.
type CatchpointPendingHashesIter interface {
	Next(ctx context.Context) (hashes [][]byte, err error)
	Close()
}

// SpVerificationCtxReader is a reader abstraction for stateproof verification tracker
// Use with SnapshotScope
type SpVerificationCtxReader interface {
	LookupSPContext(stateProofLastAttestedRound basics.Round) (*ledgercore.StateProofVerificationContext, error)
	GetAllSPContexts(ctx context.Context) ([]ledgercore.StateProofVerificationContext, error)
	GetAllSPContextsFromCatchpointTbl(ctx context.Context) ([]ledgercore.StateProofVerificationContext, error)
}

// SpVerificationCtxWriter is a writer abstraction for stateproof verification tracker
// Use with BatchScope
type SpVerificationCtxWriter interface {
	DeleteOldSPContexts(ctx context.Context, earliestLastAttestedRound basics.Round) error
	StoreSPContexts(ctx context.Context, verificationContext []*ledgercore.StateProofVerificationContext) error
	StoreSPContextsToCatchpointTbl(ctx context.Context, verificationContexts []ledgercore.StateProofVerificationContext) error
}

// SpVerificationCtxReaderWriter is SpVerificationCtxReader+SpVerificationCtxWriter
// Use with TransactionScope
type SpVerificationCtxReaderWriter interface {
	SpVerificationCtxReader
	SpVerificationCtxWriter
}
