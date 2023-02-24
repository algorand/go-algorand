package storetest

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/ledger/store"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// testinterfaces.go contains interface extensions for the store package
// to use test-only functionality, cast your Interface to the test-version, eg:
// testTx := tx.(TransactionTestScope)
// implementations of test functionality should live in the store package to prevent import cycles

type BatchTestScope interface {
	store.BatchScope

	AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool)
	AccountsUpdateSchemaTest(ctx context.Context) (err error)
	RunMigrations(ctx context.Context, params store.TrackerDBParams, log logging.Logger, targetVersion int32) (mgr store.TrackerDBInitParams, err error)
}

type TransactionTestScope interface {
	store.TransactionScope

	MakeAccountsOptimizedReader() (store.AccountsReader, error)
	MakeOnlineAccountsOptimizedReader() (store.OnlineAccountsReader, error)
	AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool)
	AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error)
}

type TestAccountsReaderExt interface {
	store.AccountsReaderExt

	AccountsAllTest() (bals map[basics.Address]basics.AccountData, err error)
	CheckCreatablesTest(t *testing.T, iteration int, expectedDbImage map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
}

type TestTrackerStore interface {
	store.TrackerStore

	CleanupTest(dbName string, inMemory bool)
	ResetToV6Test(ctx context.Context) error
}
