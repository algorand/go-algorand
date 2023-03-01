package trackerdb

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// testinterfaces.go contains interface extensions for the store package
// to use test-only functionality, cast your Interface to the test-version, eg:
// testTx := tx.(TransactionTestScope)

type TestBatchScope interface {
	BatchScope

	AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool)
	AccountsUpdateSchemaTest(ctx context.Context) (err error)
	RunMigrations(ctx context.Context, params Params, log logging.Logger, targetVersion int32) (mgr InitParams, err error)
	ModifyAcctBaseTest() error
}

type TestTransactionScope interface {
	TransactionScope

	MakeAccountsOptimizedReader() (AccountsReader, error)
	MakeOnlineAccountsOptimizedReader() (OnlineAccountsReader, error)
	AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool)
	AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error)
}

type TestAccountsReaderExt interface {
	AccountsReaderExt

	AccountsAllTest() (bals map[basics.Address]basics.AccountData, err error)
	CheckCreatablesTest(t *testing.T, iteration int, expectedDbImage map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
}
