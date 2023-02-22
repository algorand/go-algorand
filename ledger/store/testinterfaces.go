package store

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type BatchTestScope interface {
	BatchScope

	AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool)
	AccountsUpdateSchemaTest(ctx context.Context) (err error)
	RunMigrations(ctx context.Context, params TrackerDBParams, log logging.Logger, targetVersion int32) (mgr TrackerDBInitParams, err error)
}

func (bs sqlBatchScope) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	return AccountsInitTest(tb, bs.tx, initAccounts, proto)
}

func (bs sqlBatchScope) AccountsUpdateSchemaTest(ctx context.Context) (err error) {
	return AccountsUpdateSchemaTest(ctx, bs.tx)
}

func (bs sqlBatchScope) RunMigrations(ctx context.Context, params TrackerDBParams, log logging.Logger, targetVersion int32) (mgr TrackerDBInitParams, err error) {
	return RunMigrations(ctx, bs.tx, params, log, targetVersion)
}
