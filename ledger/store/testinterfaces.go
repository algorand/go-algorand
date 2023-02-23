package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/stretchr/testify/require"
)

// testinterfaces.go contains interface extensions for the store package
// to use test-only functionality, cast your Interface to the test-version, eg:
// testTx := tx.(TransactionTestScope)

type BatchTestScope interface {
	BatchScope

	AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool)
	AccountsUpdateSchemaTest(ctx context.Context) (err error)
	RunMigrations(ctx context.Context, params TrackerDBParams, log logging.Logger, targetVersion int32) (mgr TrackerDBInitParams, err error)
}

// implements BatchTestScope for sql TX Scopes
func (bs sqlBatchScope) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	return AccountsInitTest(tb, bs.tx, initAccounts, proto)
}

// implements BatchTestScope for sql TX Scopes
func (bs sqlBatchScope) AccountsUpdateSchemaTest(ctx context.Context) (err error) {
	return AccountsUpdateSchemaTest(ctx, bs.tx)
}

// implements BatchTestScope for sql TX Scopes
func (bs sqlBatchScope) RunMigrations(ctx context.Context, params TrackerDBParams, log logging.Logger, targetVersion int32) (mgr TrackerDBInitParams, err error) {
	return RunMigrations(ctx, bs.tx, params, log, targetVersion)
}

type TransactionTestScope interface {
	TransactionScope

	MakeAccountsOptimizedReader() (AccountsReader, error)
	MakeOnlineAccountsOptimizedReader() (OnlineAccountsReader, error)
	AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool)
	AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error)
}

// implements TransactionTestScope for sql TX Scopes
func (txs sqlTransactionScope) MakeAccountsOptimizedReader() (AccountsReader, error) {
	return AccountsInitDbQueries(txs.tx)
}

// implements TransactionTestScope for sql TX Scopes
func (txs sqlTransactionScope) MakeOnlineAccountsOptimizedReader() (r OnlineAccountsReader, err error) {
	return OnlineAccountsInitDbQueries(txs.tx)
}

// implements TransactionTestScope for sql TX Scopes
func (txs sqlTransactionScope) AccountsInitTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto protocol.ConsensusVersion) (newDatabase bool) {
	return AccountsInitTest(tb, txs.tx, initAccounts, proto)
}

// implements TransactionTestScope for sql TX Scopes
func (txs sqlTransactionScope) AccountsInitLightTest(tb testing.TB, initAccounts map[basics.Address]basics.AccountData, proto config.ConsensusParams) (newDatabase bool, err error) {
	return AccountsInitLightTest(tb, txs.tx, initAccounts, proto)
}

type TestAccountsReaderExt interface {
	AccountsReaderExt

	AccountsAllTest() (bals map[basics.Address]basics.AccountData, err error)
	CheckCreatablesTest(t *testing.T, iteration int, expectedDbImage map[basics.CreatableIndex]ledgercore.ModifiedCreatable)
}

// AccountsAllTest iterates the account table and returns a map of the data
// It is meant only for testing purposes - it is heavy and has no production use case.
// implements TestAccountsReaderExt for V2 Readers
func (r *accountsV2Reader) AccountsAllTest() (bals map[basics.Address]basics.AccountData, err error) {
	rows, err := r.q.Query("SELECT rowid, address, data FROM accountbase")
	if err != nil {
		return
	}
	defer rows.Close()

	bals = make(map[basics.Address]basics.AccountData)
	for rows.Next() {
		var addrbuf []byte
		var buf []byte
		var rowid sql.NullInt64
		err = rows.Scan(&rowid, &addrbuf, &buf)
		if err != nil {
			return
		}

		var data BaseAccountData
		err = protocol.Decode(buf, &data)
		if err != nil {
			return
		}

		var addr basics.Address
		if len(addrbuf) != len(addr) {
			err = fmt.Errorf("account DB address length mismatch: %d != %d", len(addrbuf), len(addr))
			return
		}
		copy(addr[:], addrbuf)

		var ad basics.AccountData
		ad, err = r.LoadFullAccount(context.Background(), "resources", addr, rowid.Int64, data)
		if err != nil {
			return
		}

		bals[addr] = ad
	}

	err = rows.Err()
	return
}

// meant only for testing purposes - it is heavy and has no production use case.
// implements TestAccountsReaderExt for V2 Readers
func (r *accountsV2Reader) CheckCreatablesTest(t *testing.T,
	iteration int,
	expectedDbImage map[basics.CreatableIndex]ledgercore.ModifiedCreatable) {
	stmt, err := r.q.Prepare("SELECT asset, creator, ctype FROM assetcreators")
	require.NoError(t, err)

	defer stmt.Close()
	rows, err := stmt.Query()
	if err != sql.ErrNoRows {
		require.NoError(t, err)
	}
	defer rows.Close()
	counter := 0
	for rows.Next() {
		counter++
		mc := ledgercore.ModifiedCreatable{}
		var buf []byte
		var asset basics.CreatableIndex
		err := rows.Scan(&asset, &buf, &mc.Ctype)
		require.NoError(t, err)
		copy(mc.Creator[:], buf)

		require.NotNil(t, expectedDbImage[asset])
		require.Equal(t, expectedDbImage[asset].Creator, mc.Creator)
		require.Equal(t, expectedDbImage[asset].Ctype, mc.Ctype)
		require.True(t, expectedDbImage[asset].Created)
	}
	require.Equal(t, len(expectedDbImage), counter)
}

type TestTrackerStore interface {
	TrackerStore

	CleanupTest(dbName string, inMemory bool)
	ResetToV6Test(ctx context.Context) error
}

func (s *trackerSQLStore) CleanupTest(dbName string, inMemory bool) {
	s.pair.Close()
	if !inMemory {
		os.Remove(dbName)
	}
}

func (s *trackerSQLStore) ResetToV6Test(ctx context.Context) error {
	var resetExprs = []string{
		`DROP TABLE IF EXISTS onlineaccounts`,
		`DROP TABLE IF EXISTS txtail`,
		`DROP TABLE IF EXISTS onlineroundparamstail`,
		`DROP TABLE IF EXISTS catchpointfirststageinfo`,
	}

	return s.pair.Wdb.AtomicContext(ctx, func(ctx context.Context, tx *sql.Tx) error {
		for _, stmt := range resetExprs {
			_, err := tx.ExecContext(ctx, stmt)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
