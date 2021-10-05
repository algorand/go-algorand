package ledger

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/util/db"
	"github.com/algorand/go-algorand/util/kvstore"
)

func (w *atomicWriteTx) Rollback() {
	(w.kvWrite).(kvstore.BatchWriter).Cancel()
	w.sqlTx.Rollback()
}
func (w *atomicWriteTx) Commit() error {
	w.writeBarrier()
	return w.sqlTx.Commit()
}

// helper for tests that call Wdb.Handle.Begin() to create and cancel SQL transactions
func beginWriteTx(t testing.TB, dbs db.Pair, kv kvstore.KVStore) (*atomicWriteTx, error) {
	tx, err := dbs.Wdb.Handle.Begin()
	if err != nil {
		return nil, err
	}
	return &atomicWriteTx{sqlTx: tx, kvWrite: kv.NewBatch(), kv: kv}, nil
}

type readTx struct {
	sqlTx      *sql.Tx
	kvRead     kvRead
	kvMultiGet kvMultiGet
	snap       kvstore.Snapshot
}

func (r *readTx) Rollback() {
	r.snap.Close()
	r.sqlTx.Rollback()
}
func (r *readTx) Commit() error {
	r.snap.Close() // XXX re-open a new snapshot?
	return r.sqlTx.Commit()
}

// helper for tests that call Rdb.Handle.Begin()
func beginReadTx(t testing.TB, dbs db.Pair, kv kvstore.KVStore) (*readTx, error) {
	var ret readTx
	tx, err := dbs.Rdb.Handle.Begin()
	if err != nil {
		return nil, err
	}
	// XXX necessary to make KV snapshot?
	ret.sqlTx = tx
	ret.kvRead = kv
	ret.kvMultiGet = kv
	return &ret, nil
}

/// for checkCreatables test
///
type kvAllCreatorsIter struct {
	first bool
	it    kvstore.Iterator
}

func (i *kvAllCreatorsIter) Err() error { return nil }
func (i *kvAllCreatorsIter) Close() error {
	i.it.Close()
	return nil
}

func (i *kvAllCreatorsIter) Next() bool {
	if i.first {
		i.first = false
	} else {
		i.it.Next()
	}
	return i.it.Valid()
}

func (i *kvAllCreatorsIter) Scan(args ...interface{}) error {
	// rnd *basics.CreatableIndex, creator *[]byte, ctype *basics.CreatableType
	if len(args) != 3 {
		return fmt.Errorf("kvAllCreatorsIter Scan args should be 3, got %d", len(args))
	}
	argCidx := (args[0]).(*basics.CreatableIndex)
	argBuf := (args[1]).(*[]byte)
	argCtype := (args[2]).(*basics.CreatableType)

	ik := i.it.KeySlice()
	defer ik.Free()
	iv, err := i.it.ValueSlice()
	if err != nil {
		return err
	}
	defer iv.Free()
	ctype, cidx, err := splitAssetCreatorsKey(ik.Data())
	if err != nil {
		return err
	}

	creator := make([]byte, iv.Size())
	copy(creator[:], iv.Data())
	*argBuf = creator
	*argCidx = cidx
	*argCtype = ctype
	return nil
}

// simulate "SELECT asset, creator, ctype FROM assetcreators")
func kvAllCreatables(kv kvRead) (accountIterator, error) {
	iter := kv.NewIterator([]byte(kvPrefixAssetCreators), []byte(kvPrefixAssetCreatorsEndRange), false)
	return &kvAllCreatorsIter{first: true, it: iter}, nil
}
