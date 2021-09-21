package kvstore

import (
	"bytes"

	"github.com/dgraph-io/badger/v3"
)

func init() {
	kvImpls["badger"] = badgerDBFactory{}
	kvImpls["badgerdb"] = badgerDBFactory{}
}

type badgerDBFactory struct{}

func (badgerDBFactory) New(dbdir string, inMem bool) (KVStore, error) {
	return NewBadgerDB(dbdir, inMem)
}

// BadgerDB implements KVStore
type BadgerDB struct {
	Bdb *badger.DB
}

// NewBadgerDB opens a BadgerDB in the specified directory
func NewBadgerDB(dbdir string, inMem bool) (*BadgerDB, error) {
	opts := badger.DefaultOptions(dbdir).WithInMemory(inMem)
	opts = opts.WithSyncWrites(true) // XXX
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &BadgerDB{Bdb: db}, nil
}

// Close closes the database
func (b *BadgerDB) Close() error {
	return b.Bdb.Close()
}

// Get a key
func (b *BadgerDB) Get(key []byte) ([]byte, error) {
	var ret []byte
	err := b.Bdb.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		ret, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}
		return nil
	})
	return ret, err
}

// Set a key to value
func (b *BadgerDB) Set(key, value []byte) error {
	return b.Bdb.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}

// badgerBatch is a batch of writes using the badger.WriteBatch API
type badgerBatch struct {
	wb *badger.WriteBatch
}

// NewBatch creates a batch writer
//func (b *BadgerDB) NewBatch() BatchWriter { return &badgerBatch{wb: b.Bdb.NewWriteBatch()} }

func (b *badgerBatch) Set(key, value []byte) error { return b.wb.Set(key, value) }
func (b *badgerBatch) Commit() error               { return b.wb.Flush() }
func (b *badgerBatch) Cancel()                     { b.wb.Cancel() }

// badgerTxn is a batch of reads/writes using the badger.Txn API
type badgerTxn struct {
	txn *badger.Txn
}

func (b *BadgerDB) NewBatch() BatchWriter {
	return &badgerTxn{txn: b.Bdb.NewTransaction(true)}
}

func (t *badgerTxn) Set(key, value []byte) error { return t.txn.Set(key, value) }
func (t *badgerTxn) Commit() error               { return t.txn.Commit() }
func (t *badgerTxn) Cancel()                     { t.txn.Discard() }

type badgerIterator struct {
	txn  *badger.Txn
	iter *badger.Iterator
	end  []byte
}

// Iterator scans a range: start and end are optional (set to nil/empty otherwise)
func (b *BadgerDB) NewIterator(start, end []byte) Iterator {
	txn := b.Bdb.NewTransaction(false)
	opts := badger.DefaultIteratorOptions
	iter := txn.NewIterator(opts)
	iter.Rewind()
	if len(start) != 0 {
		iter.Seek(start)
	}
	return &badgerIterator{txn: txn, iter: iter, end: end}
}

func (i *badgerIterator) Next()                  { i.iter.Next() }
func (i *badgerIterator) Key() []byte            { return i.iter.Item().KeyCopy(nil) }
func (i *badgerIterator) Value() ([]byte, error) { return i.iter.Item().ValueCopy(nil) }

func (i *badgerIterator) Close() {
	i.iter.Close()
	i.txn.Discard()
}

func (i *badgerIterator) Valid() bool {
	if !i.iter.Valid() {
		return false
	}
	if len(i.end) != 0 {
		key := i.iter.Item().Key()
		if c := bytes.Compare(key, i.end); c >= 0 {
			return false
		}
	}
	return true
}
