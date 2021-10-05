// +build kv_badgerdb

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
	opts := badger.DefaultOptions(dbdir + ".badgerdb").WithInMemory(inMem)
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

// MultiGet some keys
func (b *BadgerDB) MultiGet(keys [][]byte) ([][]byte, error) {
	ret := make([][]byte, len(keys))
	err := b.Bdb.View(func(txn *badger.Txn) error {
		for i := range keys {
			item, err := txn.Get(keys[i])
			if err != nil {
				return err
			}
			ret[i], err = item.ValueCopy(nil)
			if err != nil {
				return err
			}
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

func (b *BadgerDB) Delete(key []byte) error {
	return b.Bdb.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

// badgerBatch is a batch of writes using the badger.WriteBatch API
type badgerBatch struct {
	wb *badger.WriteBatch
}

// NewBatch creates a batch writer
//func (b *BadgerDB) NewBatch() BatchWriter { return &badgerBatch{wb: b.Bdb.NewWriteBatch()} }

func (b *badgerBatch) Set(key, value []byte) error { return b.wb.Set(key, value) }
func (b *badgerBatch) Delete(key []byte) error     { return b.wb.Delete(key) }
func (b *badgerBatch) Commit() error               { return b.wb.Flush() }
func (b *badgerBatch) Cancel()                     { b.wb.Cancel() }

// badgerTxn is a batch of reads/writes using the badger.Txn API
type badgerTxn struct {
	txn *badger.Txn
}

func (b *BadgerDB) NewBatch() BatchWriter {
	return &badgerTxn{txn: b.Bdb.NewTransaction(true)}
}

func (b *BadgerDB) NewSnapshot() Snapshot {
	return &badgerTxn{txn: b.Bdb.NewTransaction(false)}
}

func (t *badgerTxn) Get(key []byte) ([]byte, error) {
	item, err := t.txn.Get(key)
	if err != nil {
		return nil, err
	}
	ret, err := item.ValueCopy(nil)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (t *badgerTxn) Set(key, value []byte) error { return t.txn.Set(key, value) }
func (t *badgerTxn) Delete(key []byte) error     { return t.txn.Delete(key) }
func (t *badgerTxn) Commit() error               { return t.txn.Commit() }
func (t *badgerTxn) Cancel()                     { t.txn.Discard() }
func (t *badgerTxn) Close()                      { t.txn.Discard() }

type badgerIterator struct {
	txn        *badger.Txn
	iter       *badger.Iterator
	start, end []byte
	reverse    bool
}

// Iterator scans a range: start and end are optional (set to nil/empty otherwise)
func (b *BadgerDB) NewIterator(start, end []byte, reverse bool) Iterator {
	txn := &badgerTxn{txn: b.Bdb.NewTransaction(false)}
	return txn.NewIterator(start, end, reverse)
}

func (t *badgerTxn) NewIterator(start, end []byte, reverse bool) Iterator {
	opts := badger.DefaultIteratorOptions
	opts.Reverse = reverse
	iter := t.txn.NewIterator(opts)
	iter.Rewind()
	if reverse {
		if len(end) != 0 {
			iter.Seek(end)
			if iter.Valid() && bytes.Compare(end, iter.Item().Key()) <= 0 {
				iter.Next()
			}
		}
	} else {
		if len(start) != 0 {
			iter.Seek(start)
		}
	}
	return &badgerIterator{txn: t.txn, iter: iter, start: start, end: end, reverse: reverse}
}

func (i *badgerIterator) Next()                  { i.iter.Next() }
func (i *badgerIterator) Key() []byte            { return i.iter.Item().KeyCopy(nil) }
func (i *badgerIterator) Value() ([]byte, error) { return i.iter.Item().ValueCopy(nil) }

// XXX could provide Item().Key() with guidance that Slice only valid until iter.Next()
func (i *badgerIterator) KeySlice() Slice { return badgerSlice(i.iter.Item().KeyCopy(nil)) }
func (i *badgerIterator) ValueSlice() (Slice, error) {
	ret, err := i.iter.Item().ValueCopy(nil)
	return badgerSlice(ret), err
}

type badgerSlice []byte

func (s badgerSlice) Data() []byte { return s }
func (s badgerSlice) Free()        {}
func (s badgerSlice) Size() int    { return len(s) }
func (s badgerSlice) Exists() bool { return s != nil }

func (i *badgerIterator) Close() {
	i.iter.Close()
	i.txn.Discard()
}

func (i *badgerIterator) Valid() bool {
	if !i.iter.Valid() {
		return false
	}
	if i.reverse {
		if len(i.start) != 0 && bytes.Compare(i.iter.Item().Key(), i.start) < 0 {
			return false
		}
	} else {
		if len(i.end) != 0 && bytes.Compare(i.end, i.iter.Item().Key()) <= 0 {
			return false
		}
	}
	return true
}
