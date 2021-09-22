// +build kv_leveldb

package kvstore

import (
	"bytes"

	"github.com/jmhodges/levigo"
)

func init() {
	kvImpls["level"] = levelDBFactory{}
	kvImpls["leveldb"] = levelDBFactory{}
}

type levelDBFactory struct{}

func (levelDBFactory) New(dbdir string, inMem bool) (KVStore, error) { return NewLevelDB(dbdir) }

// LevelDB implements KVStore
type LevelDB struct {
	Ldb *levigo.DB
	ro  *levigo.ReadOptions
	wo  *levigo.WriteOptions
}

func NewLevelDB(dbdir string) (*LevelDB, error) {
	opts := levigo.NewOptions()
	opts.SetCache(levigo.NewLRUCache(1 << 30))
	opts.SetCreateIfMissing(true)
	opts.SetFilterPolicy(levigo.NewBloomFilter(10))

	db, err := levigo.Open(dbdir+".leveldb", opts)
	if err != nil {
		return nil, err
	}

	ro := levigo.NewReadOptions()
	wo := levigo.NewWriteOptions()
	wo.SetSync(true)
	return &LevelDB{Ldb: db, ro: ro, wo: wo}, nil
}

func (db *LevelDB) Close() error {
	db.ro.Close()
	db.wo.Close()
	db.Ldb.Close()
	return nil
}

func (db *LevelDB) Get(key []byte) ([]byte, error) { return db.Ldb.Get(db.ro, key) }
func (db *LevelDB) Set(key, val []byte) error      { return db.Ldb.Put(db.wo, key, val) }

type levelBatch struct {
	db *LevelDB
	wb *levigo.WriteBatch
}

func (db *LevelDB) NewBatch() BatchWriter { return &levelBatch{wb: levigo.NewWriteBatch(), db: db} }

func (b *levelBatch) Set(key, val []byte) error {
	b.wb.Put(key, val)
	return nil
}
func (b *levelBatch) Commit() error {
	defer b.wb.Close()
	return b.db.Ldb.Write(b.db.wo, b.wb)
}
func (b *levelBatch) Cancel() { b.wb.Close() }

type levelIterator struct {
	iter *levigo.Iterator
	end  []byte
}

func (db *LevelDB) NewIterator(start, end []byte) Iterator {
	iter := db.Ldb.NewIterator(db.ro)
	if len(start) != 0 {
		iter.Seek(start)
	} else {
		iter.SeekToFirst()
	}
	return &levelIterator{iter: iter, end: end}
}

func (i *levelIterator) Next()                      { i.iter.Next() }
func (i *levelIterator) Key() []byte                { return i.iter.Key() }
func (i *levelIterator) Value() ([]byte, error)     { return i.iter.Value(), nil }
func (i *levelIterator) Close()                     { i.iter.Close() }
func (i *levelIterator) KeySlice() Slice            { return levelSlice(i.iter.Key()) }
func (i *levelIterator) ValueSlice() (Slice, error) { return levelSlice(i.iter.Value()), nil }

type levelSlice []byte

func (s levelSlice) Data() []byte { return s }
func (s levelSlice) Free()        {}
func (s levelSlice) Size() int    { return len(s) }
func (s levelSlice) Exists() bool { return s != nil }

func (i *levelIterator) Valid() bool {
	if !i.iter.Valid() {
		return false
	}
	if len(i.end) != 0 {
		if c := bytes.Compare(i.iter.Key(), i.end); c >= 0 {
			return false
		}
	}
	return true
}
