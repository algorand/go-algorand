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
	opts.SetCache(levigo.NewLRUCache(4 * 1024 * 1024))
	opts.SetCreateIfMissing(true)
	opts.SetWriteBufferSize(64 * 1024 * 1024) // RocksDB default is 64MB
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
func (db *LevelDB) Delete(key []byte) error {
	db.Ldb.Delete(db.wo, key)
	return nil
}

func (db *LevelDB) MultiGet(keys [][]byte) ([][]byte, error) {
	snap := db.Ldb.NewSnapshot()
	defer db.Ldb.ReleaseSnapshot(snap)
	opts := levigo.NewReadOptions()
	opts.SetSnapshot(snap)
	defer opts.Close()

	ret := make([][]byte, len(keys))
	for i := range keys {
		key, err := db.Ldb.Get(opts, keys[i])
		if err != nil {
			return nil, err
		}
		ret[i] = make([]byte, len(key))
		copy(ret[i], key)
	}
	return ret, nil
}

type levelBatch struct {
	db *LevelDB
	wb *levigo.WriteBatch
}

func (db *LevelDB) NewBatch() BatchWriter { return &levelBatch{wb: levigo.NewWriteBatch(), db: db} }

func (b *levelBatch) Set(key, val []byte) error {
	b.wb.Put(key, val)
	return nil
}
func (b *levelBatch) Delete(key []byte) error {
	b.wb.Delete(key)
	return nil
}
func (b *levelBatch) Commit() error {
	defer b.wb.Close()
	return b.db.Ldb.Write(b.db.wo, b.wb)
}
func (b *levelBatch) Cancel() { b.wb.Close() }

type levelSnapshot struct {
	db   *LevelDB
	opts *levigo.ReadOptions
	snap *levigo.Snapshot
}

func (db *LevelDB) NewSnapshot() Snapshot {
	snap := db.Ldb.NewSnapshot()
	opts := levigo.NewReadOptions()
	opts.SetSnapshot(snap)
	return &levelSnapshot{snap: snap, opts: opts, db: db}
}

func (s *levelSnapshot) Get(key []byte) ([]byte, error) {
	return s.db.Ldb.Get(s.opts, key)
}
func (s *levelSnapshot) NewIterator(start, end []byte, reverse bool) Iterator {
	return s.db.newIterator(s.opts, start, end, reverse)
}
func (s *levelSnapshot) Close() {
	s.opts.Close()
	s.db.Ldb.ReleaseSnapshot(s.snap)
}

type levelIterator struct {
	iter       *levigo.Iterator
	start, end []byte
	reverse    bool
}

func (db *LevelDB) NewIterator(start, end []byte, reverse bool) Iterator {
	return db.newIterator(db.ro, start, end, reverse)
}

func (db *LevelDB) newIterator(opts *levigo.ReadOptions, start, end []byte, reverse bool) Iterator {
	iter := db.Ldb.NewIterator(opts)
	if !reverse {
		if len(start) != 0 {
			iter.Seek(start)
		} else {
			iter.SeekToFirst()
		}
	} else {
		if len(end) != 0 {
			iter.Seek(end)
			if iter.Valid() && bytes.Compare(end, iter.Key()) <= 0 {
				iter.Prev()
			}
		} else {
			iter.SeekToLast()
		}
	}
	return &levelIterator{iter: iter, start: start, end: end, reverse: reverse}
}

func (i *levelIterator) Next() {
	if i.reverse {
		i.iter.Prev()
	} else {
		i.iter.Next()
	}
}

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
	if i.reverse {
		if len(i.start) != 0 && bytes.Compare(i.iter.Key(), i.start) < 0 {
			return false
		}
	} else {
		if len(i.end) != 0 && bytes.Compare(i.end, i.iter.Key()) <= 0 {
			return false
		}
	}
	return true
}
