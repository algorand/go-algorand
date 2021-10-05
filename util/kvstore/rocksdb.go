// +build kv_rocksdb

package kvstore

import (
	"bytes"
	"fmt"
	"runtime"

	"github.com/tecbot/gorocksdb"
)

func init() {
	kvImpls["rocks"] = rocksDBFactory{}
	kvImpls["rocksdb"] = rocksDBFactory{}
}

type rocksDBFactory struct{}

func (rocksDBFactory) New(dbdir string, inMem bool) (KVStore, error) { return NewRocksDB(dbdir) }

type RocksDB struct {
	Rdb *gorocksdb.DB
	ro  *gorocksdb.ReadOptions
	wo  *gorocksdb.WriteOptions
}

func NewRocksDB(dbdir string) (*RocksDB, error) {
	bbto := gorocksdb.NewDefaultBlockBasedTableOptions()
	bbto.SetBlockCache(gorocksdb.NewLRUCache(4 * 1024 * 1024))
	bbto.SetFilterPolicy(gorocksdb.NewBloomFilter(10))

	opts := gorocksdb.NewDefaultOptions()
	opts.SetBlockBasedTableFactory(bbto)
	opts.SetCreateIfMissing(true)
	opts.IncreaseParallelism(runtime.NumCPU())
	// 1.5GB maximum memory use for writebuffer.
	opts.OptimizeLevelStyleCompaction(512 * 1024 * 1024)

	db, err := gorocksdb.OpenDb(opts, dbdir+".rocksdb")
	if err != nil {
		return nil, err
	}
	ro := gorocksdb.NewDefaultReadOptions()
	wo := gorocksdb.NewDefaultWriteOptions()
	//woSync := gorocksdb.NewDefaultWriteOptions()
	wo.SetSync(true)
	return &RocksDB{Rdb: db, ro: ro, wo: wo}, nil
}

func (db *RocksDB) Close() error {
	if db == nil {
		return nil
	}
	db.ro.Destroy()
	db.wo.Destroy()
	db.Rdb.Close()
	return nil
}

func sliceBytes(val *gorocksdb.Slice) []byte {
	defer val.Free()
	if !val.Exists() {
		return nil
	}
	ret := make([]byte, len(val.Data()))
	copy(ret, val.Data())
	return ret
}

func (db *RocksDB) Get(key []byte) ([]byte, error) {
	return db.get(db.ro, key)
}

func (db *RocksDB) get(opts *gorocksdb.ReadOptions, key []byte) ([]byte, error) {
	val, err := db.Rdb.Get(opts, key)
	if err != nil {
		return nil, err
	}
	if val.Data() == nil {
		return nil, fmt.Errorf("%x: %w", key, ErrKeyNotFound)
	}
	return sliceBytes(val), nil
}

func (db *RocksDB) Set(key []byte, val []byte) error { return db.Rdb.Put(db.wo, key, val) }

func (db *RocksDB) Delete(key []byte) error {
	db.Rdb.Delete(db.wo, key)
	return nil
}
func (db *RocksDB) DeleteRange(start, end []byte) error { return kvDeleteRange(db, start, end) }

func (db *RocksDB) MultiGet(keys [][]byte) ([][]byte, error) {
	val, err := db.Rdb.MultiGet(db.ro, keys...)
	if err != nil {
		return nil, err
	}
	ret := make([][]byte, len(val))
	for i := 0; i < len(val); i++ {
		ret[i] = sliceBytes(val[i])
	}
	return ret, nil
}

type rocksBatch struct {
	rdb *RocksDB
	wb  *gorocksdb.WriteBatch
}

func (db *RocksDB) NewBatch() BatchWriter { return &rocksBatch{wb: gorocksdb.NewWriteBatch(), rdb: db} }

func (b *rocksBatch) Set(key, value []byte) error {
	b.wb.Put(key, value)
	return nil
}
func (b *rocksBatch) Delete(key []byte) error {
	b.wb.Delete(key)
	return nil
}
func (b *rocksBatch) DeleteRange(start, end []byte) error {
	b.wb.DeleteRange(start, end)
	return nil
}
func (b *rocksBatch) WriteBarrier() error {
	err := b.rdb.Rdb.Write(b.rdb.wo, b.wb)
	b.wb.Destroy()
	b.wb = gorocksdb.NewWriteBatch()
	return err
}

func (b *rocksBatch) Commit() error {
	defer b.wb.Destroy()
	return b.rdb.Rdb.Write(b.rdb.wo, b.wb)
}
func (b *rocksBatch) Cancel() { b.wb.Destroy() }

type rocksSnapshot struct {
	db   *RocksDB
	opts *gorocksdb.ReadOptions
	snap *gorocksdb.Snapshot
}

func (db *RocksDB) NewSnapshot() Snapshot {
	snap := db.Rdb.NewSnapshot()
	opts := gorocksdb.NewDefaultReadOptions()
	opts.SetSnapshot(snap)
	return &rocksSnapshot{snap: snap, opts: opts, db: db}
}

func (s *rocksSnapshot) Get(key []byte) ([]byte, error) {
	return s.db.get(s.opts, key)
}
func (s *rocksSnapshot) NewIterator(start, end []byte, reverse bool) Iterator {
	return s.db.newIterator(s.opts, start, end, reverse)
}
func (s *rocksSnapshot) Close() {
	s.opts.Destroy()
	s.db.Rdb.ReleaseSnapshot(s.snap)
}

type rocksIterator struct {
	iter       *gorocksdb.Iterator
	start, end []byte
	reverse    bool
}

func (db *RocksDB) NewIterator(start, end []byte, reverse bool) Iterator {
	return db.newIterator(db.ro, start, end, reverse)
}

func (db *RocksDB) newIterator(opts *gorocksdb.ReadOptions, start, end []byte, reverse bool) Iterator {
	iter := db.Rdb.NewIterator(opts)
	if !reverse {
		if len(start) != 0 {
			iter.Seek(start)
		} else {
			iter.SeekToFirst()
		}
	} else {
		if len(end) != 0 {
			iter.SeekForPrev(end)
			if bytes.Compare(end, sliceBytes(iter.Key())) <= 0 {
				iter.Prev()
			}
		} else {
			iter.SeekToLast()
		}
	}
	return &rocksIterator{iter: iter, start: start, end: end, reverse: reverse}
}

func (i *rocksIterator) Next() {
	if i.reverse {
		i.iter.Prev()
	} else {
		i.iter.Next()
	}
}

func (i *rocksIterator) Key() []byte                { return sliceBytes(i.iter.Key()) }
func (i *rocksIterator) Value() ([]byte, error)     { return sliceBytes(i.iter.Value()), nil }
func (i *rocksIterator) Close()                     { i.iter.Close() }
func (i *rocksIterator) KeySlice() Slice            { return &rocksSlice{i.iter.Key()} }
func (i *rocksIterator) ValueSlice() (Slice, error) { return &rocksSlice{i.iter.Value()}, nil }

type rocksSlice struct {
	*gorocksdb.Slice
}

func (i *rocksIterator) Valid() bool {
	if !i.iter.Valid() {
		return false
	}
	if i.reverse {
		if len(i.start) != 0 && bytes.Compare(sliceBytes(i.iter.Key()), i.start) < 0 {
			return false
		}
	} else {
		if len(i.end) != 0 && bytes.Compare(i.end, sliceBytes(i.iter.Key())) <= 0 {
			return false
		}
	}
	return true
}
