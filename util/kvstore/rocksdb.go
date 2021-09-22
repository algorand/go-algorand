// +build kv_rocksdb

package kvstore

import (
	"bytes"
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
	bbto.SetBlockCache(gorocksdb.NewLRUCache(1 << 30))
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
	val, err := db.Rdb.Get(db.ro, key)
	if err != nil {
		return nil, err
	}
	return sliceBytes(val), nil
}

func (db *RocksDB) Set(key []byte, val []byte) error { return db.Rdb.Put(db.wo, key, val) }

type rocksBatch struct {
	rdb *RocksDB
	wb  *gorocksdb.WriteBatch
}

func (db *RocksDB) NewBatch() BatchWriter { return &rocksBatch{wb: gorocksdb.NewWriteBatch(), rdb: db} }

func (b *rocksBatch) Set(key, value []byte) error {
	b.wb.Put(key, value)
	return nil
}
func (b *rocksBatch) Commit() error {
	defer b.wb.Destroy()
	return b.rdb.Rdb.Write(b.rdb.wo, b.wb)
}
func (b *rocksBatch) Cancel() { b.wb.Destroy() }

type rocksIterator struct {
	iter *gorocksdb.Iterator
	end  []byte
}

func (db *RocksDB) NewIterator(start, end []byte) Iterator {
	iter := db.Rdb.NewIterator(db.ro)
	if len(start) != 0 {
		iter.Seek(start)
	} else {
		iter.SeekToFirst()
	}
	return &rocksIterator{iter: iter, end: end}
}

func (i *rocksIterator) Next()                      { i.iter.Next() }
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
	if len(i.end) != 0 {
		if c := bytes.Compare(sliceBytes(i.iter.Key()), i.end); c >= 0 {
			return false
		}
	}
	return true
}
