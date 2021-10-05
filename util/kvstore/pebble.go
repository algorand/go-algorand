// +build kv_pebbledb

package kvstore

import (
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"
	"github.com/cockroachdb/pebble/vfs"
)

func init() {
	kvImpls["pebble"] = pebbleDBFactory{}
	kvImpls["pebbledb"] = pebbleDBFactory{}
}

type pebbleDBFactory struct{}

func (pebbleDBFactory) New(dbdir string, inMem bool) (KVStore, error) {
	return NewPebbleDB(dbdir, inMem)
}

// PebbleDB implements KVstore
type PebbleDB struct {
	Pdb *pebble.DB
	wo  *pebble.WriteOptions
}

// NewPebbleDB opens a PebbleDB in the specified directory
func NewPebbleDB(dbdir string, inMem bool) (*PebbleDB, error) {
	cache := pebble.NewCache(4 * 1024 * 1024)
	defer cache.Unref()
	// based on cockroach DB's DefaultPebbleOptions()
	opts := &pebble.Options{
		Cache:                       cache,
		L0CompactionThreshold:       2,
		L0StopWritesThreshold:       1000,
		LBaseMaxBytes:               64 << 20, // 64 MB
		Levels:                      make([]pebble.LevelOptions, 7),
		MaxConcurrentCompactions:    3,
		MemTableSize:                64 << 20, // 64 MB
		MemTableStopWritesThreshold: 4,
	}
	opts.Experimental.DeleteRangeFlushDelay = 10 * time.Second
	opts.Experimental.MinDeletionRate = 128 << 20 // 128 MB
	opts.Experimental.ReadSamplingMultiplier = -1
	for i := 0; i < len(opts.Levels); i++ {
		l := &opts.Levels[i]
		l.BlockSize = 32 << 10       // 32 KB
		l.IndexBlockSize = 256 << 10 // 256 KB
		l.FilterPolicy = bloom.FilterPolicy(10)
		l.FilterType = pebble.TableFilter
		if i > 0 {
			l.TargetFileSize = opts.Levels[i-1].TargetFileSize * 2
		}
		l.EnsureDefaults()
	}
	opts.Levels[6].FilterPolicy = nil
	if inMem {
		opts.FS = vfs.NewMem()
	}
	db, err := pebble.Open(dbdir+".pebbledb", opts)
	if err != nil {
		return nil, err
	}
	wo := &pebble.WriteOptions{Sync: true}
	return &PebbleDB{Pdb: db, wo: wo}, nil
}

// Close closes the database
func (db *PebbleDB) Close() error { return db.Pdb.Close() }

// Get a key
func (db *PebbleDB) Get(key []byte) ([]byte, error) {
	val, closer, err := db.Pdb.Get(key)
	if err != nil {
		return nil, err
	}
	ret := make([]byte, len(val))
	copy(ret, val)
	closer.Close()
	return ret, nil
}

// Set a key to value
func (db *PebbleDB) Set(key, value []byte) error { return db.Pdb.Set(key, value, db.wo) }

func (db *PebbleDB) Delete(key []byte) error { return db.Pdb.Delete(key, db.wo) }

// MultiGet by using snapshots
func (db *PebbleDB) MultiGet(keys [][]byte) ([][]byte, error) {
	snap := db.Pdb.NewSnapshot()
	defer snap.Close()
	ret := make([][]byte, len(keys))
	for i := range keys {
		val, closer, err := snap.Get(keys[i])
		if err != nil {
			return nil, err
		}
		ret[i] = make([]byte, len(val))
		copy(ret[i], val)
		closer.Close()
	}
	return ret, nil
}

// pebbleBatch is a batch of writes using the pebble.WriteBatch API
type pebbleBatch struct {
	wb *pebble.Batch
	wo *pebble.WriteOptions
}

// NewBatch creates a batch writer
func (db *PebbleDB) NewBatch() BatchWriter { return &pebbleBatch{wb: db.Pdb.NewBatch(), wo: db.wo} }

func (b *pebbleBatch) Set(key, value []byte) error { return b.wb.Set(key, value, b.wo) }
func (b *pebbleBatch) Delete(key []byte) error     { return b.wb.Delete(key, b.wo) }
func (b *pebbleBatch) Commit() error               { return b.wb.Commit(b.wo) }
func (b *pebbleBatch) Cancel()                     { b.wb.Close() }

type pebbleSnapshot struct {
	db   *PebbleDB
	snap *pebble.Snapshot
}

func (db *PebbleDB) NewSnapshot() Snapshot { return &pebbleSnapshot{snap: db.Pdb.NewSnapshot()} }

func (s *pebbleSnapshot) Get(key []byte) ([]byte, error) {
	val, closer, err := s.snap.Get(key)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	ret := make([]byte, len(val))
	copy(ret, key)
	return ret, nil
}
func (s *pebbleSnapshot) Close() { s.snap.Close() }

func (s *pebbleSnapshot) NewIterator(start, end []byte, reverse bool) Iterator {
	iter := s.snap.NewIter(&pebble.IterOptions{LowerBound: start, UpperBound: end})
	return s.db.newIterator(iter, reverse)
}

type pebbleIterator struct {
	iter    *pebble.Iterator
	reverse bool
}

// NewIterator scans a range: start and end are optional (set to nil/empty otherwise)
func (db *PebbleDB) NewIterator(start, end []byte, reverse bool) Iterator {
	iter := db.Pdb.NewIter(&pebble.IterOptions{LowerBound: start, UpperBound: end})
	return db.newIterator(iter, reverse)
}

func (db *PebbleDB) newIterator(iter *pebble.Iterator, reverse bool) Iterator {
	if reverse {
		iter.Last()
	} else {
		iter.First()
	}
	return &pebbleIterator{iter: iter, reverse: reverse}
}

func (i *pebbleIterator) Next() {
	if i.reverse {
		i.iter.Prev()
	} else {
		i.iter.Next()
	}
}
func (i *pebbleIterator) Valid() bool { return i.iter.Valid() }
func (i *pebbleIterator) Close()      { i.iter.Close() }

func (i *pebbleIterator) Key() []byte {
	k := i.iter.Key()
	ret := make([]byte, len(k))
	copy(ret, k)
	return ret
}

func (i *pebbleIterator) Value() ([]byte, error) {
	v := i.iter.Value()
	ret := make([]byte, len(v))
	copy(ret, v)
	return ret, nil
}

// XXX providing iter.Key() with guidance that Slice only valid until iter.Next()
func (i *pebbleIterator) KeySlice() Slice            { return pebbleSlice(i.iter.Key()) }
func (i *pebbleIterator) ValueSlice() (Slice, error) { return pebbleSlice(i.iter.Value()), nil }

type pebbleSlice []byte

func (s pebbleSlice) Data() []byte { return s }
func (s pebbleSlice) Free()        {}
func (s pebbleSlice) Size() int    { return len(s) }
func (s pebbleSlice) Exists() bool { return s != nil }
