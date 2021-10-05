package kvstore

import (
	"errors"
)

// KVStore is a simple KV API
type KVStore interface {
	Get([]byte) ([]byte, error)
	Set([]byte, []byte) error
	Delete(key []byte) error

	MultiGet(keys [][]byte) ([][]byte, error)

	NewIterator(start, end []byte, reverse bool) Iterator
	NewSnapshot() Snapshot

	NewBatch() BatchWriter
	Close() error
}

// BatchWriter is a set of mutations
type BatchWriter interface {
	Set(key, value []byte) error
	Delete(key []byte) error

	Commit() error
	Cancel()
}

// Iterator scans a range of KVs
type Iterator interface {
	Next()
	Key() []byte
	KeySlice() Slice
	Value() ([]byte, error)
	ValueSlice() (Slice, error)
	Valid() bool
	Close()
}

// Snapshot provides a consistent reader that must be closed
type Snapshot interface {
	Get([]byte) ([]byte, error)
	NewIterator(start, end []byte, reverse bool) Iterator
	Close()
}

// Slice must be freed, and may be backed by *C.char (gorocksdb.Slice)
// XXX for some Iterator implementations, could be faster to specify Slice is only valid until iter.Next()
type Slice interface {
	Data() []byte
	Free()
	Size() int
	Exists() bool
}

type kvFactory interface {
	New(dbdir string, inMem bool) (KVStore, error)
}

var kvImpls = make(map[string]kvFactory)

var ErrImplNotFound = errors.New("KVStore implementation not found")

// NewKVStore returns a KVStore implementation matching the provided implementation name
func NewKVStore(impl string, dbdir string, inMem bool) (KVStore, error) {
	factory, ok := kvImpls[impl]
	if !ok {
		return nil, ErrImplNotFound
	}
	return factory.New(dbdir, inMem)
}
