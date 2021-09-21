package kvstore

import "fmt"

// KVStore is a simple KV API
type KVStore interface {
	Get([]byte) ([]byte, error)
	Set([]byte, []byte) error

	NewIterator(start, end []byte) Iterator

	NewBatch() BatchWriter
	Close() error
}

// BatchWriter is a set of mutations
type BatchWriter interface {
	Set(key, value []byte) error

	Commit() error
	Cancel()
}

// Iterator scans a range of KVs
type Iterator interface {
	Next()
	Key() []byte
	Value() ([]byte, error)
	Valid() bool
	Close()
}

type kvFactory interface {
	New(dbdir string, inMem bool) (KVStore, error)
}

var kvImpls = make(map[string]kvFactory)

// NewKVStore returns a KVStore implementation matching the provided implementation name
func NewKVStore(impl string, dbdir string, inMem bool) (KVStore, error) {
	factory, ok := kvImpls[impl]
	if !ok {
		return nil, fmt.Errorf("KVStore impl %s not found", impl)
	}
	return factory.New(dbdir, inMem)
}
