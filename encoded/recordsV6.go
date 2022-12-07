package encoded

import (
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/msgp/msgp"
)

// Adjust these to be big enough for boxes, but not directly tied to box values.
const (
	// For boxes: "bx:<8 bytes><64 byte name>"
	KVRecordV6MaxKeyLength = 128

	// For boxes: MaxBoxSize
	KVRecordV6MaxValueLength = 32768

	// MaxEncodedKVDataSize is the max size of serialized KV entry, checked with TestEncodedKVDataSize.
	// Exact value is 32906 that is 10 bytes more than 32768 + 128
	MaxEncodedKVDataSize = 33000

	// resourcesPerCatchpointFileChunkBackwardCompatible is the old value for ResourcesPerCatchpointFileChunk.
	// Size of a single resource entry was underestimated to 300 bytes that holds only for assets and not for apps.
	// It is safe to remove after April, 2023 since we are only supporting catchpoint that are 6 months old.
	resourcesPerCatchpointFileChunkBackwardCompatible = 300_000
)

// SortUint64 re-export this sort, which is implemented in basics, and being used by the msgp when
// encoding the resources map below.
type SortUint64 = basics.SortUint64

// BalanceRecordV6 is the encoded account balance record.
type BalanceRecordV6 struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Address     basics.Address      `codec:"a,allocbound=crypto.DigestSize"`
	AccountData msgp.Raw            `codec:"b"`                                                              // encoding of baseAccountData
	Resources   map[uint64]msgp.Raw `codec:"c,allocbound=resourcesPerCatchpointFileChunkBackwardCompatible"` // map of resourcesData

	// flag indicating whether there are more records for the same account coming up
	ExpectingMoreEntries bool `codec:"e"`
}

// KVRecordV6 is the encoded KV record.
type KVRecordV6 struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	Key   []byte `codec:"k,allocbound=KVRecordV6MaxKeyLength"`
	Value []byte `codec:"v,allocbound=KVRecordV6MaxValueLength"`
}
