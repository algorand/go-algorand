package msgp

import (
	"math"
	"math/rand"
)

var (
	tint8   int8   = 126                  // cannot be most fix* types
	tint16  int16  = 150                  // cannot be int8
	tint32  int32  = math.MaxInt16 + 100  // cannot be int16
	tint64  int64  = math.MaxInt32 + 100  // cannot be int32
	tuint16 uint32 = 300                  // cannot be uint8
	tuint32 uint32 = math.MaxUint16 + 100 // cannot be uint16
	tuint64 uint64 = math.MaxUint32 + 100 // cannot be uint32
)

func RandBytes(sz int) []byte {
	out := make([]byte, sz)
	for i := range out {
		out[i] = byte(rand.Int63n(math.MaxInt64) % 256)
	}
	return out
}
