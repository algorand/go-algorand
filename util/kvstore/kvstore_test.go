package kvstore

import (
	"encoding/binary"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bigEndianUint64(v uint64) []byte {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, v)
	return ret
}

func prefixUint64Byte(prefix []byte, normBalance uint64, address []byte) []byte {
	ret := prefix[:]
	ret = append(ret, bigEndianUint64(normBalance)...)
	ret = append(ret, address...)
	return ret
}

func splitPrefixUint64Byte(t *testing.T, key []byte) ([]byte, uint64, []byte) {
	require.True(t, len(key) > 12)
	return key[0:4], binary.BigEndian.Uint64(key[4:12]), key[12:]
}

func TestAllIterator(t *testing.T) { testAll(t, testIterator) }

func testIterator(t *testing.T, kv KVStore) {
	prefix := []byte("\x00\x00\x00\x03")
	endRange := []byte("\x00\x00\x00\x04")
	kv.Set(prefixUint64Byte(prefix, 0, []byte("AA")), []byte{})
	kv.Set(prefixUint64Byte(prefix, 100, []byte("FF")), []byte{})
	kv.Set(prefixUint64Byte(prefix, 1, []byte("BB")), []byte{})
	kv.Set(prefixUint64Byte(prefix, 0xFFFFFFFFFFFFFFFF, []byte("GG")), []byte{})
	kv.Set(prefixUint64Byte(prefix, 2, []byte("CC")), []byte{})
	kv.Set(endRange, []byte("end"))
	kv.Set(prefixUint64Byte(prefix, 10, []byte("EE")), []byte{})
	kv.Set(prefixUint64Byte(prefix, 3, []byte("DD")), []byte{})

	type keyItem struct {
		num  uint64
		addr string
	}
	prefix1 := prefixUint64Byte(prefix, 1, []byte{})
	for _, tc := range []struct {
		start, end []byte
		reverse    bool
		order      []keyItem
	}{
		{prefix, endRange, false, []keyItem{{0, "AA"}, {1, "BB"}, {2, "CC"}, {3, "DD"}, {10, "EE"}, {100, "FF"}, {18446744073709551615, "GG"}}},
		{prefix, endRange, true, []keyItem{{18446744073709551615, "GG"}, {100, "FF"}, {10, "EE"}, {3, "DD"}, {2, "CC"}, {1, "BB"}, {0, "AA"}}},
		{prefix1, endRange, false, []keyItem{{1, "BB"}, {2, "CC"}, {3, "DD"}, {10, "EE"}, {100, "FF"}, {18446744073709551615, "GG"}}},
		{prefix1, endRange, true, []keyItem{{18446744073709551615, "GG"}, {100, "FF"}, {10, "EE"}, {3, "DD"}, {2, "CC"}, {1, "BB"}}},
	} {
		keyList := []keyItem{}
		for iter := kv.NewIterator(tc.start, tc.end, tc.reverse); iter.Valid(); iter.Next() {
			p, val, addr := splitPrefixUint64Byte(t, iter.Key())
			assert.Equal(t, prefix, p)
			t.Logf("key iter.Key() val %v addr %v", val, addr)
			keyList = append(keyList, keyItem{val, string(addr)})
		}
		assert.Equal(t, tc.order, keyList)
	}
}

func testAll(t *testing.T, testFn func(*testing.T, KVStore)) {
	for _, impl := range []string{"leveldb", "rocksdb", "pebble", "badger"} {
		t.Run(impl, func(t *testing.T) {
			dir, err := ioutil.TempDir("", impl+"-test")
			require.NoError(t, err)
			kv, err := NewKVStore(impl, dir, false)
			if err == ErrImplNotFound {
				t.Skip("no impl found")
			}
			defer kv.Close()
			require.NoError(t, err)
			testFn(t, kv)
		})
	}
}
