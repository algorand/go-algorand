package msgp

import (
	"testing"
	"time"
)

func BenchmarkAppendMapHeader(b *testing.B) {
	buf := make([]byte, 0, 9)
	N := b.N / 4
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < N; i++ {
		AppendMapHeader(buf[:0], 0)
		AppendMapHeader(buf[:0], uint32(tint8))
		AppendMapHeader(buf[:0], tuint16)
		AppendMapHeader(buf[:0], tuint32)
	}
}

func BenchmarkAppendArrayHeader(b *testing.B) {
	buf := make([]byte, 0, 9)
	N := b.N / 4
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < N; i++ {
		AppendArrayHeader(buf[:0], 0)
		AppendArrayHeader(buf[:0], uint32(tint8))
		AppendArrayHeader(buf[:0], tuint16)
		AppendArrayHeader(buf[:0], tuint32)
	}
}

func TestAppendNil(t *testing.T) {
	var bts []byte
	bts = AppendNil(bts[0:0])
	if bts[0] != mnil {
		t.Fatal("bts[0] is not 'nil'")
	}
}

func BenchmarkAppendFloat64(b *testing.B) {
	f := float64(3.14159)
	buf := make([]byte, 0, 9)
	b.SetBytes(9)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AppendFloat64(buf[0:0], f)
	}
}

func BenchmarkAppendFloat32(b *testing.B) {
	f := float32(3.14159)
	buf := make([]byte, 0, 5)
	b.SetBytes(5)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AppendFloat32(buf[0:0], f)
	}
}

func BenchmarkAppendInt64(b *testing.B) {
	is := []int64{0, 1, -5, -50, int64(tint16), int64(tint32), int64(tint64)}
	l := len(is)
	buf := make([]byte, 0, 9)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AppendInt64(buf[0:0], is[i%l])
	}
}

func BenchmarkAppendUint64(b *testing.B) {
	us := []uint64{0, 1, 15, uint64(tuint16), uint64(tuint32), tuint64}
	buf := make([]byte, 0, 9)
	b.ReportAllocs()
	b.ResetTimer()
	l := len(us)
	for i := 0; i < b.N; i++ {
		AppendUint64(buf[0:0], us[i%l])
	}
}

func benchappendBytes(size uint32, b *testing.B) {
	bts := RandBytes(int(size))
	buf := make([]byte, 0, len(bts)+5)
	b.SetBytes(int64(len(bts) + 5))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AppendBytes(buf[0:0], bts)
	}
}

func BenchmarkAppend16Bytes(b *testing.B) { benchappendBytes(16, b) }

func BenchmarkAppend256Bytes(b *testing.B) { benchappendBytes(256, b) }

func BenchmarkAppend2048Bytes(b *testing.B) { benchappendBytes(2048, b) }

func benchappendString(size uint32, b *testing.B) {
	str := string(RandBytes(int(size)))
	buf := make([]byte, 0, len(str)+5)
	b.SetBytes(int64(len(str) + 5))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AppendString(buf[0:0], str)
	}
}

func BenchmarkAppend16String(b *testing.B) { benchappendString(16, b) }

func BenchmarkAppend256String(b *testing.B) { benchappendString(256, b) }

func BenchmarkAppend2048String(b *testing.B) { benchappendString(2048, b) }

func BenchmarkAppendBool(b *testing.B) {
	vs := []bool{true, false}
	buf := make([]byte, 0, 1)
	b.SetBytes(1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AppendBool(buf[0:0], vs[i%2])
	}
}

func BenchmarkAppendTime(b *testing.B) {
	t := time.Now()
	b.SetBytes(15)
	buf := make([]byte, 0, 15)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AppendTime(buf[0:0], t)
	}
}
