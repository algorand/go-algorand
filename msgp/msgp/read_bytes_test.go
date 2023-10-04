package msgp

import (
	"testing"
	"time"
)

func BenchmarkReadMapHeaderBytes(b *testing.B) {
	sizes := []uint32{1, 100, tuint16, tuint32}
	buf := make([]byte, 0, 5*len(sizes))
	for _, sz := range sizes {
		buf = AppendMapHeader(buf, sz)
	}
	b.SetBytes(int64(len(buf) / len(sizes)))
	b.ReportAllocs()
	b.ResetTimer()
	o := buf
	for i := 0; i < b.N; i++ {
		_, _, buf, _ = ReadMapHeaderBytes(buf)
		if len(buf) == 0 {
			buf = o
		}
	}
}

func BenchmarkReadArrayHeaderBytes(b *testing.B) {
	sizes := []uint32{1, 100, tuint16, tuint32}
	buf := make([]byte, 0, 5*len(sizes))
	for _, sz := range sizes {
		buf = AppendArrayHeader(buf, sz)
	}
	b.SetBytes(int64(len(buf) / len(sizes)))
	b.ReportAllocs()
	b.ResetTimer()
	o := buf
	for i := 0; i < b.N; i++ {
		_, _, buf, _ = ReadArrayHeaderBytes(buf)
		if len(buf) == 0 {
			buf = o
		}
	}
}

func BenchmarkReadNilByte(b *testing.B) {
	buf := []byte{mnil}
	b.SetBytes(1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ReadNilBytes(buf)
	}
}

func BenchmarkReadFloat64Bytes(b *testing.B) {
	f := float64(3.14159)
	buf := make([]byte, 0, 9)
	buf = AppendFloat64(buf, f)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ReadFloat64Bytes(buf)
	}
}

func BenchmarkReadFloat32Bytes(b *testing.B) {
	f := float32(3.14159)
	buf := make([]byte, 0, 5)
	buf = AppendFloat32(buf, f)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ReadFloat32Bytes(buf)
	}
}

func BenchmarkReadBoolBytes(b *testing.B) {
	buf := []byte{mtrue, mfalse, mtrue, mfalse}
	b.SetBytes(1)
	b.ReportAllocs()
	b.ResetTimer()
	o := buf
	for i := 0; i < b.N; i++ {
		_, buf, _ = ReadBoolBytes(buf)
		if len(buf) == 0 {
			buf = o
		}
	}
}

func BenchmarkReadTimeBytes(b *testing.B) {
	data := AppendTime(nil, time.Now())
	b.SetBytes(15)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ReadTimeBytes(data)
	}
}
