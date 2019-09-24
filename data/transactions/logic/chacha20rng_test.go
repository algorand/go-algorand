package logic

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const benchSeed = "abcdefghijklmnopqrstuvwxyz012345"
const benchMore = "ABCDEFGH"

func BenchmarkChaCha20Rng(b *testing.B) {
	rng, err := NewChaCha20RNG([]byte(benchSeed), []byte(benchMore))
	require.NoError(b, err)
	b.ResetTimer()
	v := uint64(0)
	for i := 0; i < b.N; i++ {
		v += rng.Uint64()
	}
	b.StopTimer()
	b.Log(v)
}
