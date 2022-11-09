package store

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

func TestKeyPrefixIntervalPreprocessing(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testCases := []struct {
		input            []byte
		outputPrefix     []byte
		outputPrefixIncr []byte
	}{
		{input: []byte{0xAB, 0xCD}, outputPrefix: []byte{0xAB, 0xCD}, outputPrefixIncr: []byte{0xAB, 0xCE}},
		{input: []byte{0xFF}, outputPrefix: []byte{0xFF}, outputPrefixIncr: nil},
		{input: []byte{0xFE, 0xFF}, outputPrefix: []byte{0xFE, 0xFF}, outputPrefixIncr: []byte{0xFF}},
		{input: []byte{0xFF, 0xFF}, outputPrefix: []byte{0xFF, 0xFF}, outputPrefixIncr: nil},
		{input: []byte{0xAB, 0xCD}, outputPrefix: []byte{0xAB, 0xCD}, outputPrefixIncr: []byte{0xAB, 0xCE}},
		{input: []byte{0x1E, 0xFF, 0xFF}, outputPrefix: []byte{0x1E, 0xFF, 0xFF}, outputPrefixIncr: []byte{0x1F}},
		{input: []byte{0xFF, 0xFE, 0xFF, 0xFF}, outputPrefix: []byte{0xFF, 0xFE, 0xFF, 0xFF}, outputPrefixIncr: []byte{0xFF, 0xFF}},
		{input: []byte{0x00, 0xFF}, outputPrefix: []byte{0x00, 0xFF}, outputPrefixIncr: []byte{0x01}},
		{input: []byte(string("bx:123")), outputPrefix: []byte(string("bx:123")), outputPrefixIncr: []byte(string("bx:124"))},
		{input: []byte{}, outputPrefix: []byte{}, outputPrefixIncr: nil},
		{input: nil, outputPrefix: []byte{}, outputPrefixIncr: nil},
		{input: []byte{0x1E, 0xFF, 0xFF}, outputPrefix: []byte{0x1E, 0xFF, 0xFF}, outputPrefixIncr: []byte{0x1F}},
		{input: []byte{0xFF, 0xFE, 0xFF, 0xFF}, outputPrefix: []byte{0xFF, 0xFE, 0xFF, 0xFF}, outputPrefixIncr: []byte{0xFF, 0xFF}},
		{input: []byte{0x00, 0xFF}, outputPrefix: []byte{0x00, 0xFF}, outputPrefixIncr: []byte{0x01}},
	}
	for _, tc := range testCases {
		actualOutputPrefix, actualOutputPrefixIncr := keyPrefixIntervalPreprocessing(tc.input)
		require.Equal(t, tc.outputPrefix, actualOutputPrefix)
		require.Equal(t, tc.outputPrefixIncr, actualOutputPrefixIncr)
	}
}
