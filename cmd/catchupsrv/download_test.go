package main

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBlockToPath(t *testing.T) {
	require.Equal(t, "00/00/000000", blockToPath(0))
	require.Equal(t, "00/00/0000rs", blockToPath(1000))
	require.Equal(t, "05/yc/05ycfo", blockToPath(10000500))
	require.Equal(t, "4ll/2c/4ll2cic", blockToPath(10012300500))
}

func TestBlockToFileName(t *testing.T) {
	require.Equal(t, "000000", blockToFileName(0))
	require.Equal(t, "0000rs", blockToFileName(1000))
	require.Equal(t, "05ycfo", blockToFileName(10000500))
	require.Equal(t, "4ll2cic", blockToFileName(10012300500))
}

func TestBlockToString(t *testing.T) {
	require.Equal(t, "0", blockToString(0))
	require.Equal(t, "rs", blockToString(1000))
	require.Equal(t, "5ycfo", blockToString(10000500))
	require.Equal(t, "4ll2cic", blockToString(10012300500))
}
