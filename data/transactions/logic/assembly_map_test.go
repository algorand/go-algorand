package logic

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

var pcPrograms = map[string]string{
	"Plain": `#pragma version 5
pushint 1
pushbytes 0xdeadbeef
len
pop
return`,
	"Empty Lines": `#pragma version 5
pushint 1


pushbytes 0xdeadbeef
len
pop
return`,
	// TODO: What else?
}

func TestAssembleMapPcToLine(t *testing.T) {
	partitiontest.PartitionTest(t)

	// Iterate over Teal program(s)  (TODO: add known pc mapping?)
	for _, program := range pcPrograms {
		// call assemble
		ops, err := AssembleString(program)
		require.NoError(t, err)
		require.Empty(t, ops.Warnings)

		// Check that the number of entries in linemap matches lines in program
		am := ops.GetAssemblyMap()
		require.Equal(t, len(am.LineMap), len(strings.Split(program, "\n")))
	}
}
