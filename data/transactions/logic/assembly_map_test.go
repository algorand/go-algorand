package logic

import (
	"strings"
	"testing"

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

var tmplPrograms = map[string]string{
	"Plain": `#pragma version 5
pushint TMPL_TEST_INT
pushbytes TMPL_TEST_BYTES
len
pop
return`,
	"bytec": `#pragma version 5
bytecblock 0xdeadbeef TMPL_TEST_BYTES 0xdeadbeef
bytec_1
len
return`,
	//TODO: make a struct instead with known tmpl positions?
}

func TestAssembleMapPCToLine(t *testing.T) {
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

func TestAssembleMapTemplate(t *testing.T) {
	// Teal program(s) with template variables (TODO: add known positions of tmpl vars?)
	for _, program := range tmplPrograms {
		// call assemble
		ops, err := AssembleString(program)
		require.NoError(t, err)
		require.Empty(t, ops.Warnings)

		// Check that the number of entries in linemap matches lines in program
		am := ops.GetAssemblyMap()
		require.Equal(t, len(am.TemplateLabels), strings.Count(program, "TMPL_"))
	}
}

func TestAssembleMapTemplatePopulate(t *testing.T) {
	// Teal program(s) with template variables

	// TODO: where should we put the logic to populate the program given the assembly map output?
}
