package main

import (
	"fmt"
	"io"
	"os"

	"github.com/algorand/go-algorand/data/transactions/logic"
)

type stringString struct {
	a string
	b string
}

func stringStringListToMap(they []stringString) map[string]string {
	out := make(map[string]string)
	for _, v := range they {
		out[v.a] = v.b
	}
	return out
}

var opDocList = []stringString{
	{"err", "Error. Panic immediately. This is primarily a fencepost against accidental zero bytes getting compiled into programs."},
	{"sha256", "SHA256 hash of value, yields [32]byte"},
	{"keccak256", "Keccac256 hash of value, yields [32]byte"},
	{"sha512_256", "SHA512_256 hash of value, yields [32]byte"},
	{"+", "A plus B"},
	{"-", "A minus B"},
	{"/", "A divided by B"},
	{"*", "A times B"},
	{"<", "A less than B => {0 or 1}"},
	{">", "A greater than B => {0 or 1}"},
	{"<=", "A less than or equal to B => {0 or 1}"},
	{">=", "A greater than or equal to B => {0 or 1}"},
	{"&&", "A is not zero and B is not zero => {0 or 1}"},
	{"||", "A is not zero or B is not zero => {0 or 1}"},
	{"==", "A is equal to B => {0 or 1}"},
	{"!=", "A is not equal to B => {0 or 1}"},
	{"!", "X == 0 yields 1; else 0"},
	{"len", "yields length of byte value"},
	{"btoi", "converts bytes as big endian to uint64"},
	{"%", "A modulo B"},
	{"|", "A bitwise-or B"},
	{"&", "A bitwise-and B"},
	{"^", "A bitwise-xor B"},
	{"~", "bitwise invert value"},
	{"intcblock", "load block of uint64 constants"},
	{"intc", "push value from uint64 constants to stack by index into constants"},
	{"intc_0", "push uint64 constant 0 to stack"},
	{"intc_1", "push uint64 constant 1 to stack"},
	{"intc_2", "push uint64 constant 2 to stack"},
	{"intc_3", "push uint64 constant 3 to stack"},
	{"bytecblock", "load block of byte-array constants"},
	{"bytec", "push bytes constant to stack by index into constants"},
	{"bytec_0", "push bytes constant 0 to stack"},
	{"bytec_1", "push bytes constant 1 to stack"},
	{"bytec_2", "push bytes constant 2 to stack"},
	{"bytec_3", "push bytes constant 3 to stack"},
	{"arg", "push LogicSig.Args[N] value to stack by index"},
	{"arg_0", "push LogicSig.Args[0] to stack"},
	{"arg_1", "push LogicSig.Args[1] to stack"},
	{"arg_2", "push LogicSig.Args[2] to stack"},
	{"arg_3", "push LogicSig.Args[3] to stack"},
	{"txn", "push field from current transaction to stack"},
	{"global", "push value from globals to stack"},
	{"bnz", "branch if value is not zero"},
	{"pop", "discard value from stack"},
	{"dup", "duplicate last value on stack"},
}

var opDocs map[string]string

var opcodeExtraList = []stringString{
	{"intcblock", "{varuint length} [{varuint value}, ...]"},
	{"intc", "{uint8 int constant index}"},
	{"bytecblock", "{varuint length} [({varuint value length} bytes), ...]"},
	{"bytec", "{uint8 byte constant index}"},
	{"arg", "{uint8 arg index N}"},
	{"txn", "{uint8 transaction field index}"},
	{"global", "{uint8 global field index}"},
	{"bnz", "{0..127 forward branch offset}"},
}
var opcodeExtras map[string]string

var opDocExtraList = []stringString{
	{"bnz", "for a bnz instruction at `pc`, if the last element of the stack is not zero then branch to instruction at `pc + 2 + N`, else procede to next instruction at `pc + 2`"},
	{"intcblock", "`intcblock` loads following program bytes into an array of integer constants in the evaluator. These integer constants can be referred to by `intc` and `intc_*` which will push the value onto the stack."},
	{"bytecblock", "`bytecblock` loads the following program bytes into an array of byte string constants in the evaluator. These constants can be referred to by `bytec` and `bytec_*` which will push the value onto the stack."},
}

var opDocExtras map[string]string

func init() {
	opDocs = stringStringListToMap(opDocList)
	opcodeExtras = stringStringListToMap(opcodeExtraList)
	opDocExtras = stringStringListToMap(opDocExtraList)
}

func transactionFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`txn` Fields:\n\n| Index | Name | Type |\n")
	fmt.Fprintf(out, "| --- | --- | --- |\n")
	for i, name := range logic.TxnFieldNames {
		gfType := logic.TxnFieldTypes[i]
		fmt.Fprintf(out, "| %d | %s | %s |\n", i, name, gfType.String())
	}
	out.Write([]byte("\n"))
}

func globalFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`global` Fields:\n\n| Index | Name | Type |\n")
	fmt.Fprintf(out, "| --- | --- | --- |\n")
	for i, name := range logic.GlobalFieldNames {
		gfType := logic.GlobalFieldTypes[i]
		fmt.Fprintf(out, "| %d | %s | %s |\n", i, name, gfType.String())
	}
	out.Write([]byte("\n"))
}

func opToMarkdown(out io.Writer, op *logic.OpSpec) (err error) {
	//fmt.Fprintf(out, "{%#v, %#v},\n", op.name, op.doc)

	opextra := opcodeExtras[op.Name]
	fmt.Fprintf(out, "\n## %s\n- Opcode: 0x%02x %s\n", op.Name, op.Opcode, opextra)
	if op.Args == nil {
		fmt.Fprintf(out, "- Pops: None\n")
	} else if len(op.Args) == 1 {
		fmt.Fprintf(out, "- Pops: *... stack*, %s\n", op.Args[0].String())
	} else if len(op.Args) == 2 {
		fmt.Fprintf(out, "- Pops: *... stack*, {%s A}, {%s B}\n", op.Args[0].String(), op.Args[1].String())
	} else {
		fmt.Fprintf(out, "- Pops: *... stack*, {%s A}", op.Args[0].String())
		for i, v := range op.Args[1:] {
			fmt.Fprintf(out, ", {%s %c}", v.String(), rune(int('B')+i))
		}
		out.Write([]byte("\n"))
	}
	fmt.Fprintf(out, "- Pushes: %s\n", op.Returns.String())
	fmt.Fprintf(out, "- %s\n", opDocs[op.Name])
	ode, hasOde := opDocExtras[op.Name]
	if hasOde {
		fmt.Fprintf(out, "\n%s\n", ode)
	}
	if op.Name == "global" {
		globalFieldsMarkdown(out)
	} else if op.Name == "txn" {
		transactionFieldsMarkdown(out)
	}
	return nil
}

func opsToMarkdown(out io.Writer) (err error) {
	for i := range logic.OpSpecs {
		err = opToMarkdown(out, &logic.OpSpecs[i])
		if err != nil {
			return
		}
	}
	return
}
func main() {
	opsToMarkdown(os.Stdout)
}
