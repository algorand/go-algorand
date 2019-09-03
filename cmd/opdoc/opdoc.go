package main

import (
	"fmt"
	"io"
	"os"
	"strings"

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
	{"+", "A plus B. Panic on overflow."},
	{"-", "A minus B. Panic if B > A."},
	{"/", "A divided by B. Panic if B == 0."},
	{"*", "A times B. Panic on overflow."},
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
	{"%", "A modulo B. Panic if B == 0."},
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

func checkOpDocs() {
	opsSeen := make(map[string]bool)
	for _, op := range logic.OpSpecs {
		opsSeen[op.Name] = false
	}
	for _, od := range opDocList {
		_, exists := opsSeen[od.a]
		if !exists {
			fmt.Fprintf(os.Stderr, "error: doc for op %#v that does not exist in logic.OpSpecs", od.a)
		}
		opsSeen[od.a] = true
	}
	for op, seen := range opsSeen {
		if !seen {
			fmt.Fprintf(os.Stderr, "error: doc for op %#v missing", op)
		}
	}
}

var opcodeExtraList = []stringString{
	{"intcblock", "{varuint length} [{varuint value}, ...]"},
	{"intc", "{uint8 int constant index}"},
	{"bytecblock", "{varuint length} [({varuint value length} bytes), ...]"},
	{"bytec", "{uint8 byte constant index}"},
	{"arg", "{uint8 arg index N}"},
	{"txn", "{uint8 transaction field index}"},
	{"global", "{uint8 global field index}"},
	{"bnz", "{0..0x7fff forward branch offset, big endian}"},
}
var opcodeExtras map[string]string

var opDocExtraList = []stringString{
	{"bnz", "for a bnz instruction at `pc`, if the last element of the stack is not zero then branch to instruction at `pc + 3 + N`, else proceed to next instruction at `pc + 3`"},
	{"intcblock", "`intcblock` loads following program bytes into an array of integer constants in the evaluator. These integer constants can be referred to by `intc` and `intc_*` which will push the value onto the stack."},
	{"bytecblock", "`bytecblock` loads the following program bytes into an array of byte string constants in the evaluator. These constants can be referred to by `bytec` and `bytec_*` which will push the value onto the stack."},
	{"*", "It is worth noting that there are 10,000,000,000,000,000 micro-Algos in the total supply, or a bit less than 2^54. When doing rational math, e.g. (A * (N/D)) as ((A * N) / D) one should limit the numerator to less than 2^10 to be completely sure there won't be overflow."},
}

var opDocExtras map[string]string

type opGroup struct {
	groupName string
	ops       []string
}

func (og *opGroup) markdownTable(out io.Writer) {
	fmt.Fprint(out, `| Op | Description |
| --- | --- |
`)
	// TODO: sort by logic.OpSpecs[].Opcode
	for _, opname := range og.ops {
		fmt.Fprintf(out, "| `%s` | %s |\n", markdownTableEscape(opname), markdownTableEscape(opDocs[opname]))
	}
}

func markdownTableEscape(x string) string {
	return strings.ReplaceAll(x, "|", "\\|")
}

var opGroupList = []opGroup{
	{"Arithmetic", []string{"sha256", "keccak256", "sha512_256", "+", "-", "/", "*", "<", ">", "<=", ">=", "&&", "||", "==", "!=", "!", "len", "btoi", "%", "|", "&", "^", "~"}},
	{"Loading Values", []string{"intcblock", "intc", "intc_0", "intc_1", "intc_2", "intc_3", "bytecblock", "bytec", "bytec_0", "bytec_1", "bytec_2", "bytec_3", "arg", "arg_0", "arg_1", "arg_2", "arg_3", "txn", "global"}},
	{"Flow Control", []string{"err", "bnz", "pop", "dup"}},
}

func checkGroupCoverage() {
	opsSeen := make(map[string]bool)
	for _, op := range logic.OpSpecs {
		opsSeen[op.Name] = false
	}
	for _, og := range opGroupList {
		for _, name := range og.ops {
			_, exists := opsSeen[name]
			if !exists {
				fmt.Fprintf(os.Stderr, "error: op %#v in group list but not in logic.OpSpecs\n", name)
				continue
			}
			opsSeen[name] = true
		}
	}
	for name, seen := range opsSeen {
		if !seen {
			fmt.Fprintf(os.Stderr, "warning: op %#v not in any group list\n", name)
		}
	}
}

func init() {
	opDocs = stringStringListToMap(opDocList)
	opcodeExtras = stringStringListToMap(opcodeExtraList)
	opDocExtras = stringStringListToMap(opDocExtraList)
}

func fieldTableMarkdown(out io.Writer, names []string, types []logic.StackType) {
	fmt.Fprintf(out, "| Index | Name | Type |\n")
	fmt.Fprintf(out, "| --- | --- | --- |\n")
	for i, name := range names {
		gfType := types[i]
		fmt.Fprintf(out, "| %d | %s | %s |\n", i, markdownTableEscape(name), markdownTableEscape(gfType.String()))
	}
	out.Write([]byte("\n"))
}

func transactionFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`txn` Fields:\n\n")
	fieldTableMarkdown(out, logic.TxnFieldNames, logic.TxnFieldTypes)
}

func globalFieldsMarkdown(out io.Writer) {
	fmt.Fprintf(out, "\n`global` Fields:\n\n")
	fieldTableMarkdown(out, logic.GlobalFieldNames, logic.GlobalFieldTypes)
}

func opToMarkdown(out io.Writer, op *logic.OpSpec) (err error) {

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
	out.Write([]byte("# Opcodes\n\n"))
	for i := range logic.OpSpecs {
		err = opToMarkdown(out, &logic.OpSpecs[i])
		if err != nil {
			return
		}
	}
	return
}
func main() {
	checkOpDocs()
	checkGroupCoverage()
	opcodesMd, _ := os.Create("opcodes.md")
	opsToMarkdown(opcodesMd)
	opcodesMd.Close()
	for _, og := range opGroupList {
		fname := fmt.Sprintf("%s.md", og.groupName)
		fname = strings.ReplaceAll(fname, " ", "_")
		fout, _ := os.Create(fname)
		og.markdownTable(fout)
		fout.Close()
	}
	txnfields, _ := os.Create("txn_fields.md")
	fieldTableMarkdown(txnfields, logic.TxnFieldNames, logic.TxnFieldTypes)
	txnfields.Close()

	globalfields, _ := os.Create("global_fields.md")
	fieldTableMarkdown(globalfields, logic.GlobalFieldNames, logic.GlobalFieldTypes)
	globalfields.Close()
}
