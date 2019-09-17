// Copyright (C) 2019 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/algorand/go-algorand/data/transactions/logic"
)

func opGroupMarkdownTable(og *logic.OpGroup, out io.Writer) {
	fmt.Fprint(out, `| Op | Description |
| --- | --- |
`)
	// TODO: sort by logic.OpSpecs[].Opcode
	for _, opname := range og.Ops {
		fmt.Fprintf(out, "| `%s` | %s |\n", markdownTableEscape(opname), markdownTableEscape(logic.OpDoc(opname)))
	}
}

func markdownTableEscape(x string) string {
	return strings.ReplaceAll(x, "|", "\\|")
}

func init() {
	//opDocByName = stringStringListToMap(opDocList)
	//opcodeImmediateNotes = stringStringListToMap(opcodeImmediateNoteList)
	//opDocExtras = stringStringListToMap(opDocExtraList)
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

	opextra := logic.OpImmediateNote(op.Name)
	cost := logic.OpCost(op.Name)
	fmt.Fprintf(out, "\n## %s\n\n- Opcode: 0x%02x %s\n", op.Name, op.Opcode, opextra)
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
	fmt.Fprintf(out, "- %s\n", logic.OpDoc(op.Name))
	if cost != 1 {
		fmt.Fprintf(out, "- **Cost**: %d\n", cost)
	}
	ode := logic.OpDocExtra(op.Name)
	if ode != "" {
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
	out.Write([]byte("# Opcodes\n\nOps have a 'cost' of 1 unless otherwise specified.\n\n"))
	for i := range logic.OpSpecs {
		err = opToMarkdown(out, &logic.OpSpecs[i])
		if err != nil {
			return
		}
	}
	return
}
func main() {
	opcodesMd, _ := os.Create("TEAL_opcodes.md")
	opsToMarkdown(opcodesMd)
	opcodesMd.Close()
	for _, og := range logic.OpGroupList {
		fname := fmt.Sprintf("%s.md", og.GroupName)
		fname = strings.ReplaceAll(fname, " ", "_")
		fout, _ := os.Create(fname)
		opGroupMarkdownTable(&og, fout)
		fout.Close()
	}
	txnfields, _ := os.Create("txn_fields.md")
	fieldTableMarkdown(txnfields, logic.TxnFieldNames, logic.TxnFieldTypes)
	txnfields.Close()

	globalfields, _ := os.Create("global_fields.md")
	fieldTableMarkdown(globalfields, logic.GlobalFieldNames, logic.GlobalFieldTypes)
	globalfields.Close()
}
