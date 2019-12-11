package main

import (
	"fmt"
	"os"

	"github.com/algorand/go-algorand/data/transactions/logic/assembler"
)

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}

func main() {
	fin := os.Stdin
	fout := os.Stdout

	ops := assembler.OpStream{}
	err := ops.Assemble(fin)
	checkErr(err)
	program, err := ops.Bytes()
	checkErr(err)
	_, err = fout.Write(program)
	checkErr(err)
}
