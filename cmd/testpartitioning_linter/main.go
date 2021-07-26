package main

import (
	"github.com/algorand/go-algorand/cmd/testpartitioning_linter/analyzer"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(analyzer.Analyzer)
}
