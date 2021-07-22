package main

import (
	"github.com/algorand/go-algorand/tools/custom_linter/partitionAnalyzer"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(partitionAnalyzer.Analyzer)
}
