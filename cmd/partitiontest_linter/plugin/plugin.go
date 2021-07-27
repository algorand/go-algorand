package main

import (
	linter "github.com/algorand/go-algorand/cmd/partitiontest_linter"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/singlechecker"
)

type analyzerPlugin struct{}

// This must be implemented
func (*analyzerPlugin) GetAnalyzers() []*analysis.Analyzer {
	return []*analysis.Analyzer{
		linter.Analyzer,
	}
}

// This must be defined and named 'AnalyzerPlugin'
var AnalyzerPlugin analyzerPlugin

func main() {
	singlechecker.Main(linter.Analyzer)
}
