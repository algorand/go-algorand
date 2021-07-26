package analyzer_test

import (
	"testing"

	"github.com/algorand/go-algorand/cmd/partitiontest_linter/analyzer"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAll(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), analyzer.Analyzer)
}
