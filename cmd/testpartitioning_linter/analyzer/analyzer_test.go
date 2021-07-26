package analyzer_test

import (
	"testing"

	"github.com/algorand/go-algorand/cmd/testpartitioning_linter/analyzer"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAll(t *testing.T) {
	// wd, err := os.Getwd()
	// if err != nil {
	// t.Fatalf("Failed to get wd: %s", err)
	// }

	// testdata := filepath.Join(filepath.Dir(filepath.Dir(wd)), "testpartitioning_linter/testdata")
	analysistest.Run(t, analysistest.TestData(), analyzer.Analyzer)
}
