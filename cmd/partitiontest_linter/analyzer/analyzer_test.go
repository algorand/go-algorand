package analyzer

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAll(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), Analyzer)
}
