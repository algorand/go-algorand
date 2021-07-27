package analyzer_testdata

import (
	"testing"

	"../../../../test/partitiontest"
)

func notTestFunction() {}

func notTestFunctionWithWrongParam(t string) {}

func notTestFunctionWithCorrectParam(t *testing.T) {}

func notTestFunctionWithCorrectParamCorrectLine(t *testing.T) {
	partitiontest.PartitionTest(t)
}

func notTestFunctionWithCorrectParamWrongLine(t *testing.T) {
	println("something")
}

func TestFunctionWithCorrectParamOnly(t *testing.T) {} // want "function is missing partitiontest.PartitionTest"

func TestFunctionWithCorrectParamCorrectLine(t *testing.T) {
	partitiontest.PartitionTest(t)
}

func TestFunctionWithCorrectParamBadLine(t *testing.T) { // want "function is missing partitiontest.PartitionTest"
	println("something")
}

func TestFunctionWithDifferentName(n *testing.T) {
	partitiontest.PartitionTest(n)
}

func TestFunctionWithCorrectParamNotFirstCorrectLine(t *testing.T) {
	println("something")
	partitiontest.PartitionTest(t)
}

func TestFunctionWithCorrectParamNotLastCorrectLine(t *testing.T) {
	partitiontest.PartitionTest(t)
	println("something")
}

func TestFunctionWithCorrectParamMiddleCorrectLine(t *testing.T) {
	println("something")
	partitiontest.PartitionTest(t)
	println("something")
}
