package analyzer_testdata

import (
	"testing"

	"github.com/algorand/go-algorand/testpartitioning"
)

func notTestFunction() {}

func notTestFunctionWithWrongParam(t string) {}

func notTestFunctionWithCorrectParam(t *testing.T) {}

func notTestFunctionWithCorrectParamCorrectLine(t *testing.T) {
	testpartitioning.PartitionTest(t)
}

func notTestFunctionWithCorrectParamWrongLine(t *testing.T) {
	println("something")
}

// func TestFunctionWithoutAnything() {}

// func TestFunctionWithWrongParam(t string) {}

func TestFunctionWithCorrectParamOnly(t *testing.T) {} // want "function is missing testpartitioning.PartitionTest"

func TestFunctionWithCorrectParamCorrectLine(t *testing.T) { // want "function is missing testpartitioning.PartitionTest"
	// 	testpartitioning.PartitionTest(t)
}

func TestFunctionWithCorrectParamBadLine(t *testing.T) { // want "function is missing testpartitioning.PartitionTest"
	println("something")
}

func TestFunctionWithDifferentName(n *testing.T) { // want "function is missing testpartitioning.PartitionTest"
	// 	testpartitioning.PartitionTest(n)
}

// func TestFunctionWithMultipleParams(t *testing.T, whatevs string) {}

// func TestFunctionWithMultipleParamsCorrectLine(t *testing.T, whatevs string) {
// 	testpartitioning.PartitionTest(t)
// }

// func TestFunctionWithMultipleParamsCorrectLineDifferentOrder(whatevs string, t *testing.T) {
// 	testpartitioning.PartitionTest(t)
// }

func TestFunctionWithCorrectParamNotFirstCorrectLine(t *testing.T) { // want "function is missing testpartitioning.PartitionTest"
	println("something")
	// 	testpartitioning.PartitionTest(t)
}

func TestFunctionWithCorrectParamNotLastCorrectLine(t *testing.T) { // want "function is missing testpartitioning.PartitionTest"
	// 	testpartitioning.PartitionTest(t)
	println("something")
}

func TestFunctionWithCorrectParamMiddleCorrectLine(t *testing.T) { // want "function is missing testpartitioning.PartitionTest"
	println("something")
	// 	testpartitioning.PartitionTest(t)
	println("something")
}
