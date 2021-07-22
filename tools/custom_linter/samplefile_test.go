package main

import (
	"fmt"
	"testing"
)

func TestFunctionOne(t *testing.T) {

}

func TestFunctionTwo(t *testing.T) {
	// testpartitioning.PartitionTest(t)
	fmt.Println(t)
	// haha
}

func TestFunctionThree(t *testing.T) {
	fmt.Println("hahaha")
}

func TestFunctionFour(t *testing.T) {
	// check second line in function
	// testpartitioning.PartitionTest(t)
}

// different function name with testing
func TiestFunctionFive(t *testing.T) {
	// testpartitioning.PartitionTest(t)
}

// different function name without testing
func TiestFunctionSix(t *testing.T) {

}

func TestFunctionSeven(t *testing.T) {

}
