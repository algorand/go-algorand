package printer

import (
	"bytes"
	"testing"
)

func TestWriteBuildHeader(t *testing.T) {
	testBuf := bytes.NewBuffer(make([]byte, 0, 4096))
	buildHeaders := []string{"foobar"}
	expectedBuf := bytes.NewBuffer(make([]byte, 0, 4096))
	expectedBuf.WriteString("//go:build foobar\n// +build foobar\n\n")

	writeBuildHeader(testBuf, buildHeaders)

	if testBuf.String() != expectedBuf.String() {
		t.Errorf("testBuf:\n%s not equal to expectedBuf:\n%s", testBuf, expectedBuf)
	}
}
