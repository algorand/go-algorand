package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPrint(t *testing.T) {
	testcases := []struct {
		input    interface{}
		expected string
	}{
		{
			input:    uint64(1234),
			expected: "1234",
		},
		{
			input:    int64(-1234),
			expected: "-1234",
		},
		{
			input:    true,
			expected: "true",
		},
		{
			input:    time.Second,
			expected: "1s",
		},
	}
	for i, tc := range testcases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "%v", tc.input)
			assert.Equal(t, tc.expected, buf.String())
		})
	}
}
